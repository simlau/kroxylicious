/*
 * Copyright Kroxylicious Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */

package io.kroxylicious.filter.encryption.encrypt;

import java.nio.ByteBuffer;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.function.IntFunction;

import org.apache.kafka.common.errors.NetworkException;

import io.kroxylicious.filter.encryption.common.EncryptionException;
import io.kroxylicious.filter.encryption.common.FilterThreadExecutor;
import io.kroxylicious.filter.encryption.common.RecordEncryptionUtil;
import io.kroxylicious.filter.encryption.crypto.Encryption;
import io.kroxylicious.filter.encryption.crypto.EncryptionHeader;
import io.kroxylicious.filter.encryption.dek.BufferTooSmallException;
import io.kroxylicious.filter.encryption.dek.Dek;
import io.kroxylicious.filter.encryption.dek.DestroyedDekException;
import io.kroxylicious.filter.encryption.dek.ExhaustedDekException;
import io.kroxylicious.kafka.common.record.internal.MemoryRecords;
import io.kroxylicious.kafka.common.record.internal.MutableRecordBatch;
import io.kroxylicious.kafka.common.utils.ByteBufferOutputStream;
import io.kroxylicious.kafka.transform.RecordStream;
import io.kroxylicious.kms.service.Serde;
import io.kroxylicious.proxy.tag.VisibleForTesting;

import edu.umd.cs.findbugs.annotations.NonNull;

/**
 * An implementation of {@link EncryptionManager}
 * that uses envelope encryption and stores the KEK id and encrypted DEK
 * alongside the record ("in-band").
 * @param <K> The type of KEK id.
 * @param <E> The type of the encrypted DEK.
 */
public class InBandEncryptionManager<K, E> implements EncryptionManager<K> {

    private static final int MAX_ATTEMPTS = 100;
    /**
    * The encryption version used on the produce path.
    * Note that the encryption version used on the fetch path is read from the
    * {@link EncryptionHeader#ENCRYPTION_HEADER_NAME} header.
    */
    private final Encryption encryption;
    private final Serde<E> edekSerde;
    private final EncryptionDekCache<K, E> dekCache;
    @NonNull
    private final FilterThreadExecutor filterThreadExecutor;
    private final int recordBufferInitialBytes;
    private final int recordBufferMaxBytes;

    /**
     * Creates an encryption manager.
     * @param encryption the encryption used on the produce path.
     * @param edekSerde the serde for encrypted DEKs.
     * @param recordBufferInitialBytes the initial size, in bytes, of the buffer used to hold the encrypted record.
     * @param recordBufferMaxBytes the maximum size, in bytes, of the buffer used to hold the encrypted record.
     * @param dekCache the cache of DEKs used for encryption.
     * @param filterThreadExecutor the executor used to complete futures on the filter thread.
     */
    public InBandEncryptionManager(@NonNull Encryption encryption,
                                   @NonNull Serde<E> edekSerde,
                                   int recordBufferInitialBytes,
                                   int recordBufferMaxBytes,
                                   @NonNull EncryptionDekCache<K, E> dekCache,
                                   @NonNull FilterThreadExecutor filterThreadExecutor) {
        this.filterThreadExecutor = filterThreadExecutor;
        this.encryption = Objects.requireNonNull(encryption); // TODO read from config
        this.edekSerde = Objects.requireNonNull(edekSerde);
        if (recordBufferInitialBytes <= 0) {
            throw new IllegalArgumentException();
        }
        this.recordBufferInitialBytes = recordBufferInitialBytes;
        if (recordBufferMaxBytes <= 0) {
            throw new IllegalArgumentException();
        }
        this.recordBufferMaxBytes = recordBufferMaxBytes;
        this.dekCache = dekCache;

    }

    /**
     * Returns the current DEK for the given encryption scheme, obtaining a new DEK from the cache if necessary.
     * @param encryptionScheme the encryption scheme.
     * @return a completion stage that completes with the current DEK for the given encryption scheme.
     */
    @VisibleForTesting
    public CompletionStage<Dek<E>> currentDek(@NonNull EncryptionScheme<K> encryptionScheme) {
        // todo should we add some scheduled timeout as well? or should we rely on the KMS to timeout appropriately.
        return dekCache.get(encryptionScheme, filterThreadExecutor);
    }

    @Override
    @NonNull
    public CompletionStage<MemoryRecords> encrypt(@NonNull String topicName,
                                                  int partition,
                                                  @NonNull EncryptionScheme<K> encryptionScheme,
                                                  @NonNull MemoryRecords records,
                                                  @NonNull IntFunction<ByteBufferOutputStream> bufferAllocator) {
        if (records.sizeInBytes() == 0) {
            // no records to transform, return input without modification
            return CompletableFuture.completedFuture(records);
        }

        int totalRecords = RecordEncryptionUtil.totalRecordsInBatches(records);
        // it is possible to encounter MemoryRecords that have had all their records compacted away, but
        // the recordbatch metadata still exists. https://kafka.apache.org/documentation/#recordbatch
        if (totalRecords == 0) {
            return CompletableFuture.completedFuture(records);
        }
        return attemptEncrypt(topicName, partition, encryptionScheme, records, 0, bufferAllocator, totalRecords);
    }

    @Override
    @NonNull
    public CompletionStage<MemoryRecords> encryptPerRecord(@NonNull String topicName,
                                                           int partition,
                                                           @NonNull List<EncryptionScheme<K>> encryptionSchemes,
                                                           @NonNull MemoryRecords records,
                                                           @NonNull IntFunction<ByteBufferOutputStream> bufferAllocator) {
        int totalRecords = countRecordsOutsideControlBatches(records);
        if (encryptionSchemes.size() != totalRecords) {
            throw new IllegalArgumentException("got " + encryptionSchemes.size() + " encryption schemes for " + totalRecords + " records");
        }
        // the number of records to encrypt with each scheme, so we reserve exactly that many encryptions per DEK
        Map<EncryptionScheme<K>, Integer> recordsPerScheme = new LinkedHashMap<>();
        for (EncryptionScheme<K> scheme : encryptionSchemes) {
            if (scheme != null) {
                recordsPerScheme.merge(scheme, 1, Integer::sum);
            }
        }
        if (recordsPerScheme.isEmpty()) {
            return CompletableFuture.completedFuture(records);
        }
        return attemptEncryptPerRecord(topicName, partition, encryptionSchemes, recordsPerScheme, records, 0, bufferAllocator);
    }

    /**
     * Counts the records the way {@link RecordStream} indexes them: control batches are skipped.
     */
    private static int countRecordsOutsideControlBatches(@NonNull MemoryRecords records) {
        int count = 0;
        for (MutableRecordBatch batch : records.batches()) {
            if (!batch.isControlBatch()) {
                Integer batchCount = batch.countOrNull();
                if (batchCount == null) {
                    // for magic < 2 the batch header has no count
                    for (var ignored : batch) {
                        count++;
                    }
                }
                else {
                    count += batchCount;
                }
            }
        }
        return count;
    }

    private CompletionStage<MemoryRecords> attemptEncryptPerRecord(@NonNull String topicName,
                                                                   int partition,
                                                                   @NonNull List<EncryptionScheme<K>> encryptionSchemes,
                                                                   @NonNull Map<EncryptionScheme<K>, Integer> recordsPerScheme,
                                                                   @NonNull MemoryRecords records,
                                                                   int attempt,
                                                                   @NonNull IntFunction<ByteBufferOutputStream> bufferAllocator) {
        if (attempt >= MAX_ATTEMPTS) {
            return CompletableFuture.failedFuture(
                    new RequestNotSatisfiable("failed to reserve EDEKs for " + recordsPerScheme.size() + " KEKs to encrypt " + encryptionSchemes.size()
                            + " records for topic " + topicName + " partition " + partition + " after " + attempt + " attempts",
                            new NetworkException("Failed to encrypt record(s) because there were no valid encryption keys")));
        }
        List<EncryptionScheme<K>> schemes = List.copyOf(recordsPerScheme.keySet());
        return RecordEncryptionUtil.join(schemes.stream().map(this::currentDek).toList()).thenCompose(deks -> {
            // if one is not alive we know a previous encrypt call has removed it from the cache and fall through to retry encrypt
            if (deks.stream().noneMatch(Dek::isDestroyed)) {
                Map<EncryptionScheme<K>, Dek<E>> dekPerScheme = new LinkedHashMap<>();
                for (int i = 0; i < schemes.size(); i++) {
                    dekPerScheme.put(schemes.get(i), deks.get(i));
                }
                try {
                    return CompletableFuture.completedFuture(encryptBatchesPerRecord(dekPerScheme,
                            recordsPerScheme,
                            topicName,
                            partition,
                            encryptionSchemes,
                            records,
                            bufferAllocator));
                }
                catch (DestroyedDekException | ExhaustedDekException e) {
                    // encryptBatchesPerRecord has rotated the DEK which could not provide the encryptions
                    // fall through to recursive call below...
                }
                catch (Exception e) {
                    return CompletableFuture.failedFuture(e);
                }
            }
            return attemptEncryptPerRecord(topicName, partition, encryptionSchemes, recordsPerScheme, records, attempt + 1, bufferAllocator);
        });
    }

    @NonNull
    private MemoryRecords encryptBatchesPerRecord(@NonNull Map<EncryptionScheme<K>, Dek<E>> dekPerScheme,
                                                  @NonNull Map<EncryptionScheme<K>, Integer> recordsPerScheme,
                                                  @NonNull String topicName,
                                                  int partition,
                                                  @NonNull List<EncryptionScheme<K>> encryptionSchemes,
                                                  @NonNull MemoryRecords memoryRecords,
                                                  @NonNull IntFunction<ByteBufferOutputStream> bufferAllocator) {
        ByteBuffer recordBuffer = ByteBuffer.allocate(recordBufferInitialBytes);
        do {
            // as in encryptBatches, create new encryptors for each attempt
            Map<EncryptionScheme<K>, PerRecordEncryptor.Selected<K, E>> selectedPerScheme = new LinkedHashMap<>();
            try {
                for (var entry : dekPerScheme.entrySet()) {
                    EncryptionScheme<K> scheme = entry.getKey();
                    Dek<E> dek = entry.getValue();
                    Dek<E>.Encryptor encryptor;
                    try {
                        encryptor = dek.encryptor(recordsPerScheme.get(scheme));
                    }
                    catch (DestroyedDekException | ExhaustedDekException e) {
                        rotateKeyContext(scheme, dek);
                        throw e;
                    }
                    selectedPerScheme.put(scheme, new PerRecordEncryptor.Selected<>(
                            new RecordEncryptor<>(topicName, partition, encryption, scheme, edekSerde, recordBuffer), encryptor));
                }
                return RecordStream.ofRecordsWithIndex(memoryRecords)
                        .mapPerRecord((batch, kafkaRecord, index) -> {
                            EncryptionScheme<K> scheme = encryptionSchemes.get(index);
                            return scheme == null ? null : selectedPerScheme.get(scheme);
                        })
                        .toMemoryRecords(allocateBufferForEncrypt(memoryRecords, bufferAllocator),
                                new PerRecordEncryptor<>(selectedPerScheme.values()));
            }
            catch (BufferTooSmallException e) {
                recordBuffer = growBuffer(recordBuffer, recordBufferMaxBytes);
            }
            finally {
                selectedPerScheme.values().forEach(selected -> selected.encryptor().close());
            }
        } while (true);
    }

    private ByteBufferOutputStream allocateBufferForEncrypt(@NonNull MemoryRecords records,
                                                            @NonNull IntFunction<ByteBufferOutputStream> bufferAllocator) {
        int sizeEstimate = 2 * records.sizeInBytes();
        // Accurate estimation is tricky without knowing the record sizes
        return bufferAllocator.apply(sizeEstimate);
    }

    private CompletionStage<MemoryRecords> attemptEncrypt(@NonNull String topicName,
                                                          int partition,
                                                          @NonNull EncryptionScheme<K> encryptionScheme,
                                                          @NonNull MemoryRecords records,
                                                          int attempt,
                                                          @NonNull IntFunction<ByteBufferOutputStream> bufferAllocator,
                                                          int allRecordsCount) {
        if (attempt >= MAX_ATTEMPTS) {
            return CompletableFuture.failedFuture(
                    new RequestNotSatisfiable("failed to reserve an EDEK to encrypt " + allRecordsCount + " records for topic " + topicName + " partition "
                            + partition + " after " + attempt + " attempts",
                            new NetworkException("Failed to encrypt record(s) because there were no valid encryption keys")));
        }
        return currentDek(encryptionScheme).thenCompose(dek -> {
            // if it's not alive we know a previous encrypt call has removed this stage from the cache and fall through to retry encrypt
            if (!dek.isDestroyed()) {
                try {
                    var encryptedMemoryRecords = encryptBatches(
                            dek,
                            allRecordsCount,
                            topicName,
                            partition,
                            encryptionScheme,
                            records,
                            bufferAllocator);
                    return CompletableFuture.completedFuture(encryptedMemoryRecords);
                }
                catch (DestroyedDekException | ExhaustedDekException e) {
                    rotateKeyContext(encryptionScheme, dek);
                    // fall through to recursive call below...
                }
                catch (Exception e) {
                    return CompletableFuture.failedFuture(e);
                }
            }
            // recurse, incrementing the attempt number
            return attemptEncrypt(topicName,
                    partition,
                    encryptionScheme,
                    records,
                    attempt + 1,
                    bufferAllocator,
                    allRecordsCount);
        });
    }

    @NonNull
    private MemoryRecords encryptBatches(Dek<E> dek,
                                         int allRecordsCount,
                                         @NonNull String topicName,
                                         int partition,
                                         @NonNull EncryptionScheme<K> encryptionScheme,
                                         @NonNull MemoryRecords memoryRecords,
                                         @NonNull IntFunction<ByteBufferOutputStream> bufferAllocator) {
        ByteBuffer recordBuffer = ByteBuffer.allocate(recordBufferInitialBytes);
        do {
            // create a new encryptor for each attempt as its requested encryption operations may be partially consumed by the attempt
            // leaving us with too few operations remaining to encrypt the batches
            try (Dek<E>.Encryptor encryptor = dek.encryptor(allRecordsCount)) {
                return RecordStream.ofRecords(memoryRecords)
                        .mapConstant(encryptor)
                        .toMemoryRecords(allocateBufferForEncrypt(memoryRecords, bufferAllocator),
                                new RecordEncryptor<>(topicName,
                                        partition,
                                        encryption,
                                        encryptionScheme,
                                        edekSerde,
                                        recordBuffer));
            }
            catch (BufferTooSmallException e) {
                recordBuffer = growBuffer(recordBuffer, recordBufferMaxBytes);
            }
        } while (true);
    }

    @VisibleForTesting
    @NonNull
    static ByteBuffer growBuffer(ByteBuffer recordBuffer, int maxBytes) {
        if (recordBuffer.capacity() == maxBytes) {
            throw new EncryptionException("Record buffer cannot grow greater than " + maxBytes + " bytes");
        }
        // we should make an attempt at the max buffer size. now that the min and max are configurable it's not guaranteed that the numbers
        // will neatly line up.
        int newCapacity = Math.min(maxBytes, 2 * recordBuffer.capacity());
        return ByteBuffer.allocate(newCapacity);
    }

    private void rotateKeyContext(@NonNull EncryptionScheme<K> encryptionScheme,
                                  @NonNull Dek<E> dek) {
        // invalidate first to prevent other threads spinning in tight loops if they obtain a destroyed DEK before cache invalidation
        dekCache.invalidate(encryptionScheme, dek);
        dek.destroyForEncrypt();
    }
}

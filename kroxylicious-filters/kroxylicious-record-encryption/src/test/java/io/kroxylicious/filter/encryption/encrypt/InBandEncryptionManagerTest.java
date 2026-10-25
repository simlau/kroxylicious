/*
 * Copyright Kroxylicious Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */

package io.kroxylicious.filter.encryption.encrypt;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.stream.IntStream;

import org.junit.jupiter.api.Test;

import io.kroxylicious.filter.encryption.common.EncryptionException;
import io.kroxylicious.filter.encryption.common.FilterThreadExecutor;
import io.kroxylicious.filter.encryption.config.RecordField;
import io.kroxylicious.filter.encryption.crypto.Encryption;
import io.kroxylicious.filter.encryption.crypto.EncryptionHeader;
import io.kroxylicious.filter.encryption.dek.CipherSpecResolver;
import io.kroxylicious.filter.encryption.dek.DekManager;
import io.kroxylicious.kafka.common.header.Header;
import io.kroxylicious.kafka.common.header.internals.RecordHeader;
import io.kroxylicious.kafka.common.record.internal.MemoryRecords;
import io.kroxylicious.kafka.common.record.internal.Record;
import io.kroxylicious.kafka.common.utils.ByteBufferOutputStream;
import io.kroxylicious.kafka.common.utils.ByteUtils;
import io.kroxylicious.kms.provider.kroxylicious.inmemory.InMemoryEdek;
import io.kroxylicious.kms.provider.kroxylicious.inmemory.InMemoryKms;
import io.kroxylicious.kms.provider.kroxylicious.inmemory.UnitTestingKmsService;
import io.kroxylicious.testing.filter.record.RecordTestUtils;

import edu.umd.cs.findbugs.annotations.NonNull;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class InBandEncryptionManagerTest {

    public static final int RECORD_BUFFER_INITIAL_BYTES = 1024 * 1024;

    // this test covers a bug fix where multiple encrypting threads would invalidate the cache key with
    // undefined results. We only need to invalidate each cached DEK once
    @Test
    void testMultipleThreadsCooperateToMinimiseDekCreations() {
        InMemoryKms kms = getInMemoryKms();
        // we are testing a race condition and want high parallelism to prompt parallel usages of exhausted DEKs
        ScheduledExecutorService executor = Executors.newScheduledThreadPool(Runtime.getRuntime().availableProcessors() * 2);
        final DekManager<UUID, InMemoryEdek> dekManager = new DekManager<>(new AsyncKms<>(kms, executor), 1);
        EncryptionDekCache<UUID, InMemoryEdek> cache = new EncryptionDekCache<>(dekManager, executor, EncryptionDekCache.NO_MAX_CACHE_SIZE, Duration.ofHours(1),
                Duration.ofHours(1));
        var encryptionManager = createEncryptionManager(dekManager, cache, executor);
        var kekId = kms.generateKey();

        var value = new byte[]{ 1, 2, 3 };
        Record record = RecordTestUtils.record(value);

        List<Record> initial = List.of(record);

        int numEncryptionOperations = 50;
        List<CompletableFuture<Void>> encrypts = IntStream.range(0, numEncryptionOperations)
                .mapToObj(x -> doEncrypt(encryptionManager, "topic", 1, new EncryptionScheme<>(kekId, EnumSet.of(RecordField.RECORD_VALUE)), initial,
                        new ArrayList<>()).toCompletableFuture())
                .toList();

        CompletableFuture<?>[] array = encrypts.toArray(CompletableFuture[]::new);
        CompletableFuture<Void> all = CompletableFuture.allOf(array);
        assertThat(all).succeedsWithin(10, TimeUnit.SECONDS);
        assertThat(cache.invalidationCount()).isEqualTo(numEncryptionOperations - 1);
    }

    @Test
    void shouldGenerateOneDekForMultipleBatchesToSameTopic() {
        // Given
        InMemoryKms kms = getInMemoryKms();
        ScheduledExecutorService executor = Executors.newSingleThreadScheduledExecutor();
        final DekManager<UUID, InMemoryEdek> dekManager = new DekManager<>(new AsyncKms<>(kms, executor), 10000);
        EncryptionDekCache<UUID, InMemoryEdek> cache = new EncryptionDekCache<>(dekManager, executor, EncryptionDekCache.NO_MAX_CACHE_SIZE, Duration.ofHours(1),
                Duration.ofHours(1));
        var encryptionManager = createEncryptionManager(dekManager, cache, executor);
        var kekId = kms.generateKey();

        var value = new byte[]{ 1, 2, 3 };
        Record record = RecordTestUtils.record(value);
        List<Record> batch = List.of(record);

        // When - send two batches to the same topic
        CompletionStage<Void> firstBatch = doEncrypt(encryptionManager, "topic", 0, new EncryptionScheme<>(kekId, EnumSet.of(RecordField.RECORD_VALUE)), batch,
                new ArrayList<>());
        CompletionStage<Void> secondBatch = doEncrypt(encryptionManager, "topic", 0, new EncryptionScheme<>(kekId, EnumSet.of(RecordField.RECORD_VALUE)), batch,
                new ArrayList<>());

        // Then - both succeed
        assertThat(firstBatch).succeedsWithin(10, TimeUnit.SECONDS);
        assertThat(secondBatch).succeedsWithin(10, TimeUnit.SECONDS);

        // And only one DEK was generated (reused for both batches)
        assertThat(kms.numDeksGenerated()).isEqualTo(1);
    }

    @Test
    void testGrowBufferCannotGrowBeyondMaximum() {
        ByteBuffer priorBuffer = ByteBuffer.allocate(2);
        assertThatThrownBy(() -> InBandEncryptionManager.growBuffer(priorBuffer, 2)).isInstanceOf(EncryptionException.class)
                .hasMessage("Record buffer cannot grow greater than 2 bytes");
    }

    @Test
    void testGrowBufferDoubles() {
        ByteBuffer priorBuffer = ByteBuffer.allocate(2);
        ByteBuffer grown = InBandEncryptionManager.growBuffer(priorBuffer, 8);
        assertThat(grown.capacity()).isEqualTo(4);
        ByteBuffer regrown = InBandEncryptionManager.growBuffer(grown, 8);
        assertThat(regrown.capacity()).isEqualTo(8);
    }

    @Test
    void testGrowBufferWillCapGrowthAtMaximum() {
        ByteBuffer priorBuffer = ByteBuffer.allocate(5);
        ByteBuffer grown = InBandEncryptionManager.growBuffer(priorBuffer, 8);
        assertThat(grown.capacity()).isEqualTo(8);
    }

    @Test
    void shouldGrowBuffer() {
        // Given
        InMemoryKms kms = getInMemoryKms();
        ScheduledExecutorService executor = Executors.newSingleThreadScheduledExecutor();
        final DekManager<UUID, InMemoryEdek> dekManager = new DekManager<>(new AsyncKms<>(kms, executor), 10000);
        EncryptionDekCache<UUID, InMemoryEdek> cache = new EncryptionDekCache<>(dekManager, executor, EncryptionDekCache.NO_MAX_CACHE_SIZE, Duration.ofHours(1),
                Duration.ofHours(1));
        var encryptionManager = createEncryptionManager(dekManager, cache, executor);
        var kekId = kms.generateKey();
        var valueLargerThanInitialEncryptionBuffer = new byte[RECORD_BUFFER_INITIAL_BYTES + 1];
        Record record = RecordTestUtils.record(valueLargerThanInitialEncryptionBuffer);

        List<Record> initial = List.of(record);

        // When
        CompletionStage<Void> encryptFuture = doEncrypt(encryptionManager, "topic", 1, new EncryptionScheme<>(kekId, EnumSet.of(RecordField.RECORD_VALUE)), initial,
                new ArrayList<>());

        // Then
        assertThat(encryptFuture).succeedsWithin(10, TimeUnit.SECONDS);
    }

    @Test
    void undersizedBufferAtTheLimitOfDekRotationSucceeds() {
        // Given
        InMemoryKms kms = getInMemoryKms();
        ScheduledExecutorService executor = Executors.newSingleThreadScheduledExecutor();
        final DekManager<UUID, InMemoryEdek> dekManager = new DekManager<>(new AsyncKms<>(kms, executor), 2);
        EncryptionDekCache<UUID, InMemoryEdek> cache = new EncryptionDekCache<>(dekManager, executor, EncryptionDekCache.NO_MAX_CACHE_SIZE, Duration.ofHours(1),
                Duration.ofHours(1));
        var encryptionManager = createEncryptionManager(dekManager, cache, executor);
        var kekId = kms.generateKey();

        Record smallRecord = RecordTestUtils.record(new byte[1]);

        var valueLargerThanInitialEncryptionBuffer = new byte[RECORD_BUFFER_INITIAL_BYTES + 1];
        Record oversizedRecord = RecordTestUtils.record(valueLargerThanInitialEncryptionBuffer);

        List<Record> encryptable = List.of(smallRecord);
        List<Record> oversized = List.of(oversizedRecord);

        // When
        // encrypt 1 record, bringing remaining encryptions on the DEK to 1
        CompletionStage<Void> encryptFuture = doEncrypt(encryptionManager, "topic", 1, new EncryptionScheme<>(kekId, EnumSet.of(RecordField.RECORD_VALUE)), encryptable,
                new ArrayList<>());

        // Then
        assertThat(encryptFuture).succeedsWithin(10, TimeUnit.SECONDS);

        // And When
        // encrypt 1 oversized record, which consumes 1 operation, fails to encrypt, retries, hits dek exhaustion, rotates dek, retries, succeeds (... phew)
        CompletionStage<Void> encryptFuture2 = doEncrypt(encryptionManager, "topic", 1, new EncryptionScheme<>(kekId, EnumSet.of(RecordField.RECORD_VALUE)), oversized,
                new ArrayList<>());

        // And Then
        assertThat(encryptFuture2).succeedsWithin(10, TimeUnit.SECONDS);
    }

    @Test
    void encryptPerRecordUsesEachRecordsKek() {
        // Given
        InMemoryKms kms = getInMemoryKms();
        var encryptionManager = createEncryptionManager(kms, 10000);
        var kekA = new EncryptionScheme<>(kms.generateKey(), EnumSet.of(RecordField.RECORD_VALUE));
        var kekB = new EncryptionScheme<>(kms.generateKey(), EnumSet.of(RecordField.RECORD_VALUE));
        Header other = new RecordHeader("other", "o".getBytes(StandardCharsets.UTF_8));
        List<Record> initial = List.of(
                RecordTestUtils.record(0L, 10L, "k0", "v0", new Header[]{ other }),
                RecordTestUtils.record(1L, 11L, "k1", "v1", new Header[]{}),
                RecordTestUtils.record(2L, 12L, "k2", "v2", new Header[]{ other }),
                RecordTestUtils.record(3L, 13L, "k3", "v3", new Header[]{ other }));
        MemoryRecords records = RecordTestUtils.memoryRecords(initial);

        // When
        CompletionStage<MemoryRecords> stage = encryptionManager.encryptPerRecord("topic", 0, Arrays.asList(kekA, kekB, kekA, null), records,
                ByteBufferOutputStream::new);

        // Then
        assertThat(stage).succeedsWithin(10, TimeUnit.SECONDS).satisfies(encrypted -> {
            List<Record> out = new ArrayList<>();
            encrypted.records().forEach(out::add);
            assertThat(out).hasSize(4);
            assertThat(kekOf(kms, out.get(0))).isEqualTo(kekA.kekId());
            assertThat(kekOf(kms, out.get(1))).isEqualTo(kekB.kekId());
            assertThat(kekOf(kms, out.get(2))).isEqualTo(kekA.kekId());
            assertThat(RecordTestUtils.recordValueAsString(out.get(3))).isEqualTo("v3");
            assertThat(out.get(3).headers()).containsExactly(other);
            for (int i = 0; i < 4; i++) {
                assertThat(out.get(i).offset()).isEqualTo(i);
                assertThat(out.get(i).timestamp()).isEqualTo(10L + i);
                assertThat(RecordTestUtils.recordKeyAsString(out.get(i))).isEqualTo("k" + i);
            }
            assertThat(out.get(0).headers()).hasSize(2).endsWith(other);
            assertThat(out.get(1).headers()).hasSize(1);
        });
        assertThat(kms.numDeksGenerated()).isEqualTo(2);
    }

    @Test
    void encryptPerRecordWithoutKeksReturnsRecordsUnchanged() {
        // Given
        InMemoryKms kms = getInMemoryKms();
        var encryptionManager = createEncryptionManager(kms, 10000);
        MemoryRecords records = RecordTestUtils.memoryRecords(List.of(RecordTestUtils.record(0L, 10L, "k0", "v0", new Header[]{})));

        // When
        CompletionStage<MemoryRecords> stage = encryptionManager.encryptPerRecord("topic", 0, Arrays.asList((EncryptionScheme<UUID>) null), records,
                ByteBufferOutputStream::new);

        // Then
        assertThat(stage).succeedsWithin(10, TimeUnit.SECONDS).isSameAs(records);
        assertThat(kms.numDeksGenerated()).isZero();
    }

    @Test
    void encryptPerRecordRotatesDekWithTooFewEncryptionsLeft() {
        // Given
        InMemoryKms kms = getInMemoryKms();
        var encryptionManager = createEncryptionManager(kms, 2);
        var kekA = new EncryptionScheme<>(kms.generateKey(), EnumSet.of(RecordField.RECORD_VALUE));
        var kekB = new EncryptionScheme<>(kms.generateKey(), EnumSet.of(RecordField.RECORD_VALUE));
        doEncrypt(encryptionManager, "topic", 0, kekA, List.of(RecordTestUtils.record(new byte[]{ 1 })), new ArrayList<>()).toCompletableFuture().join();
        MemoryRecords records = RecordTestUtils.memoryRecords(List.of(
                RecordTestUtils.record(0L, 10L, "k0", "v0", new Header[]{}),
                RecordTestUtils.record(1L, 11L, "k1", "v1", new Header[]{}),
                RecordTestUtils.record(2L, 12L, "k2", "v2", new Header[]{})));

        // When
        CompletionStage<MemoryRecords> stage = encryptionManager.encryptPerRecord("topic", 0, Arrays.asList(kekA, kekB, kekA), records,
                ByteBufferOutputStream::new);

        // Then
        assertThat(stage).succeedsWithin(10, TimeUnit.SECONDS).satisfies(encrypted -> {
            List<Record> out = new ArrayList<>();
            encrypted.records().forEach(out::add);
            assertThat(out).extracting(r -> kekOf(kms, r)).containsExactly(kekA.kekId(), kekB.kekId(), kekA.kekId());
        });
        // the first DEK of A had one encryption left, the partition needs two: A gets a second DEK
        assertThat(kms.numDeksGenerated()).isEqualTo(3);
    }

    @Test
    void encryptPerRecordGrowsBuffer() {
        // Given
        InMemoryKms kms = getInMemoryKms();
        var encryptionManager = createEncryptionManager(kms, 10000);
        var kekA = new EncryptionScheme<>(kms.generateKey(), EnumSet.of(RecordField.RECORD_VALUE));
        var kekB = new EncryptionScheme<>(kms.generateKey(), EnumSet.of(RecordField.RECORD_VALUE));
        MemoryRecords records = RecordTestUtils.memoryRecords(List.of(
                RecordTestUtils.record(0L, ByteBuffer.wrap(new byte[]{ 1 })),
                RecordTestUtils.record(1L, ByteBuffer.wrap(new byte[RECORD_BUFFER_INITIAL_BYTES + 1]))));

        // When
        CompletionStage<MemoryRecords> stage = encryptionManager.encryptPerRecord("topic", 0, Arrays.asList(kekA, kekB), records,
                ByteBufferOutputStream::new);

        // Then
        assertThat(stage).succeedsWithin(10, TimeUnit.SECONDS).satisfies(encrypted -> {
            List<Record> out = new ArrayList<>();
            encrypted.records().forEach(out::add);
            assertThat(out).extracting(r -> kekOf(kms, r)).containsExactly(kekA.kekId(), kekB.kekId());
        });
    }

    @Test
    void encryptPerRecordRejectsSchemeListOfWrongSize() {
        // Given
        InMemoryKms kms = getInMemoryKms();
        var encryptionManager = createEncryptionManager(kms, 10000);
        var kekA = new EncryptionScheme<>(kms.generateKey(), EnumSet.of(RecordField.RECORD_VALUE));
        MemoryRecords records = RecordTestUtils.memoryRecords(List.of(RecordTestUtils.record(new byte[]{ 1 })));
        List<EncryptionScheme<UUID>> schemes = List.of(kekA, kekA);

        // When / Then
        assertThatThrownBy(() -> encryptionManager.encryptPerRecord("topic", 0, schemes, records, ByteBufferOutputStream::new))
                .isInstanceOf(IllegalArgumentException.class);
    }

    private static UUID kekOf(InMemoryKms kms, Record record) {
        assertThat(record.headers()).extracting(Header::key).contains(EncryptionHeader.ENCRYPTION_HEADER_NAME);
        ByteBuffer wrapper = record.value();
        CipherSpecResolver.ALL.fromSerializedId(wrapper.get());
        int edekLength = ByteUtils.readUnsignedVarint(wrapper);
        ByteBuffer edek = wrapper.slice(wrapper.position(), edekLength);
        return kms.edekSerde().deserialize(edek).kekRef();
    }

    @NonNull
    private static InBandEncryptionManager<UUID, InMemoryEdek> createEncryptionManager(InMemoryKms kms, int maxEncryptionsPerDek) {
        ScheduledExecutorService executor = Executors.newSingleThreadScheduledExecutor();
        final DekManager<UUID, InMemoryEdek> dekManager = new DekManager<>(new AsyncKms<>(kms, executor), maxEncryptionsPerDek);
        EncryptionDekCache<UUID, InMemoryEdek> cache = new EncryptionDekCache<>(dekManager, executor, EncryptionDekCache.NO_MAX_CACHE_SIZE, Duration.ofHours(1),
                Duration.ofHours(1));
        return createEncryptionManager(dekManager, cache, executor);
    }

    @NonNull
    private static InMemoryKms getInMemoryKms() {
        var kmsService = UnitTestingKmsService.newInstance();
        kmsService.initialize(new UnitTestingKmsService.Config());
        return kmsService.buildKms();
    }

    @NonNull
    private static CompletionStage<Void> doEncrypt(
                                                   InBandEncryptionManager<UUID, InMemoryEdek> encryptionManager,
                                                   String topic,
                                                   int partition,
                                                   EncryptionScheme<UUID> scheme,
                                                   List<Record> initial,
                                                   List<Record> encrypted) {
        MemoryRecords records = RecordTestUtils.memoryRecords(initial);
        return encryptionManager.encrypt(topic, partition, scheme, records, ByteBufferOutputStream::new)
                .thenApply(memoryRecords -> {
                    memoryRecords.records().forEach(encrypted::add);
                    return null;
                });
    }

    @NonNull
    private static InBandEncryptionManager<UUID, InMemoryEdek> createEncryptionManager(DekManager<UUID, InMemoryEdek> dekManager,
                                                                                       EncryptionDekCache<UUID, InMemoryEdek> cache,
                                                                                       ScheduledExecutorService executor) {

        return new InBandEncryptionManager<>(Encryption.V2,
                dekManager.edekSerde(),
                RECORD_BUFFER_INITIAL_BYTES,
                8 * 1024 * 1024,
                cache,
                new FilterThreadExecutor(executor));
    }

}

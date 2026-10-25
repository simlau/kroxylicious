/*
 * Copyright Kroxylicious Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */

package io.kroxylicious.filter.encryption.encrypt;

import java.util.List;
import java.util.concurrent.CompletionStage;
import java.util.function.IntFunction;

import io.kroxylicious.kafka.common.record.internal.MemoryRecords;
import io.kroxylicious.kafka.common.utils.ByteBufferOutputStream;

import edu.umd.cs.findbugs.annotations.NonNull;

/**
 * A manager of (data) encryption keys supporting encryption operations,
 * encapsulating access to the data encryption keys.
 * @param <K> The type of KEK id.
 */
public interface EncryptionManager<K> {
    /**
     * Asynchronously encrypt the given {@code records} using the current DEK for the given KEK returning a MemoryRecords object which will contain all records
     * transformed according to the {@code encryptionScheme}.
     * @param topicName The name of the topic to which the records are being produced.
     * @param partition The index of the partition to which the records are being produced.
     * @param encryptionScheme The encryption scheme.
     * @param records The MemoryRecords to be encrypted.
     * @param bufferAllocator Allocator of ByteBufferOutputStream
     * @return A completion stage that completes with the output MemoryRecords when all the records have been processed and transformed.
     */
    @NonNull
    CompletionStage<MemoryRecords> encrypt(
                                           @NonNull String topicName,
                                           int partition,
                                           @NonNull EncryptionScheme<K> encryptionScheme,
                                           @NonNull MemoryRecords records,
                                           @NonNull IntFunction<ByteBufferOutputStream> bufferAllocator);

    /**
     * Asynchronously encrypt each of the given {@code records} using the current DEK for that record's own KEK, returning a MemoryRecords
     * object which will contain all records, each transformed according to its encryption scheme. A record without an encryption scheme
     * is passed through unchanged.
     * @param topicName The name of the topic to which the records are being produced.
     * @param partition The index of the partition to which the records are being produced.
     * @param encryptionSchemes The encryption scheme of each record, in record order (control batches excluded). A null element means
     * the record is not encrypted.
     * @param records The MemoryRecords to be encrypted.
     * @param bufferAllocator Allocator of ByteBufferOutputStream
     * @return A completion stage that completes with the output MemoryRecords when all the records have been processed and transformed.
     * @throws IllegalArgumentException if the number of encryption schemes differs from the number of records.
     */
    @NonNull
    CompletionStage<MemoryRecords> encryptPerRecord(
                                                    @NonNull String topicName,
                                                    int partition,
                                                    @NonNull List<EncryptionScheme<K>> encryptionSchemes,
                                                    @NonNull MemoryRecords records,
                                                    @NonNull IntFunction<ByteBufferOutputStream> bufferAllocator);
}

/*
 * Copyright Kroxylicious Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */

package io.kroxylicious.filter.encryption.decrypt;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

import io.kroxylicious.filter.encryption.crypto.EncryptionHeader;
import io.kroxylicious.filter.encryption.dek.Dek;
import io.kroxylicious.kafka.common.header.Header;
import io.kroxylicious.kafka.common.header.internals.RecordHeader;
import io.kroxylicious.kafka.common.record.internal.Record;
import io.kroxylicious.kafka.common.record.internal.RecordBatch;
import io.kroxylicious.kafka.transform.RecordTransform;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;

/**
 * A {@link RecordTransform} that decrypts records that were previously encrypted by {@link io.kroxylicious.filter.encryption.encrypt.RecordEncryptor}.
 * @param <E> The type of encrypted DEK.
 */
public class RecordDecryptor<E> implements RecordTransform<DecryptState<E>> {

    /** The name of the header added to a shredded record: a record whose KEK no longer exists. */
    public static final String SHREDDED_HEADER_NAME = "X-Shredded";
    private static final byte[] SHREDDED_HEADER_VALUE = "true".getBytes(StandardCharsets.UTF_8);

    private final String topicName;
    private final int partition;
    private RecordBatch batch;

    private ByteBuffer transformedValue;
    private Header[] transformedHeaders;

    /**
     * Creates a record decryptor.
     * @param topicName the name of the topic from which the records are being fetched.
     * @param partition the index of the partition from which the records are being fetched.
     */
    public RecordDecryptor(@NonNull String topicName, int partition) {
        this.topicName = Objects.requireNonNull(topicName);
        this.partition = partition;
    }

    @Override
    public void initBatch(@NonNull RecordBatch batch) {
        this.batch = Objects.requireNonNull(batch);
    }

    @Override
    public void init(@Nullable DecryptState<E> decryptState,
                     @NonNull Record record) {
        if (batch == null) {
            throw new IllegalStateException();
        }
        if (decryptState != null && decryptState.isShredded()) {
            transformedValue = null;
            transformedHeaders = shreddedHeaders(record.headers());
            return;
        }
        final Dek<E>.Decryptor decryptor;
        if (decryptState == null) {
            decryptor = null;
        }
        else {
            decryptor = decryptState.decryptor();
        }
        if (decryptor == null) {
            transformedValue = record.value();
            transformedHeaders = record.headers();
            return;
        }

        var wrapper = record.value();
        decryptState.encryptionUsed().wrapper().read(decryptState.encryptionUsed().parcel(),
                topicName,
                partition,
                batch,
                record,
                wrapper,
                decryptor,
                (v, h) -> {
                    transformedValue = v;
                    transformedHeaders = h;
                });

    }

    /**
     * Returns the headers of a shredded record: the record's headers in their order, without the encryption header,
     * followed by the {@value #SHREDDED_HEADER_NAME} header.
     */
    private static Header[] shreddedHeaders(Header[] headers) {
        List<Header> result = new ArrayList<>(headers.length + 1);
        for (Header header : headers) {
            if (!EncryptionHeader.ENCRYPTION_HEADER_NAME.equals(header.key())) {
                result.add(header);
            }
        }
        result.add(new RecordHeader(SHREDDED_HEADER_NAME, SHREDDED_HEADER_VALUE.clone()));
        return result.toArray(Header[]::new);
    }

    @Override
    public long transformOffset(@NonNull Record record) {
        return record.offset();
    }

    @Override
    public long transformTimestamp(@NonNull Record record) {
        return record.timestamp();
    }

    @Nullable
    @Override
    public ByteBuffer transformKey(@NonNull Record record) {
        return record.key();
    }

    @Nullable
    @Override
    public ByteBuffer transformValue(@NonNull Record record) {
        return transformedValue == null ? null : transformedValue.duplicate();
    }

    @Nullable
    @Override
    public Header[] transformHeaders(@NonNull Record record) {
        return transformedHeaders;
    }

    @Override
    public void resetAfterTransform(@Nullable DecryptState decryptState,
                                    @NonNull Record record) {
        if (transformedValue != null) {
            transformedValue.clear();
        }
        transformedHeaders = null;
    }
}

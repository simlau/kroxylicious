/*
 * Copyright Kroxylicious Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */

package io.kroxylicious.filter.encryption.encrypt;

import java.nio.ByteBuffer;
import java.util.Collection;
import java.util.List;
import java.util.Objects;

import io.kroxylicious.filter.encryption.dek.Dek;
import io.kroxylicious.kafka.common.header.Header;
import io.kroxylicious.kafka.common.record.internal.Record;
import io.kroxylicious.kafka.common.record.internal.RecordBatch;
import io.kroxylicious.kafka.transform.RecordTransform;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;

/**
 * A {@link RecordTransform} which encrypts each record with the {@link RecordEncryptor} and encryptor selected for it,
 * and passes a record for which none is selected through unchanged.
 * @param <K> The type of KEK id
 * @param <E> The type of encrypted DEK.
 */
class PerRecordEncryptor<K, E> implements RecordTransform<PerRecordEncryptor.Selected<K, E>> {

    /**
     * The record encryptor and the encryptor for the records of one encryption scheme.
     * @param recordEncryptor the record encryptor of the scheme.
     * @param encryptor the encryptor of the current DEK of the scheme's KEK.
     * @param <K> The type of KEK id
     * @param <E> The type of encrypted DEK.
     */
    record Selected<K, E>(@NonNull RecordEncryptor<K, E> recordEncryptor, Dek<E>.Encryptor encryptor) {
        Selected {
            Objects.requireNonNull(recordEncryptor);
            Objects.requireNonNull(encryptor);
        }
    }

    private final List<Selected<K, E>> all;
    private @Nullable Selected<K, E> current;

    PerRecordEncryptor(@NonNull Collection<Selected<K, E>> all) {
        this.all = List.copyOf(all);
    }

    @Override
    public void initBatch(@NonNull RecordBatch batch) {
        all.forEach(selected -> selected.recordEncryptor().initBatch(batch));
    }

    @Override
    public void init(@Nullable Selected<K, E> state, @NonNull Record kafkaRecord) {
        current = state;
        if (state != null) {
            state.recordEncryptor().init(state.encryptor(), kafkaRecord);
        }
    }

    @Override
    public void resetAfterTransform(@Nullable Selected<K, E> state, Record kafkaRecord) {
        if (state != null) {
            state.recordEncryptor().resetAfterTransform(state.encryptor(), kafkaRecord);
        }
        current = null;
    }

    @Override
    public long transformOffset(Record kafkaRecord) {
        return current == null ? kafkaRecord.offset() : current.recordEncryptor().transformOffset(kafkaRecord);
    }

    @Override
    public long transformTimestamp(Record kafkaRecord) {
        return current == null ? kafkaRecord.timestamp() : current.recordEncryptor().transformTimestamp(kafkaRecord);
    }

    @Override
    public @Nullable ByteBuffer transformKey(Record kafkaRecord) {
        return current == null ? kafkaRecord.key() : current.recordEncryptor().transformKey(kafkaRecord);
    }

    @Override
    public @Nullable ByteBuffer transformValue(Record kafkaRecord) {
        return current == null ? kafkaRecord.value() : current.recordEncryptor().transformValue(kafkaRecord);
    }

    @Override
    public @Nullable Header[] transformHeaders(Record kafkaRecord) {
        return current == null ? kafkaRecord.headers() : current.recordEncryptor().transformHeaders(kafkaRecord);
    }
}

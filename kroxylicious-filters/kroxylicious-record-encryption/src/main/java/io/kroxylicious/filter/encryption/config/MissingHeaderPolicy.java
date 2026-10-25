/*
 * Copyright Kroxylicious Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */

package io.kroxylicious.filter.encryption.config;

/**
 * What the {@link io.kroxylicious.filter.encryption.HeaderRecordEncryption} filter does with a produced record
 * that does not carry the KEK header.
 */
public enum MissingHeaderPolicy {
    /**
     * Reject the record. The entire produce request is rejected with {@code INVALID_RECORD}. This is the default.
     */
    REJECT,
    /**
     * Pass the record through unencrypted.
     */
    PASSTHROUGH_UNENCRYPTED
}

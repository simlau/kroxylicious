/*
 * Copyright Kroxylicious Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */

package io.kroxylicious.filter.encryption;

import io.kroxylicious.filter.encryption.common.EncryptionException;

/**
 * A produced record's headers do not allow the {@link HeaderRecordEncryption} filter to select its KEK:
 * the KEK header is missing, repeated or has an invalid value, or the record carries a header reserved for the proxy.
 * The produce request is rejected with {@code INVALID_RECORD}.
 */
public class InvalidHeaderException extends EncryptionException {
    /**
     * Creates an exception with the given message.
     * @param message the detail message. It must not contain the header value.
     */
    public InvalidHeaderException(String message) {
        super(message);
    }
}

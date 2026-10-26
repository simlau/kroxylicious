/*
 * Copyright Kroxylicious Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */

package io.kroxylicious.filter.encryption;

import java.util.Objects;
import java.util.Optional;

import io.kroxylicious.filter.encryption.config.HeaderKekSelectorConfig;
import io.kroxylicious.filter.encryption.crypto.EncryptionHeader;
import io.kroxylicious.filter.encryption.decrypt.RecordDecryptor;
import io.kroxylicious.kafka.common.header.Header;
import io.kroxylicious.kafka.common.record.internal.Record;

import edu.umd.cs.findbugs.annotations.NonNull;

import static java.nio.charset.StandardCharsets.US_ASCII;

/**
 * Derives the KEK alias of a produced record from its KEK header.
 * A header value is valid only if it is 1 to {@value #MAX_VALUE_LENGTH} characters from {@code [A-Za-z0-9_-]}
 * and the header occurs once on the record. A record carrying the {@value RecordDecryptor#SHREDDED_HEADER_NAME}
 * header (in any letter case) is rejected, because the proxy reserves it for records it delivers as shredded.
 * So is a record carrying the {@value EncryptionHeader#ENCRYPTION_HEADER_NAME} header: the proxy writes it itself, and a
 * client-made one could name a missing KEK and so make the proxy deliver the record as shredded.
 */
class HeaderKekResolver {

    static final int MAX_VALUE_LENGTH = 64;

    private final String headerName;
    private final String template;

    HeaderKekResolver(@NonNull HeaderKekSelectorConfig config) {
        Objects.requireNonNull(config);
        this.headerName = config.header();
        this.template = config.template();
    }

    String headerName() {
        return headerName;
    }

    /**
     * Returns the KEK alias for the given record.
     * @param kafkaRecord the record.
     * @return the KEK alias, or empty if the record has no KEK header.
     * @throws InvalidHeaderException if the KEK header is repeated or has an invalid value, or the record
     * carries the {@value RecordDecryptor#SHREDDED_HEADER_NAME} or the {@value EncryptionHeader#ENCRYPTION_HEADER_NAME} header.
     */
    Optional<String> aliasFor(@NonNull Record kafkaRecord) {
        Header kekHeader = null;
        for (Header header : kafkaRecord.headers()) {
            if (RecordDecryptor.SHREDDED_HEADER_NAME.equalsIgnoreCase(header.key())) {
                throw new InvalidHeaderException("record header " + RecordDecryptor.SHREDDED_HEADER_NAME + " is reserved for the proxy");
            }
            if (EncryptionHeader.ENCRYPTION_HEADER_NAME.equals(header.key())) {
                throw new InvalidHeaderException("record header " + EncryptionHeader.ENCRYPTION_HEADER_NAME + " is reserved for the proxy");
            }
            if (headerName.equals(header.key())) {
                if (kekHeader != null) {
                    throw new InvalidHeaderException("record header " + headerName + " must occur at most once");
                }
                kekHeader = header;
            }
        }
        if (kekHeader == null) {
            return Optional.empty();
        }
        byte[] value = kekHeader.value();
        if (!isValid(value)) {
            throw new InvalidHeaderException("record header " + headerName + " must be 1 to " + MAX_VALUE_LENGTH + " characters from [A-Za-z0-9_-]");
        }
        return Optional.of(template.replace(HeaderKekSelectorConfig.HEADER_VALUE_PLACEHOLDER, new String(value, US_ASCII)));
    }

    private static boolean isValid(byte[] value) {
        if (value == null || value.length == 0 || value.length > MAX_VALUE_LENGTH) {
            return false;
        }
        for (byte b : value) {
            boolean valid = (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9') || b == '_' || b == '-';
            if (!valid) {
                return false;
            }
        }
        return true;
    }
}

/*
 * Copyright Kroxylicious Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */

package io.kroxylicious.filter.encryption.config;

import java.util.Map;
import java.util.Optional;

import edu.umd.cs.findbugs.annotations.Nullable;

/**
 * The configuration shared by the record encryption filter factories: the KMS and the experimental
 * properties, and the parsing of the experimental properties into the cache, buffer and DEK manager configuration.
 * Keeping the parsing here means every filter factory understands the same experimental properties.
 */
public interface CommonEncryptionConfig {

    /**
     * Returns the name of the KMS service implementation providing the key management.
     * @return the name of the KMS service implementation.
     */
    String kms();

    /**
     * Returns the KMS service implementation's configuration.
     * @return the KMS service implementation's configuration.
     */
    Object kmsConfig();

    /**
     * Returns the experimental configuration properties, subject to change without notice. Never null.
     * @return the experimental configuration properties.
     */
    Map<String, Object> experimental();

    /**
     * Returns the configuration of the caches which sit in front of the KMS.
     * @return the configuration of the caches which sit in front of the KMS.
     */
    default KmsCacheConfig kmsCache() {
        Integer decryptedDekCacheSize = getExperimentalInt("decryptedDekCacheSize");
        Long decryptedDekExpireAfterAccessSeconds = getExperimentalLong("decryptedDekExpireAfterAccessSeconds");
        Integer resolvedAliasCacheSize = getExperimentalInt("resolvedAliasCacheSize");
        Long resolvedAliasExpireAfterWriteSeconds = getExperimentalLong("resolvedAliasExpireAfterWriteSeconds");
        Long resolvedAliasRefreshAfterWriteSeconds = getExperimentalLong("resolvedAliasRefreshAfterWriteSeconds");
        Long notFoundAliasExpireAfterWriteSeconds = getExperimentalLong("notFoundAliasExpireAfterWriteSeconds");
        Long encryptionDekRefreshAfterWriteSeconds = getExperimentalLong("encryptionDekRefreshAfterWriteSeconds");
        Long encryptionDekExpireAfterWriteSeconds = getExperimentalLong("encryptionDekExpireAfterWriteSeconds");
        Long decryptedDekExpireAfterWriteSeconds = getExperimentalLong("decryptedDekExpireAfterWriteSeconds");
        return new KmsCacheConfig(decryptedDekCacheSize, decryptedDekExpireAfterAccessSeconds, resolvedAliasCacheSize, resolvedAliasExpireAfterWriteSeconds,
                resolvedAliasRefreshAfterWriteSeconds, notFoundAliasExpireAfterWriteSeconds, encryptionDekRefreshAfterWriteSeconds, encryptionDekExpireAfterWriteSeconds,
                decryptedDekExpireAfterWriteSeconds);
    }

    /**
     * Returns the configuration of the encryption buffer size limits.
     * @return the configuration of the encryption buffer size limits.
     */
    default EncryptionBufferConfig encryptionBuffer() {
        Integer minimumBufSize = getExperimentalIntOrElse("encryptionBufferMinimumSizeBytes", RecordEncryptionConfig.RECORD_BUFFER_DEFAULT_INITIAL_BYTES);
        Integer maximumBufSize = getExperimentalIntOrElse("encryptionBufferMaximumSizeBytes", 1024 * 1024 * 8);
        return new EncryptionBufferConfig(minimumBufSize, maximumBufSize);
    }

    /**
     * Returns the configuration of the DEK manager.
     * @return the configuration of the DEK manager.
     */
    default DekManagerConfig dekManager() {
        Long maxEncryptionsPerDek = getExperimentalLong("maxEncryptionsPerDek");
        return new DekManagerConfig(maxEncryptionsPerDek);

    }

    @Nullable
    private Integer getExperimentalInt(String property) {
        return getExperimentalIntOrElse(property, null);
    }

    private Integer getExperimentalIntOrElse(String property, Integer defaultValue) {
        return Optional.ofNullable(experimental().get(property)).map(value -> switch (value) {
            case Number number -> number.intValue();
            case String stringValue -> Integer.parseInt(stringValue);
            default -> throw new IllegalArgumentException("could not convert " + property + " with type " + value.getClass().getSimpleName() + " to Integer");
        }).orElse(defaultValue);
    }

    @Nullable
    private Long getExperimentalLong(String property) {
        return Optional.ofNullable(experimental().get(property)).map(value -> switch (value) {
            case Number number -> number.longValue();
            case String stringValue -> Long.parseLong(stringValue);
            default -> throw new IllegalArgumentException("could not convert " + property + " with type " + value.getClass().getSimpleName() + " to Long");
        }).orElse(null);
    }
}

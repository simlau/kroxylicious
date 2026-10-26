/*
 * Copyright Kroxylicious Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */

package io.kroxylicious.filter.encryption.config;

import java.time.Duration;
import java.util.function.Function;

import edu.umd.cs.findbugs.annotations.Nullable;

import static java.util.Objects.requireNonNullElse;

/**
 * Configuration of the caches which sit in front of the KMS.
 *
 * @param decryptedDekCacheSize The maximum number of decrypted DEKs to cache.
 * @param decryptedDekExpireAfterAccessDuration How long after last access a decrypted DEK is removed from the cache.
 * @param resolvedAliasCacheSize The maximum number of resolved aliases to cache.
 * @param resolvedAliasExpireAfterWriteDuration How long after being cached a resolved alias is removed from the cache.
 * @param resolvedAliasRefreshAfterWriteDuration How long after being cached a resolved alias becomes eligible for a refresh.
 * @param notFoundAliasExpireAfterWriteDuration How long an unresolvable alias is remembered before the KMS is asked to resolve it again.
 * @param encryptionDekCacheRefreshAfterWriteDuration How long after being cached a DEK used for encryption becomes eligible for a refresh.
 * @param encryptionDekCacheExpireAfterWriteDuration How long after being cached a DEK used for encryption is removed from the cache.
 * @param decryptedDekExpireAfterWriteDuration How long after being cached a decrypted DEK is removed from the caches, however often it is read,
 * or null for no such limit.
 */
public record KmsCacheConfig(
                             Integer decryptedDekCacheSize,
                             Duration decryptedDekExpireAfterAccessDuration,
                             Integer resolvedAliasCacheSize,
                             Duration resolvedAliasExpireAfterWriteDuration,
                             Duration resolvedAliasRefreshAfterWriteDuration,
                             Duration notFoundAliasExpireAfterWriteDuration,
                             Duration encryptionDekCacheRefreshAfterWriteDuration,
                             Duration encryptionDekCacheExpireAfterWriteDuration,
                             @Nullable Duration decryptedDekExpireAfterWriteDuration) {

    /**
     * Creates a KMS cache config, applying defaults for any null argument
     * except {@code decryptedDekExpireAfterWriteDuration}, for which null means no limit.
     */
    public KmsCacheConfig {
        decryptedDekCacheSize = requireNonNullElse(decryptedDekCacheSize, 1000);
        decryptedDekExpireAfterAccessDuration = requireNonNullElse(decryptedDekExpireAfterAccessDuration, Duration.ofHours(1));
        resolvedAliasCacheSize = requireNonNullElse(resolvedAliasCacheSize, 1000);
        resolvedAliasExpireAfterWriteDuration = requireNonNullElse(resolvedAliasExpireAfterWriteDuration, Duration.ofMinutes(10));
        resolvedAliasRefreshAfterWriteDuration = requireNonNullElse(resolvedAliasRefreshAfterWriteDuration, Duration.ofMinutes(8));
        notFoundAliasExpireAfterWriteDuration = requireNonNullElse(notFoundAliasExpireAfterWriteDuration, Duration.ofSeconds(30));
        encryptionDekCacheRefreshAfterWriteDuration = requireNonNullElse(encryptionDekCacheRefreshAfterWriteDuration, Duration.ofHours(1));
        encryptionDekCacheExpireAfterWriteDuration = requireNonNullElse(encryptionDekCacheExpireAfterWriteDuration, Duration.ofHours(2));
    }

    @SuppressWarnings("java:S1905") // Sonar's warning about this is incorrect, the cast is required.
    KmsCacheConfig(Integer decryptedDekCacheSize,
                   Long decryptedDekExpireAfterAccessSeconds,
                   Integer resolvedAliasCacheSize,
                   Long resolvedAliasExpireAfterWriteSeconds,
                   Long resolvedAliasRefreshAfterWriteSeconds,
                   Long notFoundAliasExpireAfterWriteSeconds,
                   Long encryptionDekRefreshAfterWriteSeconds,
                   Long encryptionDekExpireAfterWriteSeconds,
                   Long decryptedDekExpireAfterWriteSeconds) {
        this(mapNotNull(decryptedDekCacheSize, Function.identity()),
                (Duration) mapNotNull(decryptedDekExpireAfterAccessSeconds, Duration::ofSeconds),
                mapNotNull(resolvedAliasCacheSize, Function.identity()),
                mapNotNull(resolvedAliasExpireAfterWriteSeconds, Duration::ofSeconds),
                mapNotNull(resolvedAliasRefreshAfterWriteSeconds, Duration::ofSeconds),
                mapNotNull(notFoundAliasExpireAfterWriteSeconds, Duration::ofSeconds),
                mapNotNull(encryptionDekRefreshAfterWriteSeconds, Duration::ofSeconds),
                mapNotNull(encryptionDekExpireAfterWriteSeconds, Duration::ofSeconds),
                mapNotNull(decryptedDekExpireAfterWriteSeconds, Duration::ofSeconds));
    }

    /**
     * Returns a copy of this config with the given maximum lifetime of a decrypted DEK.
     * @param decryptedDekExpireAfterWriteDuration How long after being cached a decrypted DEK is removed from the caches,
     * or null for no such limit.
     * @return the copy.
     */
    public KmsCacheConfig withDecryptedDekExpireAfterWriteDuration(@Nullable Duration decryptedDekExpireAfterWriteDuration) {
        return new KmsCacheConfig(decryptedDekCacheSize, decryptedDekExpireAfterAccessDuration, resolvedAliasCacheSize, resolvedAliasExpireAfterWriteDuration,
                resolvedAliasRefreshAfterWriteDuration, notFoundAliasExpireAfterWriteDuration, encryptionDekCacheRefreshAfterWriteDuration,
                encryptionDekCacheExpireAfterWriteDuration, decryptedDekExpireAfterWriteDuration);
    }

    static <T, Y> Y mapNotNull(T t, Function<T, Y> function) {
        return t == null ? null : function.apply(t);
    }

}

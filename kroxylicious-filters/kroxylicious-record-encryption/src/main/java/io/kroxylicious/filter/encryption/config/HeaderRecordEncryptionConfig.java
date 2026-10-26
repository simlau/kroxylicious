/*
 * Copyright Kroxylicious Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */

package io.kroxylicious.filter.encryption.config;

import java.time.Duration;
import java.util.Map;
import java.util.Objects;

import com.fasterxml.jackson.annotation.JsonProperty;

import io.kroxylicious.kms.service.KmsService;
import io.kroxylicious.proxy.plugin.PluginImplConfig;
import io.kroxylicious.proxy.plugin.PluginImplName;

import edu.umd.cs.findbugs.annotations.Nullable;

/**
 * The configuration for the {@link io.kroxylicious.filter.encryption.HeaderRecordEncryption} filter factory.
 * @param kms The name of the KMS service implementation providing the key management.
 * @param kmsConfig The KMS service implementation's configuration.
 * @param selector The KEK selector. Must be {@value #HEADER_KEK_SELECTOR}.
 * @param selectorConfig The configuration of the header KEK selector.
 * @param experimental Experimental configuration properties, subject to change without notice. The same properties as
 *        for {@link io.kroxylicious.filter.encryption.RecordEncryption}, except that {@value #DECRYPTED_DEK_EXPIRE_AFTER_WRITE_SECONDS}
 *        defaults to {@link #DEFAULT_DECRYPTED_DEK_EXPIRE_AFTER_WRITE} and must be positive.
 * @param unresolvedKeyPolicy The policy applied when the KEK named by a record's header cannot be resolved,
 *        defaulting to {@link UnresolvedKeyPolicy#REJECT}.
 */
public record HeaderRecordEncryptionConfig(@JsonProperty(required = true) @PluginImplName(KmsService.class) String kms,
                                           @PluginImplConfig(implNameProperty = "kms") Object kmsConfig,
                                           @JsonProperty(required = true) String selector,
                                           @JsonProperty(required = true) HeaderKekSelectorConfig selectorConfig,
                                           @JsonProperty Map<String, Object> experimental,
                                           @JsonProperty @Nullable UnresolvedKeyPolicy unresolvedKeyPolicy)
        implements CommonEncryptionConfig {

    /** The only supported {@code selector}. */
    public static final String HEADER_KEK_SELECTOR = "HeaderKekSelector";

    /**
     * The maximum lifetime of a decrypted DEK when {@value #DECRYPTED_DEK_EXPIRE_AFTER_WRITE_SECONDS} is not set.
     * It bounds how long the records of a deleted KEK stay readable through a proxy that had decrypted their DEK.
     * Without it, a decrypted DEK would stay cached for the life of the proxy.
     */
    public static final Duration DEFAULT_DECRYPTED_DEK_EXPIRE_AFTER_WRITE = Duration.ofHours(1);

    /**
     * Creates a header record encryption config, applying an empty map if {@code experimental} is null and
     * {@link UnresolvedKeyPolicy#REJECT} if {@code unresolvedKeyPolicy} is null.
     * @throws IllegalArgumentException if {@code selector} is not {@value #HEADER_KEK_SELECTOR}, or the experimental
     * property {@value #DECRYPTED_DEK_EXPIRE_AFTER_WRITE_SECONDS} is not a positive number.
     */
    public HeaderRecordEncryptionConfig {
        if (!HEADER_KEK_SELECTOR.equals(selector)) {
            throw new IllegalArgumentException("selector must be " + HEADER_KEK_SELECTOR + ", but was " + selector);
        }
        Objects.requireNonNull(selectorConfig, "selectorConfig must not be null");
        experimental = experimental == null ? Map.of() : experimental;
        unresolvedKeyPolicy = unresolvedKeyPolicy == null ? UnresolvedKeyPolicy.REJECT : unresolvedKeyPolicy;
        Long decryptedDekLifetimeSeconds = ExperimentalProperties.longOrNull(experimental, DECRYPTED_DEK_EXPIRE_AFTER_WRITE_SECONDS);
        if (decryptedDekLifetimeSeconds != null && decryptedDekLifetimeSeconds <= 0) {
            throw new IllegalArgumentException("experimental." + DECRYPTED_DEK_EXPIRE_AFTER_WRITE_SECONDS + " must be a positive number of seconds, but was "
                    + decryptedDekLifetimeSeconds + "; leave it unset for the default of " + DEFAULT_DECRYPTED_DEK_EXPIRE_AFTER_WRITE.toSeconds() + " seconds");
        }
    }

    /**
     * Returns the configuration of the caches which sit in front of the KMS, as for
     * {@link io.kroxylicious.filter.encryption.RecordEncryption}, except that a decrypted DEK is cached for at most
     * {@link #DEFAULT_DECRYPTED_DEK_EXPIRE_AFTER_WRITE} when {@value #DECRYPTED_DEK_EXPIRE_AFTER_WRITE_SECONDS} is not set.
     * @return the configuration of the caches which sit in front of the KMS.
     */
    @Override
    public KmsCacheConfig kmsCache() {
        KmsCacheConfig kmsCacheConfig = CommonEncryptionConfig.super.kmsCache();
        if (kmsCacheConfig.decryptedDekExpireAfterWriteDuration() != null) {
            return kmsCacheConfig;
        }
        return kmsCacheConfig.withDecryptedDekExpireAfterWriteDuration(DEFAULT_DECRYPTED_DEK_EXPIRE_AFTER_WRITE);
    }
}

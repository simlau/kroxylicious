/*
 * Copyright Kroxylicious Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */

package io.kroxylicious.filter.encryption.config;

import java.util.Map;

import com.fasterxml.jackson.annotation.JsonProperty;

import io.kroxylicious.kms.service.KmsService;
import io.kroxylicious.proxy.plugin.PluginImplConfig;
import io.kroxylicious.proxy.plugin.PluginImplName;

/**
 * The configuration for the {@link io.kroxylicious.filter.encryption.RecordEncryption} filter factory.
 * @param kms The name of the KMS service implementation providing the key management.
 * @param kmsConfig The KMS service implementation's configuration.
 * @param selector The name of the KEK selector service implementation used to select the KEK for a topic.
 * @param selectorConfig The KEK selector service implementation's configuration.
 * @param experimental Experimental configuration properties, subject to change without notice.
 * @param unresolvedKeyPolicy The policy applied when the KEK for a topic cannot be resolved.
 */
public record RecordEncryptionConfig(@JsonProperty(required = true) @PluginImplName(KmsService.class) String kms,
                                     @PluginImplConfig(implNameProperty = "kms") Object kmsConfig,

                                     @JsonProperty(required = true) @PluginImplName(KekSelectorService.class) String selector,
                                     @PluginImplConfig(implNameProperty = "selector") Object selectorConfig,
                                     @JsonProperty Map<String, Object> experimental,
                                     @JsonProperty UnresolvedKeyPolicy unresolvedKeyPolicy)
        implements CommonEncryptionConfig {

    /** The default initial size, in bytes, of the buffer used to hold an encrypted record. */
    public static final int RECORD_BUFFER_DEFAULT_INITIAL_BYTES = 1024 * 1024;

    /**
     * Creates a record encryption config, applying an empty map if {@code experimental} is null.
     */
    public RecordEncryptionConfig {
        experimental = experimental == null ? Map.of() : experimental;
    }

    /**
     * Returns the policy applied when the KEK for a topic cannot be resolved, defaulting to
     * {@link UnresolvedKeyPolicy#PASSTHROUGH_UNENCRYPTED}.
     * @return the policy applied when the KEK for a topic cannot be resolved.
     */
    @Override
    public UnresolvedKeyPolicy unresolvedKeyPolicy() {
        return unresolvedKeyPolicy == null ? UnresolvedKeyPolicy.PASSTHROUGH_UNENCRYPTED : unresolvedKeyPolicy;
    }
}

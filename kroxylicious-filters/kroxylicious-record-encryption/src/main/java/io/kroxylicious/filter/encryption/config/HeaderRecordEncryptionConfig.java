/*
 * Copyright Kroxylicious Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */

package io.kroxylicious.filter.encryption.config;

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
 *        for {@link io.kroxylicious.filter.encryption.RecordEncryption}.
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
     * Creates a header record encryption config, applying an empty map if {@code experimental} is null and
     * {@link UnresolvedKeyPolicy#REJECT} if {@code unresolvedKeyPolicy} is null.
     * @throws IllegalArgumentException if {@code selector} is not {@value #HEADER_KEK_SELECTOR}.
     */
    public HeaderRecordEncryptionConfig {
        if (!HEADER_KEK_SELECTOR.equals(selector)) {
            throw new IllegalArgumentException("selector must be " + HEADER_KEK_SELECTOR + ", but was " + selector);
        }
        Objects.requireNonNull(selectorConfig, "selectorConfig must not be null");
        experimental = experimental == null ? Map.of() : experimental;
        unresolvedKeyPolicy = unresolvedKeyPolicy == null ? UnresolvedKeyPolicy.REJECT : unresolvedKeyPolicy;
    }
}

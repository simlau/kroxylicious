/*
 * Copyright Kroxylicious Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */

package io.kroxylicious.filter.encryption.config;

import java.util.Map;
import java.util.Optional;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;

/**
 * Converts the values of the experimental configuration properties. Used by {@link CommonEncryptionConfig}, and by
 * config records which validate an experimental property when they are created.
 */
final class ExperimentalProperties {

    private ExperimentalProperties() {
    }

    @Nullable
    static Integer intOrElse(@NonNull Map<String, Object> experimental, @NonNull String property, @Nullable Integer defaultValue) {
        return Optional.ofNullable(experimental.get(property)).map(value -> switch (value) {
            case Number number -> number.intValue();
            case String stringValue -> Integer.parseInt(stringValue);
            default -> throw new IllegalArgumentException("could not convert " + property + " with type " + value.getClass().getSimpleName() + " to Integer");
        }).orElse(defaultValue);
    }

    @Nullable
    static Long longOrNull(@NonNull Map<String, Object> experimental, @NonNull String property) {
        return Optional.ofNullable(experimental.get(property)).map(value -> switch (value) {
            case Number number -> number.longValue();
            case String stringValue -> Long.parseLong(stringValue);
            default -> throw new IllegalArgumentException("could not convert " + property + " with type " + value.getClass().getSimpleName() + " to Long");
        }).orElse(null);
    }
}

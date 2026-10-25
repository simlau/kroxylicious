/*
 * Copyright Kroxylicious Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */

package io.kroxylicious.filter.encryption.config;

import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.fasterxml.jackson.annotation.JsonProperty;

import edu.umd.cs.findbugs.annotations.Nullable;

/**
 * The configuration of the {@code HeaderKekSelector} of the {@link io.kroxylicious.filter.encryption.HeaderRecordEncryption} filter,
 * which selects the KEK of each produced record from a record header.
 * @param header The name of the record header holding the KEK id, for example {@code X-Kek-Id}. Matched case-sensitively.
 * @param template The template used to derive the KEK alias from the header value. It must contain the
 *        {@value #HEADER_VALUE_PLACEHOLDER} placeholder exactly once, and no other placeholder.
 * @param missingHeader What to do with a record without the header, defaulting to {@link MissingHeaderPolicy#REJECT}.
 */
public record HeaderKekSelectorConfig(@JsonProperty(required = true) String header,
                                      @JsonProperty(required = true) String template,
                                      @JsonProperty @Nullable MissingHeaderPolicy missingHeader) {

    /** The placeholder in the {@code template} which is replaced with the header value. */
    public static final String HEADER_VALUE_PLACEHOLDER = "$(headerValue)";

    private static final Pattern PLACEHOLDER = Pattern.compile("\\$\\((.*?)\\)");

    /**
     * Creates a header KEK selector config, applying {@link MissingHeaderPolicy#REJECT} if {@code missingHeader} is null.
     * @throws IllegalArgumentException if {@code header} is empty or {@code template} does not contain
     * {@value #HEADER_VALUE_PLACEHOLDER} exactly once, or contains another placeholder.
     */
    public HeaderKekSelectorConfig {
        Objects.requireNonNull(header, "header must not be null");
        Objects.requireNonNull(template, "template must not be null");
        if (header.isEmpty()) {
            throw new IllegalArgumentException("header must not be empty");
        }
        int placeholders = 0;
        Matcher matcher = PLACEHOLDER.matcher(template);
        while (matcher.find()) {
            if (!matcher.group().equals(HEADER_VALUE_PLACEHOLDER)) {
                throw new IllegalArgumentException("Unknown template parameter: " + matcher.group(1) + ", the only parameter is " + HEADER_VALUE_PLACEHOLDER);
            }
            placeholders++;
        }
        if (placeholders != 1) {
            throw new IllegalArgumentException("template must contain " + HEADER_VALUE_PLACEHOLDER + " exactly once, but contains it " + placeholders + " times");
        }
        missingHeader = missingHeader == null ? MissingHeaderPolicy.REJECT : missingHeader;
    }
}

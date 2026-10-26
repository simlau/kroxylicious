/*
 * Copyright Kroxylicious Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */

package io.kroxylicious.filter.encryption;

import java.util.Optional;
import java.util.stream.Stream;

import org.apache.kafka.common.InvalidRecordException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

import io.kroxylicious.filter.encryption.config.HeaderKekSelectorConfig;
import io.kroxylicious.kafka.common.header.Header;
import io.kroxylicious.kafka.common.header.internals.RecordHeader;
import io.kroxylicious.kafka.common.record.internal.Record;
import io.kroxylicious.testing.filter.record.RecordTestUtils;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.params.provider.Arguments.argumentSet;

class HeaderKekResolverTest {

    private static final HeaderKekResolver RESOLVER = new HeaderKekResolver(new HeaderKekSelectorConfig("X-Kek-Id", "user-kek-$(headerValue)", null));

    @Test
    void uuidHeaderValueMapsToAlias() {
        // Given
        Record record = record(kekHeader("3fca3d12-42c5-4971-adb8-13ff9da4d68a"));

        // When
        Optional<String> alias = RESOLVER.aliasFor(record);

        // Then
        assertThat(alias).contains("user-kek-3fca3d12-42c5-4971-adb8-13ff9da4d68a");
    }

    @ParameterizedTest
    @ValueSource(strings = { "a", "AZaz09_-", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" })
    void validHeaderValuesAccepted(String value) {
        // Given
        Record record = record(kekHeader(value));

        // When
        Optional<String> alias = RESOLVER.aliasFor(record);

        // Then
        assertThat(alias).contains("user-kek-" + value);
    }

    @Test
    void noHeaderGivesEmpty() {
        // Given
        Record record = record(new RecordHeader("other", "x".getBytes(UTF_8)));

        // When
        Optional<String> alias = RESOLVER.aliasFor(record);

        // Then
        assertThat(alias).isEmpty();
    }

    @Test
    void headerNameIsCaseSensitive() {
        // Given
        Record record = record(new RecordHeader("x-kek-id", "abc".getBytes(UTF_8)));

        // When
        Optional<String> alias = RESOLVER.aliasFor(record);

        // Then
        assertThat(alias).isEmpty();
    }

    static Stream<Arguments> badHeaderValuesRejected() {
        return Stream.of(
                argumentSet("path traversal", (Object) new Header[]{ kekHeader("../x") }),
                argumentSet("slash", (Object) new Header[]{ kekHeader("a/b") }),
                argumentSet("percent-encoded slash", (Object) new Header[]{ kekHeader("%2F") }),
                argumentSet("empty", (Object) new Header[]{ kekHeader("") }),
                argumentSet("65 characters", (Object) new Header[]{ kekHeader("a".repeat(65)) }),
                argumentSet("non-ASCII bytes", (Object) new Header[]{ new RecordHeader("X-Kek-Id", new byte[]{ (byte) 0xC3, (byte) 0xA6 }) }),
                argumentSet("null value", (Object) new Header[]{ new RecordHeader("X-Kek-Id", (byte[]) null) }),
                argumentSet("two X-Kek-Id headers", (Object) new Header[]{ kekHeader("a"), kekHeader("a") }));
    }

    @ParameterizedTest
    @MethodSource
    void badHeaderValuesRejected(Header[] headers) {
        // Given
        Record record = record(headers);

        // When / Then
        assertThatThrownBy(() -> RESOLVER.aliasFor(record))
                .isInstanceOf(InvalidHeaderException.class)
                .satisfies(e -> assertThat(((InvalidHeaderException) e).getApiException()).isInstanceOf(InvalidRecordException.class));
    }

    @ParameterizedTest
    @ValueSource(strings = { "X-Shredded", "x-shredded" })
    void forgedShreddedHeaderRejected(String headerName) {
        // Given
        Record record = record(kekHeader("abc"), new RecordHeader(headerName, "true".getBytes(UTF_8)));

        // When / Then
        assertThatThrownBy(() -> RESOLVER.aliasFor(record))
                .isInstanceOf(InvalidHeaderException.class)
                .hasMessageContaining("X-Shredded");
    }

    @Test
    void forgedShreddedHeaderRejectedWithoutKekHeader() {
        // Given
        Record record = record(new RecordHeader("X-Shredded", (byte[]) null));

        // When / Then
        assertThatThrownBy(() -> RESOLVER.aliasFor(record))
                .isInstanceOf(InvalidHeaderException.class);
    }

    @Test
    void clientMadeEncryptionHeaderRejected() {
        // Given
        Record record = record(kekHeader("abc"), new RecordHeader("kroxylicious.io/encryption", new byte[]{ 2 }));

        // When / Then
        assertThatThrownBy(() -> RESOLVER.aliasFor(record))
                .isInstanceOf(InvalidHeaderException.class)
                .hasMessageContaining("kroxylicious.io/encryption");
    }

    @Test
    void clientMadeEncryptionHeaderRejectedWithoutKekHeader() {
        // Given
        Record record = record(new RecordHeader("kroxylicious.io/encryption", new byte[]{ 2 }));

        // When / Then
        assertThatThrownBy(() -> RESOLVER.aliasFor(record))
                .isInstanceOf(InvalidHeaderException.class);
    }

    @Test
    void rejectionDoesNotEchoHeaderValue() {
        // Given
        Record record = record(kekHeader("secret/../value"));

        // When / Then
        assertThatThrownBy(() -> RESOLVER.aliasFor(record))
                .isInstanceOf(InvalidHeaderException.class)
                .message().doesNotContain("secret");
    }

    private static Header kekHeader(String value) {
        return new RecordHeader("X-Kek-Id", value.getBytes(UTF_8));
    }

    private static Record record(Header... headers) {
        return RecordTestUtils.record(0L, 0L, "key", "value", headers);
    }
}

/*
 * Copyright Kroxylicious Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */

package io.kroxylicious.filter.encryption.config;

import java.time.Duration;
import java.util.Map;
import java.util.stream.Stream;

import org.assertj.core.api.InstanceOfAssertFactories;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.params.provider.Arguments.argumentSet;

class HeaderRecordEncryptionConfigTest {

    private static final ObjectMapper MAPPER = new ObjectMapper(new YAMLFactory());

    /**
     * The proxy config sketch of the design (levior/infra, docs/superpowers/specs/2026-10-22-openbao-crypto-shredding-design.md, section 3).
     */
    private static final String SPEC_YAML = """
            virtualClusters:
              - name: levior
                targetCluster:
                  bootstrapServers: levior-kafka-bootstrap.kafka.svc:9092
                gateways:
                  - name: in-cluster
                    portIdentifiesNode:
                      bootstrapAddress: kroxylicious.levior.svc:9192
            filterDefinitions:
              - name: encrypt
                type: HeaderRecordEncryption
                config:
                  kms: VaultKmsService
                  kmsConfig:
                    vaultUrl: http://openbao-active.openbao.svc:8200
                    vaultNamespace: simlau-playground   # or the path prefix /v1/simlau-playground
                    transitEnginePath: transit
                    credentials:
                      kubernetes:
                        vaultRole: proxy
                  selector: HeaderKekSelector
                  selectorConfig:
                    header: X-Kek-Id
                    template: "user-kek-$(headerValue)"
                    missingHeader: REJECT
                  unresolvedKeyPolicy: REJECT
            defaultFilters: [encrypt]
            """;

    private static final HeaderKekSelectorConfig SELECTOR_CONFIG = new HeaderKekSelectorConfig("X-Kek-Id", "user-kek-$(headerValue)", null);

    @Test
    void specYamlParses() throws Exception {
        // Given
        JsonNode filterConfig = MAPPER.readTree(SPEC_YAML).path("filterDefinitions").get(0).path("config");

        // When
        HeaderRecordEncryptionConfig config = MAPPER.treeToValue(filterConfig, HeaderRecordEncryptionConfig.class);

        // Then
        assertThat(config.kms()).isEqualTo("VaultKmsService");
        assertThat(config.kmsConfig()).asInstanceOf(InstanceOfAssertFactories.MAP)
                .containsEntry("vaultUrl", "http://openbao-active.openbao.svc:8200")
                .containsEntry("transitEnginePath", "transit");
        assertThat(config.selector()).isEqualTo("HeaderKekSelector");
        assertThat(config.selectorConfig()).isEqualTo(new HeaderKekSelectorConfig("X-Kek-Id", "user-kek-$(headerValue)", MissingHeaderPolicy.REJECT));
        assertThat(config.unresolvedKeyPolicy()).isEqualTo(UnresolvedKeyPolicy.REJECT);
        assertThat(config.experimental()).isEmpty();
    }

    @Test
    void defaults() throws Exception {
        // Given
        String yaml = """
                kms: VaultKmsService
                kmsConfig: {}
                selector: HeaderKekSelector
                selectorConfig:
                  header: X-Kek-Id
                  template: "user-kek-$(headerValue)"
                """;

        // When
        HeaderRecordEncryptionConfig config = MAPPER.readValue(yaml, HeaderRecordEncryptionConfig.class);

        // Then
        assertThat(config.selectorConfig().missingHeader()).isEqualTo(MissingHeaderPolicy.REJECT);
        assertThat(config.unresolvedKeyPolicy()).isEqualTo(UnresolvedKeyPolicy.REJECT);
        assertThat(config.experimental()).isEmpty();
    }

    @Test
    void missingHeaderPassthroughParses() throws Exception {
        // Given
        String yaml = configYaml("HeaderKekSelector", "X-Kek-Id", "user-kek-$(headerValue)") + "    missingHeader: PASSTHROUGH_UNENCRYPTED\n";

        // When
        HeaderRecordEncryptionConfig config = MAPPER.readValue(yaml, HeaderRecordEncryptionConfig.class);

        // Then
        assertThat(config.selectorConfig().missingHeader()).isEqualTo(MissingHeaderPolicy.PASSTHROUGH_UNENCRYPTED);
    }

    static Stream<Arguments> invalidConfig() {
        return Stream.of(
                argumentSet("selector Other", configYaml("Other", "X-Kek-Id", "user-kek-$(headerValue)")),
                argumentSet("template without $(headerValue)", configYaml("HeaderKekSelector", "X-Kek-Id", "user-kek")),
                argumentSet("template with $(headerValue) twice", configYaml("HeaderKekSelector", "X-Kek-Id", "$(headerValue)-$(headerValue)")),
                argumentSet("template with another placeholder", configYaml("HeaderKekSelector", "X-Kek-Id", "$(topicName)-$(headerValue)")),
                argumentSet("empty header name", configYaml("HeaderKekSelector", "", "user-kek-$(headerValue)")),
                argumentSet("no selectorConfig", """
                        kms: VaultKmsService
                        selector: HeaderKekSelector
                        """),
                argumentSet("no selector", """
                        kms: VaultKmsService
                        selectorConfig:
                          header: X-Kek-Id
                          template: "user-kek-$(headerValue)"
                        """),
                argumentSet("no template", """
                        kms: VaultKmsService
                        selector: HeaderKekSelector
                        selectorConfig:
                          header: X-Kek-Id
                        """));
    }

    @ParameterizedTest
    @MethodSource
    void invalidConfig(String yaml) {
        // When / Then
        assertThatThrownBy(() -> MAPPER.readValue(yaml, HeaderRecordEncryptionConfig.class))
                .isInstanceOf(JsonMappingException.class);
    }

    @Test
    void selectorMustBeHeaderKekSelector() {
        // When / Then
        assertThatThrownBy(() -> new HeaderRecordEncryptionConfig("kms", null, "Other", SELECTOR_CONFIG, null, null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("HeaderKekSelector");
    }

    @Test
    void templateMustContainHeaderValuePlaceholder() {
        // When / Then
        assertThatThrownBy(() -> new HeaderKekSelectorConfig("X-Kek-Id", "user-kek", null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("$(headerValue)");
    }

    @Test
    void experimentalParsingIsSharedWithRecordEncryption() {
        // Given
        Map<String, Object> experimental = Map.of(
                "decryptedDekExpireAfterWriteSeconds", 3600,
                "resolvedAliasCacheSize", "7",
                "encryptionBufferMinimumSizeBytes", 500,
                "maxEncryptionsPerDek", 1000L);
        var stock = new RecordEncryptionConfig("kms", null, "selector", null, experimental, null);
        var header = new HeaderRecordEncryptionConfig("kms", null, "HeaderKekSelector", SELECTOR_CONFIG, experimental, null);

        // When
        KmsCacheConfig kmsCache = header.kmsCache();

        // Then
        assertThat(kmsCache).isEqualTo(stock.kmsCache());
        assertThat(kmsCache.decryptedDekExpireAfterWriteDuration()).isEqualTo(Duration.ofHours(1));
        assertThat(header.encryptionBuffer()).isEqualTo(stock.encryptionBuffer());
        assertThat(header.dekManager()).isEqualTo(stock.dekManager());
    }

    private static String configYaml(String selector, String header, String template) {
        return """
                kms: VaultKmsService
                kmsConfig: {}
                selector: %s
                selectorConfig:
                    header: "%s"
                    template: "%s"
                """.formatted(selector, header, template);
    }
}

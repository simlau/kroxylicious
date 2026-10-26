/*
 * Copyright Kroxylicious Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */

package io.kroxylicious.filter.encryption;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.ServiceLoader;
import java.util.UUID;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import io.micrometer.core.instrument.Metrics;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;

import io.kroxylicious.filter.encryption.config.HeaderKekSelectorConfig;
import io.kroxylicious.filter.encryption.config.HeaderRecordEncryptionConfig;
import io.kroxylicious.filter.encryption.config.MissingHeaderPolicy;
import io.kroxylicious.filter.encryption.crypto.EncryptionHeader;
import io.kroxylicious.filter.encryption.dek.CipherSpecResolver;
import io.kroxylicious.kafka.common.header.Header;
import io.kroxylicious.kafka.common.header.internals.RecordHeader;
import io.kroxylicious.kafka.common.message.FetchResponseData;
import io.kroxylicious.kafka.common.message.FetchResponseData.FetchableTopicResponse;
import io.kroxylicious.kafka.common.message.FetchResponseData.PartitionData;
import io.kroxylicious.kafka.common.message.ProduceRequestData;
import io.kroxylicious.kafka.common.message.ProduceRequestData.PartitionProduceData;
import io.kroxylicious.kafka.common.message.ProduceRequestData.TopicProduceData;
import io.kroxylicious.kafka.common.message.RequestHeaderData;
import io.kroxylicious.kafka.common.message.ResponseHeaderData;
import io.kroxylicious.kafka.common.protocol.Errors;
import io.kroxylicious.kafka.common.record.internal.MemoryRecords;
import io.kroxylicious.kafka.common.record.internal.Record;
import io.kroxylicious.kafka.common.utils.ByteUtils;
import io.kroxylicious.kms.provider.kroxylicious.inmemory.InMemoryEdek;
import io.kroxylicious.kms.provider.kroxylicious.inmemory.InMemoryKms;
import io.kroxylicious.kms.provider.kroxylicious.inmemory.UnitTestingKmsService;
import io.kroxylicious.kms.service.KmsService;
import io.kroxylicious.proxy.filter.FilterDispatchExecutor;
import io.kroxylicious.proxy.filter.FilterFactory;
import io.kroxylicious.proxy.filter.FilterFactoryContext;
import io.kroxylicious.proxy.filter.RequestFilterResult;
import io.kroxylicious.proxy.filter.ResponseFilterResult;
import io.kroxylicious.proxy.plugin.Plugin;
import io.kroxylicious.testing.filter.assertj.MockFilterContextAssert;
import io.kroxylicious.testing.filter.context.MockFilterContext;
import io.kroxylicious.testing.filter.record.RecordTestUtils;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.params.provider.Arguments.argumentSet;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.clearInvocations;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

class HeaderRecordEncryptionTest {

    private static final String TOPIC = "guestbook";
    private static final String KMS_NAME = "UnitTestingKmsService";
    private static final Header OTHER_HEADER = new RecordHeader("other", "o".getBytes(UTF_8));

    private InMemoryKms kms;
    private HeaderRecordEncryption<UUID, InMemoryEdek> factory;
    private SharedEncryptionContext<UUID, InMemoryEdek, HeaderRecordEncryptionConfig> sharedContext;
    private SimpleMeterRegistry meterRegistry;

    @BeforeEach
    void setUp() {
        meterRegistry = new SimpleMeterRegistry();
        Metrics.globalRegistry.add(meterRegistry);
    }

    @AfterEach
    void tearDown() {
        if (sharedContext != null) {
            factory.close(sharedContext);
        }
        meterRegistry.getMeters().forEach(Metrics.globalRegistry::remove);
        Metrics.globalRegistry.remove(meterRegistry);
    }

    @Test
    void registeredAsFilterFactory() {
        // When
        var types = ServiceLoader.load(FilterFactory.class).stream().map(ServiceLoader.Provider::type).toList();

        // Then
        assertThat(types).contains(HeaderRecordEncryption.class, RecordEncryption.class);
        assertThat(HeaderRecordEncryption.class.getSimpleName()).isEqualTo("HeaderRecordEncryption");
        assertThat(HeaderRecordEncryption.class.getAnnotation(Plugin.class).configType()).isEqualTo(HeaderRecordEncryptionConfig.class);
    }

    @Test
    void mixedKeksInOnePartitionRoundTrip() {
        // Given
        var filter = createFilter(MissingHeaderPolicy.PASSTHROUGH_UNENCRYPTED);
        String idA = UUID.randomUUID().toString();
        String idB = UUID.randomUUID().toString();
        UUID kekA = createKek(idA);
        UUID kekB = createKek(idB);
        List<Record> original = List.of(
                RecordTestUtils.record(0L, 100L, "k0", "v0", new Header[]{ kekHeader(idA), OTHER_HEADER }),
                RecordTestUtils.record(1L, 101L, "k1", "v1", new Header[]{ kekHeader(idB) }),
                RecordTestUtils.record(2L, 102L, "k2", "v2", new Header[]{ OTHER_HEADER, kekHeader(idA) }),
                RecordTestUtils.record(3L, 103L, "k3", "v3", new Header[]{ OTHER_HEADER }));

        // When
        List<Record> produced = forwardedRecords(produce(filter, RecordTestUtils.memoryRecords(original)));
        List<Record> fetched = fetchedRecords(fetch(filter, RecordTestUtils.memoryRecords(produced)));

        // Then
        assertThat(produced).hasSize(4);
        assertThat(kekOf(produced.get(0))).isEqualTo(kekA);
        assertThat(kekOf(produced.get(1))).isEqualTo(kekB);
        assertThat(kekOf(produced.get(2))).isEqualTo(kekA);
        assertThat(produced.get(3).headers()).containsExactly(OTHER_HEADER);
        assertThat(RecordTestUtils.recordValueAsString(produced.get(3))).isEqualTo("v3");
        for (int i = 0; i < original.size(); i++) {
            Record expected = original.get(i);
            Record actual = produced.get(i);
            assertThat(actual.offset()).isEqualTo(expected.offset());
            assertThat(actual.timestamp()).isEqualTo(expected.timestamp());
            assertThat(RecordTestUtils.recordKeyAsString(actual)).isEqualTo(RecordTestUtils.recordKeyAsString(expected));
            assertThat(withoutEncryptionHeader(actual.headers())).containsExactly(expected.headers());
        }
        assertThat(fetched).extracting(RecordTestUtils::recordValueAsString).containsExactly("v0", "v1", "v2", "v3");
        assertThat(fetched).extracting(Record::headers).containsExactly(original.stream().map(Record::headers).toArray(Header[][]::new));
        assertThat(meterRegistry.get("kroxylicious_filter_record_encryption_encrypted_records").counter().count()).isEqualTo(3);
        assertThat(meterRegistry.get("kroxylicious_filter_record_encryption_plain_records").counter().count()).isEqualTo(1);
    }

    @Test
    void recordsOfDeletedKekAreShreddedOnFetch() {
        // Given
        var filter = createFilter(MissingHeaderPolicy.REJECT);
        String idA = UUID.randomUUID().toString();
        String idB = UUID.randomUUID().toString();
        UUID kekA = createKek(idA);
        createKek(idB);
        List<Record> produced = forwardedRecords(produce(filter, RecordTestUtils.memoryRecords(List.of(
                RecordTestUtils.record(0L, 100L, "k0", "v0", new Header[]{ kekHeader(idA) }),
                RecordTestUtils.record(1L, 101L, "k1", "v1", new Header[]{ kekHeader(idB) })))));
        kms.deleteAlias("user-kek-" + idA);
        kms.deleteKey(kekA);

        // When
        List<Record> fetched = fetchedRecords(fetch(filter, RecordTestUtils.memoryRecords(produced)));

        // Then
        assertThat(fetched.get(0).hasValue()).isFalse();
        assertThat(fetched.get(0).headers()).containsExactly(kekHeader(idA), new RecordHeader("X-Shredded", "true".getBytes(UTF_8)));
        assertThat(RecordTestUtils.recordValueAsString(fetched.get(1))).isEqualTo("v1");
        assertThat(meterRegistry.get("kroxylicious_filter_record_encryption_shredded_records").counter().count()).isEqualTo(1);
    }

    static Stream<Arguments> badHeaderValuesRejectWithoutKmsCall() {
        return Stream.of(
                argumentSet("path traversal", (Object) new Header[]{ kekHeader("../x") }),
                argumentSet("slash", (Object) new Header[]{ kekHeader("a/b") }),
                argumentSet("percent-encoded slash", (Object) new Header[]{ kekHeader("%2F") }),
                argumentSet("empty", (Object) new Header[]{ kekHeader("") }),
                argumentSet("65 characters", (Object) new Header[]{ kekHeader("a".repeat(65)) }),
                argumentSet("non-ASCII bytes", (Object) new Header[]{ new RecordHeader("X-Kek-Id", new byte[]{ (byte) 0xC3, (byte) 0xA6 }) }),
                argumentSet("two X-Kek-Id headers", (Object) new Header[]{ kekHeader("a"), kekHeader("a") }));
    }

    @ParameterizedTest
    @MethodSource
    void badHeaderValuesRejectWithoutKmsCall(Header[] badHeaders) {
        // Given
        var filter = createFilter(MissingHeaderPolicy.REJECT);
        String idA = UUID.randomUUID().toString();
        createKek(idA);
        MemoryRecords records = RecordTestUtils.memoryRecords(List.of(
                RecordTestUtils.record(0L, 100L, "k0", "v0", new Header[]{ kekHeader(idA) }),
                RecordTestUtils.record(1L, 101L, "k1", "v1", badHeaders)));

        // When
        CompletionStage<RequestFilterResult> result = produce(filter, records);

        // Then
        assertInvalidRecordResponse(result);
        verifyNoInteractions(kms);
    }

    @Test
    void forgedShreddedHeaderRejected() {
        // Given
        var filter = createFilter(MissingHeaderPolicy.PASSTHROUGH_UNENCRYPTED);
        String idA = UUID.randomUUID().toString();
        createKek(idA);
        MemoryRecords records = RecordTestUtils.memoryRecords(List.of(
                RecordTestUtils.record(0L, 100L, "k0", "v0", new Header[]{ kekHeader(idA), new RecordHeader("X-Shredded", "true".getBytes(UTF_8)) })));

        // When
        CompletionStage<RequestFilterResult> result = produce(filter, records);

        // Then
        assertInvalidRecordResponse(result);
        verifyNoInteractions(kms);
    }

    @Test
    void forgedShreddedHeaderOnRecordWithoutKekHeaderRejected() {
        // Given
        var filter = createFilter(MissingHeaderPolicy.PASSTHROUGH_UNENCRYPTED);
        MemoryRecords records = RecordTestUtils.memoryRecords(List.of(
                RecordTestUtils.record(0L, 100L, "k0", "v0", new Header[]{ new RecordHeader("X-Shredded", "true".getBytes(UTF_8)) })));

        // When
        CompletionStage<RequestFilterResult> result = produce(filter, records);

        // Then
        assertInvalidRecordResponse(result);
        verifyNoInteractions(kms);
    }

    @Test
    void clientMadeEncryptionHeaderRejected() {
        // Given
        var filter = createFilter(MissingHeaderPolicy.PASSTHROUGH_UNENCRYPTED);
        String idA = UUID.randomUUID().toString();
        createKek(idA);
        MemoryRecords records = RecordTestUtils.memoryRecords(List.of(
                RecordTestUtils.record(0L, 100L, "k0", "v0", new Header[]{ kekHeader(idA) }),
                RecordTestUtils.record(1L, 101L, "k1", "v1", new Header[]{ new RecordHeader(EncryptionHeader.ENCRYPTION_HEADER_NAME, new byte[]{ 2 }) })));

        // When
        CompletionStage<RequestFilterResult> result = produce(filter, records);

        // Then
        assertInvalidRecordResponse(result);
        verifyNoInteractions(kms);
    }

    @Test
    void tombstoneNamingDeletedKekPassesUnencrypted() {
        // Given
        var filter = createFilter(MissingHeaderPolicy.REJECT);
        String deletedId = UUID.randomUUID().toString();
        String idB = UUID.randomUUID().toString();
        UUID deletedKek = createKek(deletedId);
        createKek(idB);
        kms.deleteAlias("user-kek-" + deletedId);
        kms.deleteKey(deletedKek);
        clearInvocations(kms);
        MemoryRecords records = RecordTestUtils.memoryRecords(List.of(
                RecordTestUtils.record(0L, 100L, "k0", (String) null, new Header[]{ kekHeader(deletedId), OTHER_HEADER }),
                RecordTestUtils.record(1L, 101L, "k1", "v1", new Header[]{ kekHeader(idB) })));

        // When
        List<Record> produced = forwardedRecords(produce(filter, records));

        // Then
        assertThat(produced).hasSize(2);
        assertThat(produced.get(0).hasValue()).isFalse();
        assertThat(produced.get(0).headers()).containsExactly(kekHeader(deletedId), OTHER_HEADER);
        assertThat(RecordTestUtils.recordKeyAsString(produced.get(0))).isEqualTo("k0");
        assertThat(produced.get(1).headers()).extracting(Header::key).contains(EncryptionHeader.ENCRYPTION_HEADER_NAME);
        verify(kms, never()).resolveAlias("user-kek-" + deletedId);
        assertThat(meterRegistry.get("kroxylicious_filter_record_encryption_encrypted_records").counter().count()).isEqualTo(1);
        assertThat(meterRegistry.get("kroxylicious_filter_record_encryption_plain_records").counter().count()).isEqualTo(1);
    }

    static Stream<Arguments> tombstoneHeadersStillChecked() {
        return Stream.of(
                argumentSet("no X-Kek-Id", (Object) new Header[]{ OTHER_HEADER }),
                argumentSet("invalid X-Kek-Id", (Object) new Header[]{ kekHeader("../x") }),
                argumentSet("two X-Kek-Id headers", (Object) new Header[]{ kekHeader("a"), kekHeader("a") }),
                argumentSet("X-Shredded", (Object) new Header[]{ kekHeader("a"), new RecordHeader("X-Shredded", "true".getBytes(UTF_8)) }),
                argumentSet("client-made encryption header",
                        (Object) new Header[]{ kekHeader("a"), new RecordHeader(EncryptionHeader.ENCRYPTION_HEADER_NAME, new byte[]{ 2 }) }));
    }

    @ParameterizedTest
    @MethodSource
    void tombstoneHeadersStillChecked(Header[] headers) {
        // Given
        var filter = createFilter(MissingHeaderPolicy.REJECT);
        MemoryRecords records = RecordTestUtils.memoryRecords(List.of(
                RecordTestUtils.record(0L, 100L, "k0", (String) null, headers)));

        // When
        CompletionStage<RequestFilterResult> result = produce(filter, records);

        // Then
        assertInvalidRecordResponse(result);
        verifyNoInteractions(kms);
    }

    @Test
    void missingHeaderRejects() {
        // Given
        var filter = createFilter(MissingHeaderPolicy.REJECT);
        String idA = UUID.randomUUID().toString();
        createKek(idA);
        MemoryRecords records = RecordTestUtils.memoryRecords(List.of(
                RecordTestUtils.record(0L, 100L, "k0", "v0", new Header[]{ kekHeader(idA) }),
                RecordTestUtils.record(1L, 101L, "k1", "v1", new Header[]{ OTHER_HEADER })));

        // When
        CompletionStage<RequestFilterResult> result = produce(filter, records);

        // Then
        assertInvalidRecordResponse(result);
        verifyNoInteractions(kms);
    }

    @Test
    void unknownKekRejects() {
        // Given
        var filter = createFilter(MissingHeaderPolicy.REJECT);
        String unknownId = UUID.randomUUID().toString();
        MemoryRecords records = RecordTestUtils.memoryRecords(List.of(
                RecordTestUtils.record(0L, 100L, "k0", "v0", new Header[]{ kekHeader(unknownId) })));

        // When
        CompletionStage<RequestFilterResult> result = produce(filter, records);

        // Then
        assertInvalidRecordResponse(result);
        verify(kms, atLeastOnce()).resolveAlias("user-kek-" + unknownId);
        verify(kms, never()).generateKey();
        verify(kms, never()).createAlias(any(), any());
        verify(kms, never()).generateDekPair(any());
    }

    private RecordEncryptionFilter<UUID> createFilter(MissingHeaderPolicy missingHeaderPolicy) {
        var kmsService = UnitTestingKmsService.newInstance();
        kmsService.initialize(new UnitTestingKmsService.Config());
        kms = spy(kmsService.buildKms());
        @SuppressWarnings("unchecked")
        KmsService<Object, UUID, InMemoryEdek> mockKmsService = mock(KmsService.class);
        doReturn(kms).when(mockKmsService).buildKms();

        FilterDispatchExecutor dispatchExecutor = mock(FilterDispatchExecutor.class);
        doAnswer(invocation -> {
            invocation.<Runnable> getArgument(0).run();
            return null;
        }).when(dispatchExecutor).execute(any());
        FilterFactoryContext factoryContext = mock(FilterFactoryContext.class);
        doReturn(mockKmsService).when(factoryContext).pluginInstance(KmsService.class, KMS_NAME);
        doReturn(dispatchExecutor).when(factoryContext).filterDispatchExecutor();

        var config = new HeaderRecordEncryptionConfig(KMS_NAME, new UnitTestingKmsService.Config(), "HeaderKekSelector",
                new HeaderKekSelectorConfig("X-Kek-Id", "user-kek-$(headerValue)", missingHeaderPolicy), Map.of(), null);
        factory = new HeaderRecordEncryption<>();
        sharedContext = factory.initialize(factoryContext, config);
        RecordEncryptionFilter<UUID> filter = factory.createFilter(factoryContext, sharedContext);
        clearInvocations(kms);
        return filter;
    }

    private UUID createKek(String id) {
        UUID kek = kms.generateKey();
        kms.createAlias(kek, "user-kek-" + id);
        clearInvocations(kms);
        return kek;
    }

    private static Header kekHeader(String value) {
        return new RecordHeader("X-Kek-Id", value.getBytes(UTF_8));
    }

    private static CompletionStage<RequestFilterResult> produce(RecordEncryptionFilter<UUID> filter, MemoryRecords records) {
        var request = new ProduceRequestData().setAcks((short) 1);
        request.topicData().add(new TopicProduceData().setName(TOPIC)
                .setPartitionData(List.of(new PartitionProduceData().setIndex(0).setRecords(records))));
        var header = new RequestHeaderData();
        MockFilterContext context = MockFilterContext.builder(header, request).build();
        return filter.onProduceRequest(ProduceRequestData.HIGHEST_SUPPORTED_VERSION, header, request, context);
    }

    private static CompletionStage<ResponseFilterResult> fetch(RecordEncryptionFilter<UUID> filter, MemoryRecords records) {
        var response = new FetchResponseData();
        response.responses().add(new FetchableTopicResponse().setTopic(TOPIC)
                .setPartitions(List.of(new PartitionData().setPartitionIndex(0).setRecords(records))));
        var header = new ResponseHeaderData();
        MockFilterContext context = MockFilterContext.builder(header, response).build();
        return filter.onFetchResponse(FetchResponseData.HIGHEST_SUPPORTED_VERSION, header, response, context);
    }

    private static List<Record> forwardedRecords(CompletionStage<RequestFilterResult> stage) {
        var request = (ProduceRequestData) stage.toCompletableFuture().orTimeout(10, TimeUnit.SECONDS).join().message();
        List<Record> records = new ArrayList<>();
        request.topicData().forEach(topic -> topic.partitionData().forEach(partition -> ((MemoryRecords) partition.records()).records().forEach(records::add)));
        return records;
    }

    private static List<Record> fetchedRecords(CompletionStage<ResponseFilterResult> stage) {
        var response = (FetchResponseData) stage.toCompletableFuture().orTimeout(10, TimeUnit.SECONDS).join().message();
        List<Record> records = new ArrayList<>();
        response.responses().forEach(topic -> topic.partitions().forEach(partition -> ((MemoryRecords) partition.records()).records().forEach(records::add)));
        return records;
    }

    private static void assertInvalidRecordResponse(CompletionStage<RequestFilterResult> stage) {
        assertThat(stage).succeedsWithin(10, TimeUnit.SECONDS).satisfies(result -> MockFilterContextAssert.assertThat(result)
                .isShortCircuitResponse()
                .isErrorResponse()
                .errorResponse()
                .hasError(Errors.INVALID_RECORD));
    }

    private UUID kekOf(Record record) {
        assertThat(record.headers()).extracting(Header::key).contains(EncryptionHeader.ENCRYPTION_HEADER_NAME);
        ByteBuffer wrapper = record.value();
        CipherSpecResolver.ALL.fromSerializedId(wrapper.get());
        int edekLength = ByteUtils.readUnsignedVarint(wrapper);
        ByteBuffer edek = wrapper.slice(wrapper.position(), edekLength);
        return kms.edekSerde().deserialize(edek).kekRef();
    }

    private static Header[] withoutEncryptionHeader(Header[] headers) {
        return Arrays.stream(headers).filter(h -> !h.key().equals(EncryptionHeader.ENCRYPTION_HEADER_NAME)).toArray(Header[]::new);
    }
}

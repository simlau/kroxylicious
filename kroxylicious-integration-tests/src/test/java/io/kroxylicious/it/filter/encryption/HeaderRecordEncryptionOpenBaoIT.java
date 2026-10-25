/*
 * Copyright Kroxylicious Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */

package io.kroxylicious.it.filter.encryption;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.stream.StreamSupport;

import org.apache.kafka.clients.consumer.Consumer;
import org.apache.kafka.clients.consumer.ConsumerConfig;
import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.apache.kafka.clients.consumer.ConsumerRecords;
import org.apache.kafka.clients.producer.KafkaProducer;
import org.apache.kafka.clients.producer.Producer;
import org.apache.kafka.clients.producer.ProducerConfig;
import org.apache.kafka.clients.producer.ProducerRecord;
import org.apache.kafka.clients.producer.RecordMetadata;
import org.apache.kafka.common.InvalidRecordException;
import org.apache.kafka.common.KafkaException;
import org.apache.kafka.common.TopicPartition;
import org.apache.kafka.common.header.Header;
import org.apache.kafka.common.header.internals.RecordHeader;
import org.apache.kafka.common.message.FetchRequestData;
import org.apache.kafka.common.message.FetchResponseData;
import org.apache.kafka.common.protocol.ApiKeys;
import org.apache.kafka.common.record.internal.MemoryRecords;
import org.apache.kafka.common.record.internal.RecordBatch;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import io.github.nettyplus.leakdetector.junit.NettyLeakDetectorExtension;

import io.kroxylicious.filter.encryption.HeaderRecordEncryption;
import io.kroxylicious.filter.encryption.crypto.EncryptionHeader;
import io.kroxylicious.proxy.config.ConfigurationBuilder;
import io.kroxylicious.proxy.config.NamedFilterDefinition;
import io.kroxylicious.proxy.service.HostPort;
import io.kroxylicious.testing.integration.Request;
import io.kroxylicious.testing.integration.client.KafkaClient;
import io.kroxylicious.testing.integration.config.NamedFilterDefinitionBuilder;
import io.kroxylicious.testing.integration.tester.KroxyliciousTester;
import io.kroxylicious.testing.kafka.api.KafkaCluster;
import io.kroxylicious.testing.kafka.common.ClientConfig;
import io.kroxylicious.testing.kafka.junit5ext.KafkaClusterExtension;
import io.kroxylicious.testing.kafka.junit5ext.Topic;
import io.kroxylicious.testing.kafka.junit5ext.TopicNameMethodSource;

import static io.kroxylicious.testing.integration.tester.KroxyliciousConfigUtils.proxy;
import static io.kroxylicious.testing.integration.tester.KroxyliciousTesters.kroxyliciousTester;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assumptions.assumeThat;
import static org.awaitility.Awaitility.await;

/**
 * The {@code HeaderRecordEncryption} filter against OpenBao 2.7.1 (the Levior platform's version) and Kafka.
 * The proxy uses a token with only the proxy policy of a Levior app namespace; keys are created and deleted with the
 * root token. Each test creates its own keys. Decrypted DEKs live for 1 s, so a deleted or re-created key takes effect
 * on fetch about a second after the last fetch that loaded its DEK.
 */
@ExtendWith(KafkaClusterExtension.class)
@ExtendWith(NettyLeakDetectorExtension.class)
class HeaderRecordEncryptionOpenBaoIT {

    private static final String KEK_ID_HEADER = "X-Kek-Id";
    private static final String SHREDDED_HEADER = "X-Shredded";
    private static final Header TRACE_HEADER = new RecordHeader("trace", "t-1".getBytes(StandardCharsets.UTF_8));
    private static final Header OTHER_HEADER = new RecordHeader("other", new byte[]{ 0, 1, 2 });
    private static final Duration CONSUME_TIMEOUT = Duration.ofSeconds(30);
    // the decrypted-DEK lifetime is 1 s; this bounds how long the proxy may still serve a key that is gone
    private static final Duration KEY_CHANGE_TIMEOUT = Duration.ofSeconds(60);
    private static final Duration NO_PROGRESS_WINDOW = Duration.ofSeconds(10);
    // the sender waits for flush(), so everything sent before it goes to the broker as one batch per partition
    private static final Map<String, Object> ONE_BATCH = Map.of(
            ProducerConfig.LINGER_MS_CONFIG, 60_000,
            ProducerConfig.BATCH_SIZE_CONFIG, 1 << 20);
    private static final int FETCH_MAX_BYTES = 1 << 20;

    static KafkaCluster cluster;

    private static OpenBaoTestServer openBao;

    @BeforeAll
    static void startOpenBao() {
        assumeThat(OpenBaoTestServer.isAvailable()).as("Docker is available").isTrue();
        openBao = OpenBaoTestServer.start();
    }

    @AfterAll
    static void stopOpenBao() {
        if (openBao != null) {
            openBao.close();
        }
    }

    @Test
    void roundTripTwoUsers(@TopicNameMethodSource Topic topic,
                           @ClientConfig(name = ConsumerConfig.GROUP_ID_CONFIG, value = "direct") Consumer<byte[], byte[]> directConsumer)
            throws Exception {
        // Given
        String a = newUser(openBao);
        String b = newUser(openBao);
        var records = List.of(
                userRecord(topic, a, "a-1", "secret of a 1", 1_000L),
                userRecord(topic, b, "b-1", "secret of b 1", 1_001L),
                userRecord(topic, a, "a-2", "secret of a 2", 1_002L),
                userRecord(topic, b, "b-2", "secret of b 2", 1_003L));

        try (var tester = kroxyliciousTester(proxyWithFilter(openBao));
                var producer = tester.producer(ONE_BATCH)) {

            // When
            List<RecordMetadata> produced = sendInOneBatch(producer, records);

            // Then
            long endOffset = produced.get(produced.size() - 1).offset() + 1;
            assertThat(produced).extracting(RecordMetadata::partition).containsOnly(0);
            assertThat(brokerBatches(topic.name()))
                    .singleElement()
                    .satisfies(batch -> {
                        assertThat(batch.baseOffset()).isEqualTo(produced.get(0).offset());
                        assertThat(batch.lastOffset()).isEqualTo(endOffset - 1);
                    });
            List<ConsumerRecord<String, String>> consumed = consumeFromNewGroup(tester, topic, endOffset);
            assertThat(consumed).hasSize(records.size());
            for (int i = 0; i < records.size(); i++) {
                assertSameRecord(consumed.get(i), records.get(i), produced.get(i));
            }

            var tp = new TopicPartition(topic.name(), 0);
            directConsumer.assign(List.of(tp));
            directConsumer.seekToBeginning(List.of(tp));
            List<ConsumerRecord<byte[], byte[]>> stored = consumeToEnd(directConsumer, tp, endOffset);
            assertThat(stored).hasSize(records.size());
            for (int i = 0; i < records.size(); i++) {
                byte[] plaintext = records.get(i).value().getBytes(StandardCharsets.UTF_8);
                assertThat(stored.get(i).value()).isNotNull().isNotEqualTo(plaintext);
                assertThat(new String(stored.get(i).value(), StandardCharsets.ISO_8859_1)).doesNotContain(records.get(i).value());
                assertThat(stored.get(i).headers().lastHeader(EncryptionHeader.ENCRYPTION_HEADER_NAME)).isNotNull();
                assertThat(stored.get(i).headers().lastHeader(KEK_ID_HEADER).value())
                        .isEqualTo(records.get(i).headers().lastHeader(KEK_ID_HEADER).value());
            }
        }
    }

    @Test
    void deletedKeyIsShreddedAndConsumerContinues(@TopicNameMethodSource Topic topic) throws Exception {
        // Given
        String a = newUser(openBao);
        String b = newUser(openBao);
        var records = List.of(
                userRecord(topic, a, "a-1", "secret of a 1", 2_000L),
                userRecord(topic, b, "b-1", "secret of b 1", 2_001L),
                userRecord(topic, a, "a-2", "secret of a 2", 2_002L),
                userRecord(topic, b, "b-2", "secret of b 2", 2_003L));

        try (var tester = kroxyliciousTester(proxyWithFilter(openBao));
                var producer = tester.producer(ONE_BATCH)) {
            List<RecordMetadata> produced = sendInOneBatch(producer, records);
            long endOffset = produced.get(produced.size() - 1).offset() + 1;
            // loads the DEKs into the proxy's decrypt caches, as a consumer that read the topic before would
            consumeFromNewGroup(tester, topic, endOffset);
            openBao.deleteKey(OpenBaoTestServer.KEY_PREFIX + a);

            // When
            // each attempt is a new consumer group from the earliest offset, which must read up to the end offset;
            // until the cached DEK of a expires, a's records still decrypt
            List<ConsumerRecord<String, String>> consumed = await().atMost(KEY_CHANGE_TIMEOUT)
                    .pollInSameThread()
                    .until(() -> consumeFromNewGroup(tester, topic, endOffset),
                            attempt -> attempt.stream().filter(r -> isOfUser(r, a)).allMatch(r -> r.value() == null));

            // Then
            assertThat(consumed).hasSize(records.size());
            for (int i = 0; i < records.size(); i++) {
                ProducerRecord<String, String> original = records.get(i);
                if (isOfUser(original, a)) {
                    assertShreddedRecord(consumed.get(i), original, produced.get(i));
                }
                else {
                    assertSameRecord(consumed.get(i), original, produced.get(i));
                }
            }
        }
    }

    @Test
    void foreignShreddedHeaderStripped(@TopicNameMethodSource Topic topic,
                                       KafkaProducer<String, String> directProducer)
            throws Exception {
        // Given
        Header forged = new RecordHeader(SHREDDED_HEADER, "true".getBytes(StandardCharsets.UTF_8));
        Header forgedLowerCase = new RecordHeader("x-shredded", "true".getBytes(StandardCharsets.UTF_8));
        var plain1 = new ProducerRecord<>(topic.name(), 0, 3_000L, "k-1", "plain 1", List.of(TRACE_HEADER, forged, OTHER_HEADER));
        var plain2 = new ProducerRecord<>(topic.name(), 0, 3_001L, "k-2", "plain 2", List.of(forgedLowerCase, TRACE_HEADER));
        directProducer.send(plain1).get(5, TimeUnit.SECONDS);
        RecordMetadata last = directProducer.send(plain2).get(5, TimeUnit.SECONDS);

        try (var tester = kroxyliciousTester(proxyWithFilter(openBao))) {

            // When
            List<ConsumerRecord<String, String>> consumed = consumeFromNewGroup(tester, topic, last.offset() + 1);

            // Then
            assertThat(consumed).extracting(ConsumerRecord::value).containsExactly("plain 1", "plain 2");
            assertThat(consumed).extracting(ConsumerRecord::key).containsExactly("k-1", "k-2");
            assertThat(headersOf(consumed.get(0))).containsExactly(TRACE_HEADER, OTHER_HEADER);
            assertThat(headersOf(consumed.get(1))).containsExactly(TRACE_HEADER);
        }
    }

    @Test
    void recreatedKeyIsNotShredded(@TopicNameMethodSource Topic topic) throws Exception {
        // Given
        String b = newUser(openBao);
        var records = List.of(
                userRecord(topic, b, "b-1", "secret of b 1", 4_000L),
                userRecord(topic, b, "b-2", "secret of b 2", 4_001L));

        try (var tester = kroxyliciousTester(proxyWithFilter(openBao));
                var producer = tester.producer(ONE_BATCH)) {
            List<RecordMetadata> produced = sendInOneBatch(producer, records);
            long endOffset = produced.get(produced.size() - 1).offset() + 1;
            consumeFromNewGroup(tester, topic, endOffset);
            openBao.deleteKey(OpenBaoTestServer.KEY_PREFIX + b);
            openBao.createKey(OpenBaoTestServer.KEY_PREFIX + b);

            // When
            List<ConsumerRecord<String, String>> delivered = new ArrayList<>();
            await().atMost(KEY_CHANGE_TIMEOUT)
                    .pollInSameThread()
                    .until(() -> newGroupMakesNoProgress(tester, topic, delivered));

            // Then
            assertThat(delivered).allSatisfy(r -> assertThat(r.headers().headers(SHREDDED_HEADER)).isEmpty());
        }
    }

    @Test
    void openBaoDownFailsFetch(@TopicNameMethodSource Topic topic) throws Exception {
        // Given
        try (var ownOpenBao = OpenBaoTestServer.start()) {
            String b = newUser(ownOpenBao);
            var records = List.of(
                    userRecord(topic, b, "b-1", "secret of b 1", 5_000L),
                    userRecord(topic, b, "b-2", "secret of b 2", 5_001L));

            try (var tester = kroxyliciousTester(proxyWithFilter(ownOpenBao));
                    var producer = tester.producer(ONE_BATCH)) {
                List<RecordMetadata> produced = sendInOneBatch(producer, records);
                long endOffset = produced.get(produced.size() - 1).offset() + 1;
                consumeFromNewGroup(tester, topic, endOffset);
                ownOpenBao.stop();

                // When
                List<ConsumerRecord<String, String>> delivered = new ArrayList<>();
                await().atMost(KEY_CHANGE_TIMEOUT)
                        .pollInSameThread()
                        .until(() -> newGroupMakesNoProgress(tester, topic, delivered));

                // Then
                assertThat(delivered).allSatisfy(r -> assertThat(r.headers().headers(SHREDDED_HEADER)).isEmpty());
            }
        }
    }

    @Test
    void badHeaderRejected(@TopicNameMethodSource Topic topic) {
        // Given
        var record = new ProducerRecord<>(topic.name(), 0, 6_000L, "k", "v",
                List.<Header> of(new RecordHeader(KEK_ID_HEADER, "../x".getBytes(StandardCharsets.UTF_8))));

        try (var tester = kroxyliciousTester(proxyWithFilter(openBao));
                var producer = tester.producer()) {

            // When
            Future<RecordMetadata> send = producer.send(record);
            producer.flush();

            // Then
            assertThat(send).failsWithin(5, TimeUnit.SECONDS)
                    .withThrowableThat()
                    .havingCause()
                    .isInstanceOf(InvalidRecordException.class)
                    .withMessageContaining("record header " + KEK_ID_HEADER + " must be 1 to 64 characters");
        }
    }

    private static ConfigurationBuilder proxyWithFilter(OpenBaoTestServer server) {
        NamedFilterDefinition filter = new NamedFilterDefinitionBuilder("header-encryption", HeaderRecordEncryption.class.getSimpleName())
                .withConfig("kms", "VaultKmsService")
                .withConfig("kmsConfig", server.kmsConfig())
                .withConfig("selector", "HeaderKekSelector")
                .withConfig("selectorConfig", Map.of(
                        "header", KEK_ID_HEADER,
                        "template", OpenBaoTestServer.KEY_PREFIX + "$(headerValue)",
                        "missingHeader", "REJECT"))
                .withConfig("unresolvedKeyPolicy", "REJECT")
                .withConfig("experimental", Map.of("decryptedDekExpireAfterWriteSeconds", 1))
                .build();
        return proxy(cluster)
                .addToFilterDefinitions(filter)
                .addToDefaultFilters(filter.name());
    }

    /**
     * Creates the key of a new user.
     * @return the user's KEK id, the value of the {@value #KEK_ID_HEADER} header.
     */
    private static String newUser(OpenBaoTestServer server) {
        String kekId = UUID.randomUUID().toString();
        server.createKey(OpenBaoTestServer.KEY_PREFIX + kekId);
        return kekId;
    }

    private static ProducerRecord<String, String> userRecord(Topic topic, String kekId, String key, String value, long timestamp) {
        List<Header> headers = List.of(TRACE_HEADER,
                new RecordHeader(KEK_ID_HEADER, kekId.getBytes(StandardCharsets.UTF_8)),
                OTHER_HEADER);
        return new ProducerRecord<>(topic.name(), 0, timestamp, key, value, headers);
    }

    /**
     * Sends the records with a producer configured with {@link #ONE_BATCH}, to partition 0 of an empty topic, then flushes.
     * @throws IllegalStateException if the broker did not store them as exactly one batch, so a test relying on
     * records of several users in one batch fails instead of silently testing less.
     */
    private static List<RecordMetadata> sendInOneBatch(Producer<String, String> producer, List<ProducerRecord<String, String>> records) throws Exception {
        List<Future<RecordMetadata>> sends = records.stream().map(producer::send).toList();
        producer.flush();
        List<RecordMetadata> produced = new ArrayList<>();
        for (Future<RecordMetadata> send : sends) {
            produced.add(send.get(5, TimeUnit.SECONDS));
        }
        List<RecordBatch> batches = brokerBatches(records.get(0).topic());
        long firstOffset = produced.get(0).offset();
        long lastOffset = produced.get(produced.size() - 1).offset();
        if (batches.size() != 1 || batches.get(0).baseOffset() != firstOffset || batches.get(0).lastOffset() != lastOffset) {
            throw new IllegalStateException("records at offsets %d..%d were not stored as one batch: %s".formatted(firstOffset, lastOffset,
                    batches.stream().map(b -> b.baseOffset() + ".." + b.lastOffset()).toList()));
        }
        return produced;
    }

    /**
     * Fetches partition 0 of the topic from offset 0 directly from the broker, bypassing the proxy and the consumer,
     * which hides batch boundaries.
     * @return the record batches as the broker stores them.
     */
    private static List<RecordBatch> brokerBatches(String topicName) {
        HostPort broker = HostPort.parse(cluster.getBootstrapServers().split(",")[0]);
        var fetch = new FetchRequestData()
                .setReplicaId(-1)
                .setMaxWaitMs(0)
                .setMinBytes(1)
                .setMaxBytes(FETCH_MAX_BYTES)
                .setTopics(List.of(new FetchRequestData.FetchTopic()
                        .setTopic(topicName)
                        .setPartitions(List.of(new FetchRequestData.FetchPartition()
                                .setPartition(0)
                                .setFetchOffset(0)
                                .setPartitionMaxBytes(FETCH_MAX_BYTES)))));
        try (var client = new KafkaClient(broker.host(), broker.port())) {
            var response = (FetchResponseData) client.getSync(new Request(ApiKeys.FETCH, (short) 12, "batch-check", fetch)).payload().message();
            FetchResponseData.PartitionData partition = response.responses().get(0).partitions().get(0);
            if (response.errorCode() != 0 || partition.errorCode() != 0) {
                throw new IllegalStateException("direct fetch of %s failed: error codes %d, %d".formatted(topicName, response.errorCode(), partition.errorCode()));
            }
            List<RecordBatch> batches = new ArrayList<>();
            ((MemoryRecords) partition.records()).batches().forEach(batches::add);
            return batches;
        }
    }

    private static List<ConsumerRecord<String, String>> consumeFromNewGroup(KroxyliciousTester tester, Topic topic, long endOffset) {
        try (var consumer = tester.consumer(newGroup())) {
            consumer.subscribe(List.of(topic.name()));
            return consumeToEnd(consumer, new TopicPartition(topic.name(), 0), endOffset);
        }
    }

    /**
     * Polls until the consumer's position reaches {@code endOffset}.
     * @throws AssertionError if it doesn't within {@link #CONSUME_TIMEOUT}.
     */
    private static <K, V> List<ConsumerRecord<K, V>> consumeToEnd(Consumer<K, V> consumer, TopicPartition tp, long endOffset) {
        List<ConsumerRecord<K, V>> records = new ArrayList<>();
        long deadline = System.nanoTime() + CONSUME_TIMEOUT.toNanos();
        while (!consumer.assignment().contains(tp) || consumer.position(tp) < endOffset) {
            if (System.nanoTime() > deadline) {
                throw new AssertionError("consumer did not reach offset %d of %s within %s, got %d records"
                        .formatted(endOffset, tp, CONSUME_TIMEOUT, records.size()));
            }
            consumer.poll(Duration.ofMillis(200)).forEach(records::add);
        }
        return records;
    }

    /**
     * Polls for {@link #NO_PROGRESS_WINDOW} with a new consumer group from the earliest offset.
     * @param delivered collects every record the consumer got
     * @return true if the consumer got no record in that time or its poll failed with an exception.
     */
    private static boolean newGroupMakesNoProgress(KroxyliciousTester tester, Topic topic, List<ConsumerRecord<String, String>> delivered) {
        try (var consumer = tester.consumer(newGroup())) {
            consumer.subscribe(List.of(topic.name()));
            long deadline = System.nanoTime() + NO_PROGRESS_WINDOW.toNanos();
            while (System.nanoTime() < deadline) {
                ConsumerRecords<String, String> records;
                try {
                    records = consumer.poll(Duration.ofMillis(200));
                }
                catch (KafkaException e) {
                    // the fetch failed visibly, which counts as no progress
                    return true;
                }
                if (!records.isEmpty()) {
                    records.forEach(delivered::add);
                    return false;
                }
            }
            return true;
        }
    }

    private static Map<String, Object> newGroup() {
        return Map.of(ConsumerConfig.GROUP_ID_CONFIG, UUID.randomUUID().toString(),
                ConsumerConfig.AUTO_OFFSET_RESET_CONFIG, "earliest");
    }

    private static boolean isOfUser(ConsumerRecord<String, String> record, String kekId) {
        Header header = record.headers().lastHeader(KEK_ID_HEADER);
        return header != null && kekId.equals(new String(header.value(), StandardCharsets.UTF_8));
    }

    private static boolean isOfUser(ProducerRecord<String, String> record, String kekId) {
        Header header = record.headers().lastHeader(KEK_ID_HEADER);
        return header != null && kekId.equals(new String(header.value(), StandardCharsets.UTF_8));
    }

    private static List<Header> headersOf(ConsumerRecord<?, ?> record) {
        return StreamSupport.stream(record.headers().spliterator(), false).toList();
    }

    private static List<Header> headersOf(ProducerRecord<?, ?> record) {
        return StreamSupport.stream(record.headers().spliterator(), false).toList();
    }

    private static void assertSameRecord(ConsumerRecord<String, String> consumed, ProducerRecord<String, String> original, RecordMetadata produced) {
        assertThat(consumed.value()).isEqualTo(original.value());
        assertThat(consumed.key()).isEqualTo(original.key());
        assertThat(consumed.offset()).isEqualTo(produced.offset());
        assertThat(consumed.timestamp()).isEqualTo(original.timestamp());
        assertThat(headersOf(consumed)).containsExactlyElementsOf(headersOf(original));
    }

    private static void assertShreddedRecord(ConsumerRecord<String, String> consumed, ProducerRecord<String, String> original, RecordMetadata produced) {
        assertThat(consumed.value()).isNull();
        assertThat(consumed.key()).isEqualTo(original.key());
        assertThat(consumed.offset()).isEqualTo(produced.offset());
        assertThat(consumed.timestamp()).isEqualTo(original.timestamp());
        List<Header> expectedHeaders = new ArrayList<>(headersOf(original));
        expectedHeaders.add(new RecordHeader(SHREDDED_HEADER, "true".getBytes(StandardCharsets.UTF_8)));
        // the original headers in their order (X-Kek-Id included), no encryption header, then exactly one X-Shredded: true
        assertThat(headersOf(consumed)).containsExactlyElementsOf(expectedHeaders);
    }

    /**
     * Names every topic of this test with a fresh UUID.
     * @return the topic name.
     */
    @SuppressWarnings("unused") // used via @TopicNameMethodSource
    static String topicName() {
        return UUID.randomUUID().toString();
    }
}

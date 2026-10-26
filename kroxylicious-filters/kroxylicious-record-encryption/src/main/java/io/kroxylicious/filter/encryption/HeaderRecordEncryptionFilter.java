/*
 * Copyright Kroxylicious Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */

package io.kroxylicious.filter.encryption;

import java.util.ArrayList;
import java.util.Collections;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.stream.Collectors;

import org.slf4j.Logger;

import io.kroxylicious.filter.encryption.common.FilterThreadExecutor;
import io.kroxylicious.filter.encryption.common.RecordEncryptionUtil;
import io.kroxylicious.filter.encryption.config.MissingHeaderPolicy;
import io.kroxylicious.filter.encryption.config.RecordField;
import io.kroxylicious.filter.encryption.config.TopicNameBasedKekSelector;
import io.kroxylicious.filter.encryption.config.TopicNameKekSelection;
import io.kroxylicious.filter.encryption.config.UnresolvedKeyPolicy;
import io.kroxylicious.filter.encryption.decrypt.DecryptionManager;
import io.kroxylicious.filter.encryption.encrypt.EncryptionManager;
import io.kroxylicious.filter.encryption.encrypt.EncryptionScheme;
import io.kroxylicious.kafka.common.message.ProduceRequestData;
import io.kroxylicious.kafka.common.message.ProduceRequestData.PartitionProduceData;
import io.kroxylicious.kafka.common.message.ProduceRequestData.TopicProduceData;
import io.kroxylicious.kafka.common.record.internal.MemoryRecords;
import io.kroxylicious.kafka.common.record.internal.Record;
import io.kroxylicious.kafka.transform.RecordStream;
import io.kroxylicious.kms.service.Kms;
import io.kroxylicious.proxy.filter.FilterContext;
import io.kroxylicious.proxy.filter.metadata.TopicNameMapping;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;

import static org.slf4j.LoggerFactory.getLogger;

/**
 * The record encryption filter built by {@link HeaderRecordEncryption}. It differs from {@link RecordEncryptionFilter}
 * only on the produce path: it selects the KEK of each record from the record's KEK header.
 * <ol>
 *     <li>Every record of the request is checked and its KEK alias derived by the {@link HeaderKekResolver}.
 *     A bad header, a forged shredded marker or (with {@link MissingHeaderPolicy#REJECT}) a missing header
 *     rejects the whole request before any KMS call is made.</li>
 *     <li>The distinct aliases of the request are resolved through the KMS (and its caches).</li>
 *     <li>Each partition is encrypted in one pass, each record with the current DEK of its own KEK.</li>
 * </ol>
 * The fetch path is the one of {@link RecordEncryptionFilter}.
 * @param <K> The type of KEK reference
 */
class HeaderRecordEncryptionFilter<K> extends RecordEncryptionFilter<K> {

    private static final Logger LOGGER = getLogger(HeaderRecordEncryptionFilter.class);
    /** Only the value is encrypted, so the headers, including the KEK header, stay readable after the KEK is deleted. */
    private static final Set<RecordField> RECORD_FIELDS = Collections.unmodifiableSet(EnumSet.of(RecordField.RECORD_VALUE));

    private final EncryptionManager<K> encryptionManager;
    private final TopicNameBasedKekSelector<K> aliasResolver;
    private final HeaderKekResolver kekResolver;
    private final MissingHeaderPolicy missingHeaderPolicy;
    private final FilterThreadExecutor filterThreadExecutor;
    private final UnresolvedKeyPolicy unresolvedKeyPolicy;

    private record PartitionAliases(String topicName, PartitionProduceData partitionData, List<String> aliases) {}

    HeaderRecordEncryptionFilter(@NonNull EncryptionManager<K> encryptionManager,
                                 @NonNull DecryptionManager decryptionManager,
                                 @NonNull Kms<K, ?> kms,
                                 @NonNull HeaderKekResolver kekResolver,
                                 @NonNull MissingHeaderPolicy missingHeaderPolicy,
                                 @NonNull FilterThreadExecutor filterThreadExecutor,
                                 @NonNull UnresolvedKeyPolicy unresolvedKeyPolicy) {
        // no topic-based KEK selector: this class replaces the produce path that uses it
        super(encryptionManager, decryptionManager, null, filterThreadExecutor, unresolvedKeyPolicy);
        this.encryptionManager = Objects.requireNonNull(encryptionManager);
        // the identity template resolves each alias as it is, reusing the upstream alias resolution and its unknown-alias handling
        this.aliasResolver = new TemplateTopicNameKekSelector<>(kms, "$(topicName)");
        this.kekResolver = Objects.requireNonNull(kekResolver);
        this.missingHeaderPolicy = Objects.requireNonNull(missingHeaderPolicy);
        this.filterThreadExecutor = Objects.requireNonNull(filterThreadExecutor);
        this.unresolvedKeyPolicy = Objects.requireNonNull(unresolvedKeyPolicy);
    }

    @Override
    CompletionStage<ProduceRequestData> maybeEncodeProduce(ProduceRequestData request, FilterContext context, TopicNameMapping topicNameMapping) {
        List<PartitionAliases> partitions;
        try {
            partitions = aliasesOf(request, topicNameMapping);
        }
        catch (InvalidHeaderException e) {
            LOGGER.atWarn()
                    .addKeyValue("error", e.getMessage())
                    .log("rejecting produce request with an invalid record header");
            return CompletableFuture.failedFuture(e);
        }
        Set<String> aliases = partitions.stream()
                .flatMap(partition -> partition.aliases().stream())
                .filter(Objects::nonNull)
                .collect(Collectors.toSet());
        return filterThreadExecutor.completingOnFilterThread(aliasResolver.selectKek(aliases))
                .thenCompose(selection -> encryptPartitions(request, context, partitions, selection))
                .exceptionallyCompose(throwable -> {
                    LOGGER.atWarn().addKeyValue("error", throwable.getMessage())
                            .setCause(LOGGER.isDebugEnabled() ? throwable : null)
                            .log("failed to encrypt records");
                    return CompletableFuture.failedStage(throwable);
                });
    }

    private List<PartitionAliases> aliasesOf(ProduceRequestData request, TopicNameMapping topicNameMapping) {
        List<PartitionAliases> result = new ArrayList<>();
        for (TopicProduceData topicData : request.topicData()) {
            String topicName = getName(topicData, topicNameMapping);
            for (PartitionProduceData partitionData : topicData.partitionData()) {
                MemoryRecords records = (MemoryRecords) partitionData.records();
                List<String> aliases = RecordStream.ofRecords(records).toList((batch, kafkaRecord, state) -> aliasOrNull(kafkaRecord));
                result.add(new PartitionAliases(topicName, partitionData, aliases));
            }
        }
        return result;
    }

    /**
     * Returns the KEK alias of the given record, or null if it is passed through unencrypted.
     * A tombstone (a record without a value) has nothing to encrypt, so its headers are checked as for any record,
     * but its alias is not resolved: it passes through unencrypted even if its KEK is gone.
     */
    private @Nullable String aliasOrNull(Record kafkaRecord) {
        Optional<String> alias = kekResolver.aliasFor(kafkaRecord);
        if (alias.isEmpty() && missingHeaderPolicy == MissingHeaderPolicy.REJECT) {
            throw new InvalidHeaderException("record has no " + kekResolver.headerName() + " header");
        }
        if (!kafkaRecord.hasValue()) {
            return null;
        }
        return alias.orElse(null);
    }

    private CompletionStage<ProduceRequestData> encryptPartitions(ProduceRequestData request,
                                                                  FilterContext context,
                                                                  List<PartitionAliases> partitions,
                                                                  TopicNameKekSelection<K> selection) {
        Set<String> unresolvedAliases = selection.unresolvedTopicNames();
        if (!unresolvedAliases.isEmpty() && unresolvedKeyPolicy == UnresolvedKeyPolicy.REJECT) {
            return CompletableFuture.failedFuture(new UnresolvedKeyException("failed to resolve key for: " + new TreeSet<>(unresolvedAliases)));
        }
        var plainRecordsTotal = RecordEncryptionMetrics.plainRecordsCounter(context.getVirtualClusterName());
        var encryptedRecordsTotal = RecordEncryptionMetrics.encryptedRecordsCounter(context.getVirtualClusterName());
        Map<String, K> kekIds = selection.topicNameToKekId();
        var futures = partitions.stream().map(partition -> {
            List<EncryptionScheme<K>> schemes = new ArrayList<>(partition.aliases().size());
            int encrypted = 0;
            for (String alias : partition.aliases()) {
                K kekId = alias == null ? null : kekIds.get(alias);
                if (kekId == null) {
                    schemes.add(null);
                }
                else {
                    schemes.add(new EncryptionScheme<>(kekId, RECORD_FIELDS));
                    encrypted++;
                }
            }
            int encryptedRecords = encrypted;
            int plainRecords = schemes.size() - encrypted;
            PartitionProduceData partitionData = partition.partitionData();
            return encryptionManager.encryptPerRecord(partition.topicName(), partitionData.index(), schemes, (MemoryRecords) partitionData.records(),
                    context::createByteBufferOutputStream).thenApply(encryptedMemoryRecords -> {
                        partitionData.setRecords(encryptedMemoryRecords);
                        if (encryptedRecords > 0) {
                            encryptedRecordsTotal.withTags(RecordEncryptionMetrics.TOPIC_NAME, partition.topicName()).increment(encryptedRecords);
                        }
                        if (plainRecords > 0) {
                            plainRecordsTotal.withTags(RecordEncryptionMetrics.TOPIC_NAME, partition.topicName()).increment(plainRecords);
                        }
                        return (Void) null;
                    });
        }).toList();
        return RecordEncryptionUtil.join(futures).thenApply(ignored -> request);
    }
}

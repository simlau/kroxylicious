/*
 * Copyright Kroxylicious Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */

package io.kroxylicious.filter.encryption;

import java.time.Duration;
import java.util.Objects;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import io.kroxylicious.filter.encryption.common.FilterThreadExecutor;
import io.kroxylicious.filter.encryption.config.HeaderRecordEncryptionConfig;
import io.kroxylicious.proxy.filter.FilterFactory;
import io.kroxylicious.proxy.filter.FilterFactoryContext;
import io.kroxylicious.proxy.plugin.Plugin;
import io.kroxylicious.proxy.plugin.PluginConfigurationException;

import edu.umd.cs.findbugs.annotations.NonNull;

/**
 * A {@link FilterFactory} for a record encryption filter which selects the KEK of each produced record
 * from a record header, instead of from the topic name as {@link RecordEncryption} does.
 * Only the record value is encrypted; the headers, including the KEK header, stay in plaintext.
 * On fetch, a record whose KEK the KMS no longer knows is delivered as shredded instead of failing the fetch.
 * The KMS, its caches, the DEK manager and the experimental options are the same as for {@link RecordEncryption}.
 * @param <K> The key reference
 * @param <E> The type of encrypted DEK
 */
@Plugin(configType = HeaderRecordEncryptionConfig.class)
public class HeaderRecordEncryption<K, E> implements FilterFactory<HeaderRecordEncryptionConfig, SharedEncryptionContext<K, E, HeaderRecordEncryptionConfig>> {

    private static final Logger LOGGER = LoggerFactory.getLogger(HeaderRecordEncryption.class);

    /**
     * Creates a new factory instance, invoked by the plugin framework.
     */
    public HeaderRecordEncryption() {
        // nothing to initialise: state is created in initialize(FilterFactoryContext, HeaderRecordEncryptionConfig)
    }

    @Override
    @SuppressWarnings("java:S2638") // Tightening UnknownNullness
    public SharedEncryptionContext<K, E, HeaderRecordEncryptionConfig> initialize(FilterFactoryContext context,
                                                                                  @NonNull HeaderRecordEncryptionConfig configuration)
            throws PluginConfigurationException {
        Objects.requireNonNull(configuration, "configuration must not be null");
        Duration decryptedDekLifetime = configuration.kmsCache().decryptedDekExpireAfterWriteDuration();
        LOGGER.atInfo()
                .addKeyValue("decryptedDekExpireAfterWriteSeconds", decryptedDekLifetime.toSeconds())
                .addKeyValue("defaulted", !configuration.experimental().containsKey(HeaderRecordEncryptionConfig.DECRYPTED_DEK_EXPIRE_AFTER_WRITE_SECONDS))
                .log("Decrypted DEK lifetime: records of a deleted KEK stay readable through this proxy for at most decryptedDekExpireAfterWriteSeconds");
        return RecordEncryption.initializeSharedContext(context, configuration);
    }

    @NonNull
    @Override
    @SuppressWarnings("java:S2638") // Tightening UnknownNullness
    public RecordEncryptionFilter<K> createFilter(FilterFactoryContext context,
                                                  @NonNull SharedEncryptionContext<K, E, HeaderRecordEncryptionConfig> sharedEncryptionContext) {
        Objects.requireNonNull(sharedEncryptionContext, "sharedEncryptionContext must not be null");
        FilterThreadExecutor executor = new FilterThreadExecutor(context.filterDispatchExecutor());
        var encryptionManager = RecordEncryption.createEncryptionManager(sharedEncryptionContext, executor);
        var decryptionManager = RecordEncryption.createDecryptionManager(sharedEncryptionContext, executor, true);
        HeaderRecordEncryptionConfig configuration = sharedEncryptionContext.configuration();
        return new HeaderRecordEncryptionFilter<>(encryptionManager,
                decryptionManager,
                sharedEncryptionContext.kms(),
                new HeaderKekResolver(configuration.selectorConfig()),
                configuration.selectorConfig().missingHeader(),
                executor,
                configuration.unresolvedKeyPolicy());
    }

    @Override
    @SuppressWarnings("java:S2638") // Tightening UnknownNullness
    public void close(@NonNull SharedEncryptionContext<K, E, HeaderRecordEncryptionConfig> initializationData) {
        initializationData.kmsServiceCloser().run();
    }
}

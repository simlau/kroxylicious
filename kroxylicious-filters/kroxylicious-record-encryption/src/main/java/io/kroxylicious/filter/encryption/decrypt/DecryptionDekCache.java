/*
 * Copyright Kroxylicious Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */

package io.kroxylicious.filter.encryption.decrypt;

import java.time.Duration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.Executor;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.github.benmanes.caffeine.cache.AsyncLoadingCache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.RemovalCause;
import com.github.benmanes.caffeine.cache.Ticker;

import io.kroxylicious.filter.encryption.common.FilterThreadExecutor;
import io.kroxylicious.filter.encryption.dek.CipherManager;
import io.kroxylicious.filter.encryption.dek.Dek;
import io.kroxylicious.filter.encryption.dek.DekManager;
import io.kroxylicious.kms.service.KmsException;
import io.kroxylicious.kms.service.UnknownKeyException;
import io.kroxylicious.proxy.tag.VisibleForTesting;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;

/**
 * A cache of DEKs used on the decryption path.
 * @param <K> The type of KEK id.
 * @param <E> The type of encrypted DEK.
 */
public class DecryptionDekCache<K, E> {

    private static final Logger LOGGER = LoggerFactory.getLogger(DecryptionDekCache.class);

    /** The value to pass as {@code dekCacheMaxItems} for a cache with no maximum size. */
    public static final int NO_MAX_CACHE_SIZE = -1;
    private final DekManager<K, E> dekManager;

    /**
     * The key to the cache.
     * Either both, or neither, of {@code cipherManager} and {@code edek} must be null.
     * @param <E> The type of encrypted DEK.
     * @param cipherManager The cipher manager, or null if the record was not encrypted.
     * @param edek The encrypted DEK, or null if the record was not encrypted.
     */
    public record CacheKey<E>(
                              @Nullable CipherManager cipherManager,
                              @Nullable E edek) {
        /**
         * Creates a cache key.
         * @throws IllegalArgumentException if exactly one of the components is null.
         */
        public CacheKey {
            if (cipherManager == null ^ edek == null) {
                throw new IllegalArgumentException();
            }
        }

        /** A sentinel for records which are not encrypted */
        @SuppressWarnings({ "rawtypes", "unchecked" })
        private static final CacheKey UNENCRYPTED = new CacheKey(null, null);

        /** Gets the sentinel value for records which are not encrypted */
        @SuppressWarnings("unchecked")
        static <E> CacheKey<E> unencrypted() {
            return UNENCRYPTED;
        }

        /**
         * Tests whether this cache key is the sentinel value representing unencrypted records
         * @return true if this cache key represents unencrypted records.
         */
        public boolean isUnencrypted() {
            return cipherManager == null || edek == null;
        }
    }

    private final AsyncLoadingCache<CacheKey<E>, Dek<E>> decryptorCache;

    /**
     * Creates a decryption DEK cache.
     * @param dekManager the DEK manager used to decrypt encrypted DEKs on a cache miss.
     * @param dekCacheExecutor the executor used to load cache entries, or null to use the cache's default executor.
     * @param dekCacheMaxItems the maximum number of DEKs to cache, or {@link #NO_MAX_CACHE_SIZE} for no maximum.
     */
    public DecryptionDekCache(@NonNull DekManager<K, E> dekManager,
                              @Nullable Executor dekCacheExecutor,
                              int dekCacheMaxItems) {
        this(dekManager, dekCacheExecutor, dekCacheMaxItems, null);
    }

    /**
     * Creates a decryption DEK cache whose entries may have a maximum lifetime.
     * @param dekManager the DEK manager used to decrypt encrypted DEKs on a cache miss.
     * @param dekCacheExecutor the executor used to load cache entries, or null to use the cache's default executor.
     * @param dekCacheMaxItems the maximum number of DEKs to cache, or {@link #NO_MAX_CACHE_SIZE} for no maximum.
     * @param expireAfterWrite how long after being loaded a DEK is removed from the cache, however often it is read,
     * or null for no maximum lifetime.
     */
    public DecryptionDekCache(@NonNull DekManager<K, E> dekManager,
                              @Nullable Executor dekCacheExecutor,
                              int dekCacheMaxItems,
                              @Nullable Duration expireAfterWrite) {
        this(dekManager, dekCacheExecutor, dekCacheMaxItems, expireAfterWrite, Ticker.systemTicker());
    }

    /**
     * Creates a decryption DEK cache whose entries may have a maximum lifetime.
     * @param dekManager the DEK manager used to decrypt encrypted DEKs on a cache miss.
     * @param dekCacheExecutor the executor used to load cache entries, or null to use the cache's default executor.
     * @param dekCacheMaxItems the maximum number of DEKs to cache, or {@link #NO_MAX_CACHE_SIZE} for no maximum.
     * @param expireAfterWrite how long after being loaded a DEK is removed from the cache, however often it is read,
     * or null for no maximum lifetime.
     * @param ticker the time source of the cache.
     */
    @VisibleForTesting
    DecryptionDekCache(@NonNull DekManager<K, E> dekManager,
                       @Nullable Executor dekCacheExecutor,
                       int dekCacheMaxItems,
                       @Nullable Duration expireAfterWrite,
                       @NonNull Ticker ticker) {
        this.dekManager = Objects.requireNonNull(dekManager);
        Caffeine<Object, Object> cache = Caffeine.newBuilder();
        if (dekCacheMaxItems != NO_MAX_CACHE_SIZE) {
            cache.maximumSize(dekCacheMaxItems);
        }
        if (dekCacheExecutor != null) {
            cache.executor(dekCacheExecutor);
        }
        if (expireAfterWrite != null) {
            cache.expireAfterWrite(expireAfterWrite);
        }
        this.decryptorCache = cache
                .ticker(Objects.requireNonNull(ticker))
                .removalListener(this::afterCacheEviction)
                .buildAsync(this::loadDek);
    }

    /**
     * Invoked by Caffeine when a DEK needs to be loaded.
     * This method is executed on the {@code dekCacheExecutor} passed to the constructor.
     * @param cacheKey The cache key
     * @param executor The executor
     * @return A future
     */
    private CompletableFuture<Dek<E>> loadDek(CacheKey<E> cacheKey, Executor executor) {
        if (cacheKey == null || cacheKey.isUnencrypted()) {
            return CompletableFuture.completedFuture(null);
        }
        // This assert is just to appease sonar because it doesn't grok that these things cannot be null due to
        // the cacheKey.isNone() check above
        assert cacheKey.edek() != null && cacheKey.cipherManager() != null;
        return dekManager.decryptEdek(cacheKey.edek(), cacheKey.cipherManager())
                .toCompletableFuture();
    }

    /**
     * Invoked by Caffeine after a DEK is evicted from the cache.
     * This method is executed on the {@code dekCacheExecutor} passed to the constructor.
     */
    private void afterCacheEviction(@Nullable CacheKey<E> cacheKey,
                                    @Nullable Dek<E> dek,
                                    RemovalCause removalCause) {
        if (dek != null) {
            dek.destroyForDecrypt();
            LOGGER.atTrace()
                    .addKeyValue("dek", dek)
                    .log("Attempted to destroy DEK");
        }
    }

    /**
     * Gets the DEKs for all the given cache keys
     * @param cacheKeys The cache key
     * @param filterThreadExecutor The filter thread executor
     * @return A completion stage which completes on the filter thread with the DEKs for the given {@code cacheKeys}.
     */
    public @NonNull CompletionStage<Map<CacheKey<E>, Dek<E>>> getAll(@NonNull List<CacheKey<E>> cacheKeys,
                                                                     @NonNull FilterThreadExecutor filterThreadExecutor) {
        return filterThreadExecutor.completingOnFilterThread(decryptorCache.getAll(cacheKeys));
    }

    /**
     * Gets the DEKs for all the given cache keys, loading each distinct key separately so that a key whose KEK
     * the KMS reports as unknown does not fail the others.
     * A failed load is not cached, as with {@link #getAll(List, FilterThreadExecutor)}.
     * @param cacheKeys The cache keys
     * @param filterThreadExecutor The filter thread executor
     * @return A completion stage which completes on the filter thread with a map holding, for each encrypted cache key,
     * the DEK, or an empty optional if the KMS failed the load with {@link UnknownKeyException}.
     * Cache keys of unencrypted records are absent from the map.
     * The stage fails if any load fails with any other exception, or completes without a DEK: only an unknown key
     * yields an empty optional, because consumers act on a shredded record by deleting data.
     */
    public @NonNull CompletionStage<Map<CacheKey<E>, Optional<Dek<E>>>> getAllAllowingUnknownKeys(@NonNull List<CacheKey<E>> cacheKeys,
                                                                                                  @NonNull FilterThreadExecutor filterThreadExecutor) {
        Map<CacheKey<E>, CompletableFuture<Optional<Dek<E>>>> loads = new HashMap<>();
        for (CacheKey<E> cacheKey : cacheKeys) {
            if (!cacheKey.isUnencrypted()) {
                loads.computeIfAbsent(cacheKey, k -> decryptorCache.get(k).handle(DecryptionDekCache::dekOrEmptyIfUnknownKey));
            }
        }
        CompletableFuture<Map<CacheKey<E>, Optional<Dek<E>>>> all = CompletableFuture.allOf(loads.values().toArray(CompletableFuture[]::new))
                .thenApply(ignored -> {
                    Map<CacheKey<E>, Optional<Dek<E>>> result = HashMap.newHashMap(loads.size());
                    loads.forEach((cacheKey, load) -> result.put(cacheKey, load.join()));
                    return result;
                });
        return filterThreadExecutor.completingOnFilterThread(all);
    }

    private static <E> Optional<Dek<E>> dekOrEmptyIfUnknownKey(@Nullable Dek<E> dek, @Nullable Throwable throwable) {
        if (throwable == null) {
            if (dek == null) {
                throw new CompletionException(new KmsException("loading the DEK of an encrypted record returned no DEK"));
            }
            return Optional.of(dek);
        }
        Throwable cause = throwable instanceof CompletionException && throwable.getCause() != null ? throwable.getCause() : throwable;
        if (cause instanceof UnknownKeyException) {
            return Optional.empty();
        }
        throw throwable instanceof CompletionException completionException ? completionException : new CompletionException(throwable);
    }
}

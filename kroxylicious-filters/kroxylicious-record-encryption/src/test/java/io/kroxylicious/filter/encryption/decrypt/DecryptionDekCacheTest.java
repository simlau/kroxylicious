/*
 * Copyright Kroxylicious Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */

package io.kroxylicious.filter.encryption.decrypt;

import java.time.Duration;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;
import java.util.concurrent.atomic.AtomicLong;

import org.junit.jupiter.api.Test;

import com.github.benmanes.caffeine.cache.Ticker;

import io.kroxylicious.filter.encryption.common.FilterThreadExecutor;
import io.kroxylicious.filter.encryption.config.CipherSpec;
import io.kroxylicious.filter.encryption.dek.CipherSpecResolver;
import io.kroxylicious.filter.encryption.dek.DekManager;
import io.kroxylicious.kms.provider.kroxylicious.inmemory.InMemoryEdek;
import io.kroxylicious.kms.provider.kroxylicious.inmemory.InMemoryKms;
import io.kroxylicious.kms.provider.kroxylicious.inmemory.UnitTestingKmsService;
import io.kroxylicious.kms.service.KmsException;

import edu.umd.cs.findbugs.annotations.Nullable;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

class DecryptionDekCacheTest {

    private static final Executor DIRECT_EXECUTOR = Runnable::run;
    private static final FilterThreadExecutor FILTER_THREAD_EXECUTOR = new FilterThreadExecutor(DIRECT_EXECUTOR);

    private final AtomicLong nanos = new AtomicLong();
    private final Ticker ticker = nanos::get;

    @Test
    void expireAfterWriteBoundsConstantlyReadDek() {
        // Given
        InMemoryKms kms = spy(getInMemoryKms());
        var cacheKey = cacheKey(kms);
        var cache = createCache(kms, Duration.ofSeconds(2));
        readEvery500MillisUntil(cache, cacheKey, Duration.ofMillis(1500));

        // When
        nanos.set(Duration.ofSeconds(2).toNanos());
        var deks = cache.getAll(List.of(cacheKey), FILTER_THREAD_EXECUTOR);

        // Then
        assertThat(deks).succeedsWithin(Duration.ZERO);
        verify(kms, times(2)).decryptEdek(any());
    }

    @Test
    void withoutExpireAfterWriteConstantlyReadDekIsNotReloaded() {
        // Given
        InMemoryKms kms = spy(getInMemoryKms());
        var cacheKey = cacheKey(kms);
        var cache = createCache(kms, null);
        readEvery500MillisUntil(cache, cacheKey, Duration.ofMillis(1500));

        // When
        nanos.set(Duration.ofSeconds(2).toNanos());
        var deks = cache.getAll(List.of(cacheKey), FILTER_THREAD_EXECUTOR);

        // Then
        assertThat(deks).succeedsWithin(Duration.ZERO);
        verify(kms, times(1)).decryptEdek(any());
    }

    @Test
    @SuppressWarnings("unchecked")
    void loadWithoutDekFailsInsteadOfShredding() {
        // Given
        DekManager<UUID, InMemoryEdek> dekManager = mock(DekManager.class);
        doReturn(CompletableFuture.completedFuture(null)).when(dekManager).decryptEdek(any(), any());
        var cache = new DecryptionDekCache<>(dekManager, DIRECT_EXECUTOR, DecryptionDekCache.NO_MAX_CACHE_SIZE, null, ticker);
        var cacheKey = cacheKey(getInMemoryKms());

        // When
        var deks = cache.getAllAllowingUnknownKeys(List.of(cacheKey), FILTER_THREAD_EXECUTOR);

        // Then
        assertThat(deks).failsWithin(Duration.ZERO)
                .withThrowableThat()
                .havingRootCause()
                .isInstanceOf(KmsException.class)
                .withMessageContaining("returned no DEK");
    }

    @Test
    void unknownKeyIsShredded() {
        // Given
        InMemoryKms kms = getInMemoryKms();
        var cacheKey = cacheKey(kms);
        var cache = createCache(kms, null);
        kms.deleteKey(cacheKey.edek().kekRef());

        // When
        var deks = cache.getAllAllowingUnknownKeys(List.of(cacheKey), FILTER_THREAD_EXECUTOR);

        // Then
        assertThat(deks).succeedsWithin(Duration.ZERO).satisfies(map -> assertThat(map).containsEntry(cacheKey, Optional.empty()));
    }

    private void readEvery500MillisUntil(DecryptionDekCache<UUID, InMemoryEdek> cache, DecryptionDekCache.CacheKey<InMemoryEdek> cacheKey, Duration until) {
        for (long millis = 0; millis <= until.toMillis(); millis += 500) {
            nanos.set(Duration.ofMillis(millis).toNanos());
            cache.getAll(List.of(cacheKey), FILTER_THREAD_EXECUTOR);
        }
    }

    private DecryptionDekCache<UUID, InMemoryEdek> createCache(InMemoryKms kms, @Nullable Duration expireAfterWrite) {
        return new DecryptionDekCache<>(new DekManager<>(kms, 1), DIRECT_EXECUTOR, DecryptionDekCache.NO_MAX_CACHE_SIZE, expireAfterWrite, ticker);
    }

    private static DecryptionDekCache.CacheKey<InMemoryEdek> cacheKey(InMemoryKms kms) {
        var edek = kms.generateDekPair(kms.generateKey()).join().edek();
        return new DecryptionDekCache.CacheKey<>(CipherSpecResolver.ALL.fromName(CipherSpec.AES_256_GCM_128), edek);
    }

    private static InMemoryKms getInMemoryKms() {
        var kmsService = UnitTestingKmsService.newInstance();
        kmsService.initialize(new UnitTestingKmsService.Config());
        return kmsService.buildKms();
    }
}

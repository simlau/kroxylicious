/*
 * Copyright Kroxylicious Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */

package io.kroxylicious.it.filter.encryption;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import org.testcontainers.DockerClientFactory;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.utility.DockerImageName;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import edu.umd.cs.findbugs.annotations.Nullable;

/**
 * An OpenBao dev server in a container, set up like a Levior app namespace: namespace {@link #NAMESPACE} with
 * a transit engine at {@link #TRANSIT_PATH}, policy {@code proxy} (the proxy policy of {@code levior/openbao}
 * {@code tofu/modules/transit-app}) and a token with only that policy, which the proxy uses.
 * Keys are created and deleted with the root token, as the key owner would.
 */
final class OpenBaoTestServer implements AutoCloseable {

    static final String NAMESPACE = "simlau-playground";
    static final String TRANSIT_PATH = "transit";
    static final String KEY_PREFIX = "user-kek-";

    private static final String IMAGE = "quay.io/openbao/openbao:2.7.1@sha256:6d2b93856e3fcf7b18ad855a0b51eaba474dc8b79cf554379ea32034797d2acf";
    private static final String ROOT_TOKEN = "root";
    private static final int PORT = 8200;
    private static final String PROXY_POLICY_NAME = "proxy";
    // as in levior/openbao tofu/modules/transit-app/main.tf (local.proxy_paths), with key_prefix "user-kek-"
    private static final Map<String, String> PROXY_POLICY_PATHS = Map.of(
            TRANSIT_PATH + "/keys/" + KEY_PREFIX + "*", "read",
            TRANSIT_PATH + "/datakey/plaintext/" + KEY_PREFIX + "*", "update",
            TRANSIT_PATH + "/decrypt/" + KEY_PREFIX + "*", "update");
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final GenericContainer<?> container;
    private final HttpClient httpClient = HttpClient.newHttpClient();
    private @Nullable String proxyToken;

    private OpenBaoTestServer() {
        DockerImageName image = DockerImageName.parse(IMAGE);
        container = new GenericContainer<>(image)
                .withCommand("server", "-dev", "-dev-listen-address=0.0.0.0:" + PORT)
                .withEnv("BAO_DEV_ROOT_TOKEN_ID", ROOT_TOKEN)
                .withEnv("SKIP_SETCAP", "true")
                .withExposedPorts(PORT)
                .waitingFor(Wait.forHttp("/v1/sys/health").forPort(PORT).forStatusCode(200));
    }

    /**
     * Returns whether Docker is available to run the server.
     * @return whether Docker is available.
     */
    static boolean isAvailable() {
        return DockerClientFactory.instance().isDockerAvailable();
    }

    /**
     * Starts a server and sets up the namespace, the transit engine, the proxy policy and the proxy's token.
     * @return the started server.
     */
    @SuppressWarnings("resource")
    static OpenBaoTestServer start() {
        var server = new OpenBaoTestServer();
        server.container.start();
        try {
            server.setUp();
        }
        catch (RuntimeException e) {
            server.close();
            throw e;
        }
        return server;
    }

    private void setUp() {
        send("POST", "sys/namespaces/" + NAMESPACE, Map.of(), null);
        send("POST", "sys/mounts/" + TRANSIT_PATH, Map.of("type", "transit"), NAMESPACE);
        StringBuilder policy = new StringBuilder();
        PROXY_POLICY_PATHS.forEach((path, capability) -> policy.append("path \"").append(path).append("\" {\n")
                .append("  capabilities = [\"").append(capability).append("\"]\n")
                .append("}\n"));
        send("PUT", "sys/policies/acl/" + PROXY_POLICY_NAME, Map.of("policy", policy.toString()), NAMESPACE);
        JsonNode token = send("POST", "auth/token/create",
                Map.of("policies", List.of(PROXY_POLICY_NAME), "no_default_policy", true, "display_name", "kroxylicious-proxy"), NAMESPACE);
        proxyToken = Objects.requireNonNull(token).path("auth").path("client_token").asText();
    }

    /**
     * Returns the {@code kmsConfig} of {@code VaultKmsService} for the proxy: namespace, transit path and the proxy's token.
     * @return the KMS config.
     */
    Map<String, Object> kmsConfig() {
        return Map.of("vaultUrl", url().toString(),
                "vaultNamespace", NAMESPACE,
                "transitEnginePath", TRANSIT_PATH,
                "credentials", Map.of("vaultToken", Map.of("token", Map.of("password", Objects.requireNonNull(proxyToken)))));
    }

    /**
     * Creates a key that can be deleted, using the root token.
     * @param name the key name.
     */
    void createKey(String name) {
        send("POST", "%s/keys/%s".formatted(TRANSIT_PATH, name), Map.of(), NAMESPACE);
        send("POST", "%s/keys/%s/config".formatted(TRANSIT_PATH, name), Map.of("deletion_allowed", true), NAMESPACE);
    }

    /**
     * Deletes a key, using the root token. The key must have been created by {@link #createKey(String)}.
     * @param name the key name.
     */
    void deleteKey(String name) {
        send("DELETE", "%s/keys/%s".formatted(TRANSIT_PATH, name), null, NAMESPACE);
    }

    /**
     * Stops the server. The proxy's requests to it then fail to connect.
     */
    void stop() {
        container.stop();
    }

    @Override
    public void close() {
        container.close();
    }

    private URI url() {
        return URI.create("http://%s:%d/".formatted(container.getHost(), container.getMappedPort(PORT)));
    }

    @Nullable
    private JsonNode send(String method, String path, @Nullable Object body, @Nullable String namespace) {
        var builder = HttpRequest.newBuilder(url().resolve("v1/" + path))
                .header("X-Vault-Token", ROOT_TOKEN)
                .method(method, body == null ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofString(toJson(body)));
        if (namespace != null) {
            builder.header("X-Vault-Namespace", namespace);
        }
        try {
            HttpResponse<String> response = httpClient.send(builder.build(), HttpResponse.BodyHandlers.ofString());
            if (!Set.of(200, 204).contains(response.statusCode())) {
                throw new IllegalStateException("OpenBao answered %s %s with %d: %s".formatted(method, path, response.statusCode(), response.body()));
            }
            return response.body().isEmpty() ? null : MAPPER.readTree(response.body());
        }
        catch (IOException e) {
            throw new UncheckedIOException("OpenBao request %s %s failed".formatted(method, path), e);
        }
        catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("Interrupted during OpenBao request %s %s".formatted(method, path), e);
        }
    }

    private static String toJson(Object body) {
        try {
            return MAPPER.writeValueAsString(body);
        }
        catch (JsonProcessingException e) {
            throw new UncheckedIOException(e);
        }
    }
}

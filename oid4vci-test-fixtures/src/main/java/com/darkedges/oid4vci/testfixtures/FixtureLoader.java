package com.darkedges.oid4vci.testfixtures;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.yaml.snakeyaml.Yaml;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.util.Map;

/**
 * Loads fixtures from the classpath: hand-transcribed OID4VCI spec examples under
 * {@code src/main/resources-spec-transcribed} in this module (the OID4VCI spec repository has no bulk
 * {@code examples/} directory the way OpenID4VP's does, so there's nothing to vendor wholesale the way
 * {@code oid4vp-test-fixtures} vendors {@code docs/1.1/examples}).
 */
public final class FixtureLoader {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private FixtureLoader() {}

    public static String readString(String classpathResource) {
        try (InputStream in = requireStream(classpathResource)) {
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new UncheckedIOException("failed to read fixture: " + classpathResource, e);
        }
    }

    public static JsonNode readJson(String classpathResource) {
        try (InputStream in = requireStream(classpathResource)) {
            return MAPPER.readTree(in);
        } catch (IOException e) {
            throw new UncheckedIOException("failed to parse JSON fixture: " + classpathResource, e);
        }
    }

    @SuppressWarnings("unchecked")
    public static Map<String, Object> readYaml(String classpathResource) {
        try (InputStream in = requireStream(classpathResource)) {
            return (Map<String, Object>) new Yaml().load(in);
        } catch (IOException e) {
            throw new UncheckedIOException("failed to read YAML fixture: " + classpathResource, e);
        }
    }

    private static InputStream requireStream(String classpathResource) {
        InputStream in = FixtureLoader.class.getClassLoader().getResourceAsStream(classpathResource);
        if (in == null) {
            throw new IllegalArgumentException("fixture not found on classpath: " + classpathResource);
        }
        return in;
    }
}

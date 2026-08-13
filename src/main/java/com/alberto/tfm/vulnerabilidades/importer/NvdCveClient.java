package com.alberto.tfm.vulnerabilidades.importer;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

/**
 * Cliente mínimo para la API pública de NVD (services.nvd.nist.gov), usando
 * solo el HttpClient del JDK para no añadir dependencias nuevas.
 */
final class NvdCveClient {

    private static final Logger log = LoggerFactory.getLogger(NvdCveClient.class);
    private static final String BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0";
    private static final int RESULTS_PER_PAGE = 2000;
    // 50 peticiones/30s con key (1 cada 0.6s); dejamos margen de sobra.
    private static final long MIN_DELAY_MS = 1000L;
    private static final int MAX_TRANSIENT_RETRIES = 4;
    private static final long RETRY_BACKOFF_MS = 10_000L;

    private final HttpClient httpClient = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(20))
            .build();
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final String apiKey;

    NvdCveClient(String apiKey) {
        this.apiKey = apiKey;
    }

    /** Barrido completo, sin filtrar por CWE. */
    JsonNode fetchPage(int startIndex) throws IOException, InterruptedException {
        return fetchPage(null, startIndex);
    }

    JsonNode fetchPage(String cweId, int startIndex) throws IOException, InterruptedException {
        return fetchPage(cweId, null, null, startIndex, 0);
    }

    /**
     * Barrido acotado por fecha de publicación (ambos extremos obligatorios
     * según la API de NVD, formato ISO-8601 con milisegundos, p.ej.
     * "2026-07-01T00:00:00.000"). El rango máximo permitido por NVD es de
     * 120 días; el llamante es responsable de trocear rangos más amplios.
     */
    JsonNode fetchPageByPublishedDate(String pubStartDate, String pubEndDate, int startIndex)
            throws IOException, InterruptedException {
        return fetchPage(null, pubStartDate, pubEndDate, startIndex, 0);
    }

    private JsonNode fetchPage(String cweId, String pubStartDate, String pubEndDate, int startIndex, int attempt)
            throws IOException, InterruptedException {
        String url = BASE_URL + "?resultsPerPage=" + RESULTS_PER_PAGE
                + "&startIndex=" + startIndex
                + (cweId != null ? "&cweId=" + cweId : "")
                + (pubStartDate != null ? "&pubStartDate=" + pubStartDate : "")
                + (pubEndDate != null ? "&pubEndDate=" + pubEndDate : "");

        HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .timeout(Duration.ofSeconds(30))
                .GET();
        if (apiKey != null && !apiKey.isBlank()) {
            requestBuilder.header("apiKey", apiKey);
        }

        Thread.sleep(MIN_DELAY_MS);

        HttpResponse<String> response;
        try {
            response = httpClient.send(requestBuilder.build(), HttpResponse.BodyHandlers.ofString());
        } catch (IOException e) {
            // Fallo transitorio de red (timeout, conexión reiniciada...): reintentar con backoff
            // antes de rendirse, en vez de abortar toda la importación por un único fallo puntual.
            if (attempt >= MAX_TRANSIENT_RETRIES) {
                throw e;
            }
            log.warn("Fallo de red en startIndex={} (intento {}/{}), reintentando en {}s: {}",
                    startIndex, attempt + 1, MAX_TRANSIENT_RETRIES, RETRY_BACKOFF_MS / 1000, e.toString());
            Thread.sleep(RETRY_BACKOFF_MS);
            return fetchPage(cweId, pubStartDate, pubEndDate, startIndex, attempt + 1);
        }

        if (response.statusCode() == 429) {
            log.warn("NVD devolvió 429 (rate limit) en startIndex={}, esperando 30s antes de reintentar",
                    startIndex);
            Thread.sleep(30_000L);
            return fetchPage(cweId, pubStartDate, pubEndDate, startIndex, attempt);
        }

        if (response.statusCode() >= 500 && attempt < MAX_TRANSIENT_RETRIES) {
            log.warn("NVD devolvió {} (error de servidor) en startIndex={} (intento {}/{}), reintentando en {}s",
                    response.statusCode(), startIndex, attempt + 1, MAX_TRANSIENT_RETRIES, RETRY_BACKOFF_MS / 1000);
            Thread.sleep(RETRY_BACKOFF_MS);
            return fetchPage(cweId, pubStartDate, pubEndDate, startIndex, attempt + 1);
        }

        if (response.statusCode() != 200) {
            throw new IOException("NVD respondió " + response.statusCode()
                    + " para startIndex=" + startIndex + ": " + response.body());
        }

        return objectMapper.readTree(response.body());
    }
}

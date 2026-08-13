package com.alberto.tfm.vulnerabilidades.scheduling;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

/**
 * Mantiene despierta la instancia del plan gratuito de Render, que suspende el
 * servicio tras unos 15 minutos sin tráfico (y tarda cerca de un minuto en
 * volver a arrancar en la siguiente petición). Para evitarlo, el propio
 * servidor se llama a /health con una periodicidad algo menor a ese margen.
 *
 * En local no aporta nada, así que puede desactivarse con
 * KEEPALIVE_ENABLED=false. Usa el HttpClient del JDK, igual que NvdCveClient,
 * para no añadir dependencias.
 */
@Component
public class KeepAliveScheduler {

    private static final Logger log = LoggerFactory.getLogger(KeepAliveScheduler.class);

    private final HttpClient httpClient = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(10))
            .build();

    @Value("${app.keepalive.enabled:true}")
    private boolean enabled;

    @Value("${app.base-url:http://localhost:8080}")
    private String baseUrl;

    @Scheduled(fixedRateString = "${app.keepalive.rate-ms:840000}")
    public void ping() {
        if (!enabled) {
            return;
        }

        String url = baseUrl.replaceAll("/+$", "") + "/health";
        try {
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(url))
                    .timeout(Duration.ofSeconds(15))
                    .GET()
                    .build();

            HttpResponse<Void> response = httpClient.send(request, HttpResponse.BodyHandlers.discarding());
            log.info("KeepAlive ping {} -> {}", url, response.statusCode());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            log.warn("KeepAlive ping interrumpido: {}", e.getMessage());
        } catch (Exception e) {
            log.warn("KeepAlive ping fallido ({}): {}", url, e.getMessage());
        }
    }
}

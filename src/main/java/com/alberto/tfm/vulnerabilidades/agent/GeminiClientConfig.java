package com.alberto.tfm.vulnerabilidades.agent;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.MediaType;
import org.springframework.web.client.RestClient;

/**
 * Cliente REST de la API de Gemini, solo se crea si los agentes están activados
 * (agents.enabled=true) para no exigir una API key en despliegues que no los usen.
 */
@Configuration
@ConditionalOnProperty(name = "agents.enabled", havingValue = "true")
public class GeminiClientConfig {

    @Bean
    public RestClient geminiClient(@Value("${gemini.api.key}") String apiKey) {
        if (apiKey == null || apiKey.isBlank()) {
            throw new IllegalStateException(
                    "agents.enabled=true pero no se ha definido la variable de entorno GEMINI_API_KEY");
        }
        return RestClient.builder()
                .baseUrl("https://generativelanguage.googleapis.com/v1beta")
                .defaultHeader("x-goog-api-key", apiKey)
                .defaultHeader("Content-Type", MediaType.APPLICATION_JSON_VALUE)
                .build();
    }
}

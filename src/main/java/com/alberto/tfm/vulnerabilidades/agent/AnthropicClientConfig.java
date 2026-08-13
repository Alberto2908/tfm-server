package com.alberto.tfm.vulnerabilidades.agent;

import com.anthropic.client.AnthropicClient;
import com.anthropic.client.okhttp.AnthropicOkHttpClient;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Cliente de la API de Anthropic, solo se crea si los agentes están activados
 * (agents.enabled=true) para no exigir una API key en despliegues que no los usen.
 */
@Configuration
@ConditionalOnProperty(name = "agents.enabled", havingValue = "true")
public class AnthropicClientConfig {

    @Bean
    public AnthropicClient anthropicClient(@Value("${anthropic.api.key}") String apiKey) {
        if (apiKey == null || apiKey.isBlank()) {
            throw new IllegalStateException(
                    "agents.enabled=true pero no se ha definido la variable de entorno ANTHROPIC_API_KEY");
        }
        return AnthropicOkHttpClient.builder()
                .apiKey(apiKey)
                .build();
    }
}

package com.alberto.tfm.vulnerabilidades.agent;

import com.anthropic.core.JsonValue;
import com.anthropic.models.messages.JsonOutputFormat;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Esquemas JSON (output_config.format) usados para forzar la salida estructurada
 * de los dos agentes. Los valores de severity/category deben coincidir exactamente
 * con las opciones del formulario "anadir" en tfm-web.
 */
final class AnthropicSchemas {

    static final List<String> SEVERITIES = List.of("Crítica", "Alta", "Media", "Baja", "Informativa");
    static final List<String> CATEGORIES = List.of(
            "Injection", "XSS", "CSRF", "Authentication", "Authorization", "Data Exposure", "DoS", "Other");

    private AnthropicSchemas() {
    }

    static JsonOutputFormat.Schema discoveryDraftSchema() {
        return buildSchema(draftProperties(), draftRequired());
    }

    /** Igual que discoveryDraftSchema, pero envuelto en un array "vulnerabilities" para permitir extraer varias de un mismo documento. */
    static JsonOutputFormat.Schema documentIngestSchema() {
        Map<String, Object> itemSchema = new LinkedHashMap<>();
        itemSchema.put("type", "object");
        itemSchema.put("properties", draftProperties());
        itemSchema.put("required", draftRequired());
        itemSchema.put("additionalProperties", false);

        Map<String, Object> vulnerabilitiesArray = new LinkedHashMap<>();
        vulnerabilitiesArray.put("type", "array");
        vulnerabilitiesArray.put("items", itemSchema);

        Map<String, Object> properties = new LinkedHashMap<>();
        properties.put("vulnerabilities", vulnerabilitiesArray);

        return buildSchema(properties, List.of("vulnerabilities"));
    }

    private static Map<String, Object> draftProperties() {
        Map<String, Object> properties = new LinkedHashMap<>();
        properties.put("name", stringProperty());
        properties.put("description", stringProperty());
        properties.put("severity", enumProperty(SEVERITIES));
        properties.put("category", enumProperty(CATEGORIES));
        properties.put("framework", stringProperty());
        properties.put("affectedEndpoint", stringProperty());
        properties.put("payloadExample", stringProperty());
        properties.put("impact", stringProperty());
        properties.put("mitigation", stringProperty());
        properties.put("referenceURL", stringProperty());
        return properties;
    }

    private static List<String> draftRequired() {
        return List.of(
                "name", "description", "severity", "category", "framework",
                "affectedEndpoint", "impact", "mitigation");
    }

    static JsonOutputFormat.Schema verificationResultSchema() {
        Map<String, Object> properties = new LinkedHashMap<>();
        properties.put("technicallyValid", booleanProperty());
        properties.put("duplicate", booleanProperty());
        properties.put("reasoning", stringProperty());

        List<String> required = List.of("technicallyValid", "duplicate", "reasoning");

        return buildSchema(properties, required);
    }

    private static JsonOutputFormat.Schema buildSchema(Map<String, Object> properties, List<String> required) {
        return JsonOutputFormat.Schema.builder()
                .putAdditionalProperty("type", JsonValue.from("object"))
                .putAdditionalProperty("properties", JsonValue.from(properties))
                .putAdditionalProperty("required", JsonValue.from(required))
                .putAdditionalProperty("additionalProperties", JsonValue.from(false))
                .build();
    }

    private static Map<String, Object> stringProperty() {
        Map<String, Object> property = new LinkedHashMap<>();
        property.put("type", "string");
        return property;
    }

    private static Map<String, Object> booleanProperty() {
        Map<String, Object> property = new LinkedHashMap<>();
        property.put("type", "boolean");
        return property;
    }

    private static Map<String, Object> enumProperty(List<String> values) {
        Map<String, Object> property = new LinkedHashMap<>();
        property.put("type", "string");
        property.put("enum", values);
        return property;
    }
}

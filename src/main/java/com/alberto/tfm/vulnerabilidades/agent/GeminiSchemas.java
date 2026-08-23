package com.alberto.tfm.vulnerabilidades.agent;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Esquemas (generationConfig.responseSchema) usados para forzar la salida
 * estructurada de los agentes. Gemini usa un subconjunto de OpenAPI 3.0: los
 * tipos van en mayúsculas y no admite "additionalProperties". Los valores de
 * severity/category deben coincidir exactamente con las opciones del
 * formulario "anadir" en tfm-web.
 */
final class GeminiSchemas {

    static final List<String> SEVERITIES = List.of("Crítica", "Alta", "Media", "Baja", "Informativa");
    static final List<String> CATEGORIES = List.of(
            "Injection", "XSS", "CSRF", "Authentication", "Authorization", "Data Exposure", "DoS", "Other");

    private GeminiSchemas() {
    }

    static Map<String, Object> discoveryDraftSchema() {
        return buildSchema(draftProperties(), draftRequired());
    }

    /** Igual que discoveryDraftSchema, pero envuelto en un array "vulnerabilities" para permitir extraer varias de un mismo documento. */
    static Map<String, Object> documentIngestSchema() {
        Map<String, Object> itemSchema = new LinkedHashMap<>();
        itemSchema.put("type", "OBJECT");
        itemSchema.put("properties", draftProperties());
        itemSchema.put("required", draftRequired());

        Map<String, Object> vulnerabilitiesArray = new LinkedHashMap<>();
        vulnerabilitiesArray.put("type", "ARRAY");
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

    static Map<String, Object> verificationResultSchema() {
        Map<String, Object> properties = new LinkedHashMap<>();
        properties.put("technicallyValid", booleanProperty());
        properties.put("duplicate", booleanProperty());
        properties.put("reasoning", stringProperty());

        List<String> required = List.of("technicallyValid", "duplicate", "reasoning");

        return buildSchema(properties, required);
    }

    private static Map<String, Object> buildSchema(Map<String, Object> properties, List<String> required) {
        Map<String, Object> schema = new LinkedHashMap<>();
        schema.put("type", "OBJECT");
        schema.put("properties", properties);
        schema.put("required", required);
        return schema;
    }

    private static Map<String, Object> stringProperty() {
        Map<String, Object> property = new LinkedHashMap<>();
        property.put("type", "STRING");
        return property;
    }

    private static Map<String, Object> booleanProperty() {
        Map<String, Object> property = new LinkedHashMap<>();
        property.put("type", "BOOLEAN");
        return property;
    }

    private static Map<String, Object> enumProperty(List<String> values) {
        Map<String, Object> property = new LinkedHashMap<>();
        property.put("type", "STRING");
        property.put("enum", values);
        return property;
    }
}

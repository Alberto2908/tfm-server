package com.alberto.tfm.vulnerabilidades.importer;

import com.alberto.tfm.vulnerabilidades.models.Vulnerability;
import com.fasterxml.jackson.databind.JsonNode;

import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.time.format.DateTimeParseException;
import java.util.Iterator;

/**
 * Convierte un nodo "cve" de la respuesta de NVD en una entidad Vulnerability,
 * ya marcada como verificada (es un CVE real y públicado, no una propuesta).
 *
 * El impacto y la mitigación se derivan del propio vector CVSS de cada CVE
 * (confidencialidad/integridad/disponibilidad, vector de ataque...), en vez de
 * repetir una frase genérica igual para todos los registros.
 */
final class CveMapper {

    private static final int MAX_DESCRIPTION_LENGTH = 600;

    private CveMapper() {
    }

    static Vulnerability toVulnerability(JsonNode cveNode) {
        String cveId = cveNode.path("id").asText();
        String description = englishDescription(cveNode);
        CvssSummary cvss = extractCvss(cveNode);
        String severity = cvss != null ? mapSeverity(cvss) : "Informativa";
        String category = detectCategory(cveNode);
        String framework = framework(cveNode);
        String referenceURL = referenceUrl(cveNode, cveId);
        LocalDateTime published = publishedDate(cveNode);

        Vulnerability vulnerability = new Vulnerability();
        vulnerability.setName(cveId);
        vulnerability.setDescription(description);
        vulnerability.setSeverity(severity);
        vulnerability.setCategory(category);
        vulnerability.setFramework(framework);
        vulnerability.setAffectedEndpoint("");
        vulnerability.setPayloadExample("");
        vulnerability.setImpact(buildImpact(severity, cvss));
        vulnerability.setMitigation(buildMitigation(framework, cvss));
        vulnerability.setReferenceURL(referenceURL);
        vulnerability.setCreatedBy("import:nvd");
        vulnerability.setCreatedAt(published);
        vulnerability.setVerified(true);
        vulnerability.setVerifiedBy("import:nvd");
        vulnerability.setVerifiedAt(published);
        return vulnerability;
    }

    private static String englishDescription(JsonNode cveNode) {
        for (JsonNode d : cveNode.path("descriptions")) {
            if ("en".equals(d.path("lang").asText())) {
                String value = d.path("value").asText("");
                return value.length() > MAX_DESCRIPTION_LENGTH
                        ? value.substring(0, MAX_DESCRIPTION_LENGTH) + "..."
                        : value;
            }
        }
        return "(sin descripción disponible)";
    }

    private static String detectCategory(JsonNode cveNode) {
        for (JsonNode weakness : cveNode.path("weaknesses")) {
            for (JsonNode description : weakness.path("description")) {
                String cweId = description.path("value").asText("");
                String category = CveCategoryMapping.CWE_TO_CATEGORY.get(cweId);
                if (category != null) {
                    return category;
                }
            }
        }
        return CveCategoryMapping.OTHER_CATEGORY;
    }

    // ---- CVSS: una única extracción (v3.1 -> v3.0 -> v2) reutilizada para
    // severidad, impacto y mitigación ----

    private static CvssSummary extractCvss(JsonNode cveNode) {
        JsonNode metrics = cveNode.path("metrics");

        CvssSummary v31 = extractV3(metrics.path("cvssMetricV31"));
        if (v31 != null) {
            return v31;
        }
        CvssSummary v30 = extractV3(metrics.path("cvssMetricV30"));
        if (v30 != null) {
            return v30;
        }
        return extractV2(metrics.path("cvssMetricV2"));
    }

    private static CvssSummary extractV3(JsonNode metricArray) {
        if (!metricArray.isArray() || metricArray.isEmpty()) {
            return null;
        }
        JsonNode data = metricArray.get(0).path("cvssData");
        CvssSummary cvss = new CvssSummary();
        cvss.version = 3;
        cvss.baseScore = data.path("baseScore").asDouble(-1);
        cvss.baseSeverity = data.path("baseSeverity").asText(null);
        cvss.confidentiality = translateImpactV3(data.path("confidentialityImpact").asText(null));
        cvss.integrity = translateImpactV3(data.path("integrityImpact").asText(null));
        cvss.availability = translateImpactV3(data.path("availabilityImpact").asText(null));
        cvss.attackVector = translateAttackVector(data.path("attackVector").asText(null));
        cvss.attackComplexity = translateComplexity(data.path("attackComplexity").asText(null));
        cvss.privilegesOrAuth = translatePrivileges(data.path("privilegesRequired").asText(null));
        cvss.userInteraction = translateUserInteraction(data.path("userInteraction").asText(null));
        return cvss;
    }

    private static CvssSummary extractV2(JsonNode metricArray) {
        if (!metricArray.isArray() || metricArray.isEmpty()) {
            return null;
        }
        JsonNode metric = metricArray.get(0);
        JsonNode data = metric.path("cvssData");
        CvssSummary cvss = new CvssSummary();
        cvss.version = 2;
        cvss.baseScore = data.path("baseScore").asDouble(-1);
        cvss.baseSeverity = metric.path("baseSeverity").asText(null);
        cvss.confidentiality = translateImpactV2(data.path("confidentialityImpact").asText(null));
        cvss.integrity = translateImpactV2(data.path("integrityImpact").asText(null));
        cvss.availability = translateImpactV2(data.path("availabilityImpact").asText(null));
        cvss.attackVector = translateAttackVector(data.path("accessVector").asText(null));
        cvss.attackComplexity = translateComplexity(data.path("accessComplexity").asText(null));
        cvss.privilegesOrAuth = translateAuthentication(data.path("authentication").asText(null));
        cvss.userInteraction = metric.path("userInteractionRequired").asBoolean(false) ? "Requerida" : "No requerida";
        return cvss;
    }

    private static String mapSeverity(CvssSummary cvss) {
        if (cvss.baseSeverity != null) {
            return switch (cvss.baseSeverity.toUpperCase()) {
                case "CRITICAL" -> "Crítica";
                case "HIGH" -> "Alta";
                case "MEDIUM" -> "Media";
                case "LOW" -> "Baja";
                default -> "Informativa";
            };
        }
        if (cvss.baseScore >= 7.0) {
            return "Alta";
        } else if (cvss.baseScore >= 4.0) {
            return "Media";
        } else if (cvss.baseScore > 0.0) {
            return "Baja";
        }
        return "Informativa";
    }

    private static String translateImpactV3(String value) {
        if (value == null) {
            return null;
        }
        return switch (value.toUpperCase()) {
            case "HIGH" -> "Alta";
            case "LOW" -> "Baja";
            case "NONE" -> "Ninguna";
            default -> null;
        };
    }

    private static String translateImpactV2(String value) {
        if (value == null) {
            return null;
        }
        return switch (value.toUpperCase()) {
            case "COMPLETE" -> "Completa";
            case "PARTIAL" -> "Parcial";
            case "NONE" -> "Ninguna";
            default -> null;
        };
    }

    private static String translateAttackVector(String value) {
        if (value == null) {
            return null;
        }
        return switch (value.toUpperCase()) {
            case "NETWORK" -> "Red";
            case "ADJACENT_NETWORK", "ADJACENT" -> "Red adyacente";
            case "LOCAL" -> "Local";
            case "PHYSICAL" -> "Físico";
            default -> null;
        };
    }

    private static String translateComplexity(String value) {
        if (value == null) {
            return null;
        }
        return switch (value.toUpperCase()) {
            case "LOW" -> "Baja";
            case "MEDIUM" -> "Media";
            case "HIGH" -> "Alta";
            default -> null;
        };
    }

    private static String translatePrivileges(String value) {
        if (value == null) {
            return null;
        }
        return switch (value.toUpperCase()) {
            case "NONE" -> "Ninguno";
            case "LOW" -> "Bajos";
            case "HIGH" -> "Altos";
            default -> null;
        };
    }

    private static String translateAuthentication(String value) {
        if (value == null) {
            return null;
        }
        return switch (value.toUpperCase()) {
            case "NONE" -> "No requerida";
            case "SINGLE" -> "Un factor";
            case "MULTIPLE" -> "Múltiples factores";
            default -> null;
        };
    }

    private static String translateUserInteraction(String value) {
        if (value == null) {
            return null;
        }
        return switch (value.toUpperCase()) {
            case "NONE" -> "No requerida";
            case "REQUIRED" -> "Requerida";
            default -> null;
        };
    }

    // ---- Construcción de impacto / mitigación a partir del CVSS real ----

    private static String buildImpact(String severity, CvssSummary cvss) {
        if (cvss == null) {
            return "Severidad " + severity + " (sin puntuación CVSS disponible en NVD).";
        }

        StringBuilder sb = new StringBuilder();
        sb.append("Impacto CVSS - confidencialidad: ").append(orDesconocido(cvss.confidentiality))
                .append(", integridad: ").append(orDesconocido(cvss.integrity))
                .append(", disponibilidad: ").append(orDesconocido(cvss.availability))
                .append(". Vector de ataque: ").append(orDesconocido(cvss.attackVector))
                .append(" (complejidad ").append(orDesconocido(cvss.attackComplexity).toLowerCase())
                .append(", privilegios ").append(orDesconocido(cvss.privilegesOrAuth).toLowerCase())
                .append(", interacción del usuario ").append(orDesconocido(cvss.userInteraction).toLowerCase())
                .append("). Severidad ").append(severity);
        if (cvss.baseScore >= 0) {
            sb.append(" (CVSS ").append(cvss.baseScore).append(")");
        }
        sb.append(".");
        return sb.toString();
    }

    private static String buildMitigation(String framework, CvssSummary cvss) {
        String aviso = (framework != null && !framework.isBlank())
                ? "Revisar el aviso oficial de " + framework + " (ver URL de referencia) para el parche disponible."
                : "Revisar el aviso oficial en la URL de referencia para el parche disponible.";

        if (cvss == null || cvss.attackVector == null) {
            return aviso;
        }

        String prioridad = switch (cvss.attackVector) {
            case "Red" -> "Al ser explotable remotamente por red, priorizar el parcheo y limitar la exposición perimetral.";
            case "Red adyacente" -> "Al requerir acceso a la red adyacente, revisar la segmentación de red como mitigación adicional.";
            case "Local" -> "Al requerir acceso local, priorizar el control de acceso y permisos en el sistema afectado.";
            case "Físico" -> "Al requerir acceso físico, revisar los controles de seguridad física del entorno.";
            default -> null;
        };

        return prioridad != null ? aviso + " " + prioridad : aviso;
    }

    private static String orDesconocido(String value) {
        return value != null ? value : "no especificada";
    }

    private static final class CvssSummary {
        int version;
        double baseScore = -1;
        String baseSeverity;
        String confidentiality;
        String integrity;
        String availability;
        String attackVector;
        String attackComplexity;
        String privilegesOrAuth;
        String userInteraction;
    }

    private static String framework(JsonNode cveNode) {
        Iterator<JsonNode> configs = cveNode.path("configurations").elements();
        while (configs.hasNext()) {
            JsonNode config = configs.next();
            for (JsonNode node : config.path("nodes")) {
                for (JsonNode cpeMatch : node.path("cpeMatch")) {
                    String parsed = parseCpe(cpeMatch.path("criteria").asText(null));
                    if (parsed != null) {
                        return parsed;
                    }
                }
            }
        }
        return "";
    }

    private static String parseCpe(String criteria) {
        if (criteria == null) {
            return null;
        }
        // Formato: cpe:2.3:a:vendor:product:version:...
        String[] parts = criteria.split(":");
        if (parts.length >= 5) {
            String vendor = capitalize(parts[3].replace('_', ' '));
            String product = capitalize(parts[4].replace('_', ' '));
            return (vendor + " " + product).trim();
        }
        return null;
    }

    private static String capitalize(String value) {
        if (value == null || value.isBlank()) {
            return value;
        }
        return Character.toUpperCase(value.charAt(0)) + value.substring(1);
    }

    private static String referenceUrl(JsonNode cveNode, String cveId) {
        JsonNode refs = cveNode.path("references");
        if (refs.isArray() && !refs.isEmpty()) {
            String url = refs.get(0).path("url").asText(null);
            if (url != null && !url.isBlank()) {
                return url;
            }
        }
        return "https://www.cve.org/CVERecord?id=" + cveId;
    }

    private static LocalDateTime publishedDate(JsonNode cveNode) {
        String published = cveNode.path("published").asText(null);
        if (published != null) {
            // NVD devuelve la fecha sin offset de zona horaria (p.ej. "1988-10-01T04:00:00.000"),
            // por lo que OffsetDateTime.parse() la rechaza; hay que usar LocalDateTime.parse().
            try {
                return LocalDateTime.parse(published);
            } catch (DateTimeParseException e) {
                // Por si alguna vez llega con offset (p.ej. terminado en "Z"), se intenta así también.
                try {
                    return OffsetDateTime.parse(published).toLocalDateTime();
                } catch (DateTimeParseException e2) {
                    // se usa el valor por defecto de abajo
                }
            }
        }
        return LocalDateTime.now();
    }
}

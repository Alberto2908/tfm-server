package com.alberto.tfm.vulnerabilidades.importer;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Mapeo de categorías del catálogo (las mismas que el formulario "anadir" de
 * tfm-web) a los CWE de NVD que las representan. Cualquier CVE cuyos CWE no
 * coincidan con ninguno de esta lista se clasifica como "Other".
 */
final class CveCategoryMapping {

    static final Map<String, List<String>> CATEGORY_TO_CWE = Map.of(
            "Injection", List.of("CWE-89", "CWE-78", "CWE-94", "CWE-611", "CWE-943", "CWE-90"),
            "XSS", List.of("CWE-79"),
            "CSRF", List.of("CWE-352"),
            "Authentication", List.of("CWE-287", "CWE-306", "CWE-798", "CWE-521"),
            "Authorization", List.of("CWE-862", "CWE-863", "CWE-269"),
            "Data Exposure", List.of("CWE-200", "CWE-311", "CWE-312", "CWE-319"),
            "DoS", List.of("CWE-400", "CWE-770", "CWE-835"));

    static final String OTHER_CATEGORY = "Other";

    static final Map<String, String> CWE_TO_CATEGORY = buildReverseMap();

    private static Map<String, String> buildReverseMap() {
        Map<String, String> reverse = new HashMap<>();
        for (Map.Entry<String, List<String>> entry : CATEGORY_TO_CWE.entrySet()) {
            for (String cwe : entry.getValue()) {
                reverse.put(cwe, entry.getKey());
            }
        }
        return reverse;
    }

    private CveCategoryMapping() {
    }
}

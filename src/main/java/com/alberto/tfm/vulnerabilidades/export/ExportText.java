package com.alberto.tfm.vulnerabilidades.export;

/**
 * Limpieza de texto común a todos los formatos de exportación.
 */
final class ExportText {

    private ExportText() {
    }

    /**
     * Normaliza los saltos de línea y descarta los caracteres de control. Los
     * textos importados del NVD traen separadores Unicode de línea y párrafo
     * (U+2028 / U+2029), que muchos editores marcan como terminadores de línea
     * inusuales al abrir el fichero exportado.
     */
    static String sanitize(String value) {
        if (value == null || value.isEmpty()) {
            return "";
        }

        StringBuilder sanitized = new StringBuilder(value.length());
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);

            if (c == '\u2028' || c == '\u2029' || c == '\u0085') {
                sanitized.append('\n');
            } else if (c == '\r') {
                sanitized.append('\n');
                if (i + 1 < value.length() && value.charAt(i + 1) == '\n') {
                    i++;
                }
            } else if (c == '\t' || c == '\n' || (c >= 0x20 && c != 0x7F && (c < 0x80 || c > 0x9F))) {
                sanitized.append(c);
            }
        }

        return sanitized.toString();
    }
}

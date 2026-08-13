package com.alberto.tfm.vulnerabilidades.export;

/**
 * Formatos disponibles al exportar el resultado de un filtro de vulnerabilidades.
 */
public enum ExportFormat {

    JSON("json", "application/json"),
    XML("xml", "application/xml"),
    CSV("csv", "text/csv;charset=UTF-8"),
    PDF("pdf", "application/pdf");

    private final String extension;
    private final String contentType;

    ExportFormat(String extension, String contentType) {
        this.extension = extension;
        this.contentType = contentType;
    }

    public String getExtension() {
        return extension;
    }

    public String getContentType() {
        return contentType;
    }

    public static ExportFormat from(String value) {
        if (value != null) {
            for (ExportFormat format : values()) {
                if (format.extension.equalsIgnoreCase(value.trim())) {
                    return format;
                }
            }
        }
        throw new IllegalArgumentException("Formato de exportación no soportado: " + value);
    }
}

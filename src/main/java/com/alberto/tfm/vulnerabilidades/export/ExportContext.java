package com.alberto.tfm.vulnerabilidades.export;

import java.time.LocalDateTime;
import java.util.List;

/**
 * Metadatos de la exportación: total de coincidencias del filtro, momento de
 * generación y descripción legible de los filtros aplicados.
 */
public record ExportContext(long total, LocalDateTime generatedAt, List<String> appliedFilters) {

    public ExportContext {
        appliedFilters = appliedFilters == null ? List.of() : List.copyOf(appliedFilters);
    }
}

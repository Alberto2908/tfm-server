package com.alberto.tfm.vulnerabilidades.dto;

import lombok.Getter;

import java.util.List;

/**
 * Respuesta paginada genérica para listados que pueden crecer mucho
 * (p. ej. Vulnerabilities, con cientos de miles de registros importados).
 */
@Getter
public class PageResponse<T> {

    private final List<T> content;
    private final long totalElements;
    private final int totalPages;
    private final int page;
    private final int size;

    public PageResponse(List<T> content, long totalElements, int page, int size) {
        this.content = content;
        this.totalElements = totalElements;
        this.page = page;
        this.size = size;
        this.totalPages = size <= 0 ? 0 : (int) Math.ceil((double) totalElements / size);
    }
}

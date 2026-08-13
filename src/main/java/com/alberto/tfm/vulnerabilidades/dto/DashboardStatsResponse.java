package com.alberto.tfm.vulnerabilidades.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

/**
 * Estadísticas agregadas del catálogo para la pestaña Dashboard. Se calculan
 * con agregaciones de MongoDB (no se materializa la colección en memoria).
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class DashboardStatsResponse {

    private long totalVulnerabilities;
    private long addedLast7Days;
    private long addedLast30Days;
    private Map<String, Long> bySeverity;
    private Map<String, Long> byCategory;
    private Map<String, Long> byYear;
    private List<NameCount> topFrameworks;
    private LatestVulnerability latestVulnerability;

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class NameCount {
        private String name;
        private long count;
    }

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class LatestVulnerability {
        private String id;
        private String name;
        private String severity;
        private String category;
        private String description;
        private LocalDateTime createdAt;
        private String createdBy;
    }
}

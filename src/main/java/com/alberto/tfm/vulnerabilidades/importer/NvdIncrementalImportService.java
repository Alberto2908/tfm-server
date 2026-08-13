package com.alberto.tfm.vulnerabilidades.importer;

import com.alberto.tfm.vulnerabilidades.models.Vulnerability;
import com.alberto.tfm.vulnerabilidades.repository.VulnerabilityRepository;
import com.fasterxml.jackson.databind.JsonNode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.domain.Sort;
import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.data.mongodb.core.query.Criteria;
import org.springframework.data.mongodb.core.query.Query;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Comprobación bajo demanda de nuevas vulnerabilidades publicadas en NVD
 * desde la última importada, sin repetir el barrido histórico completo.
 * Usa como punto de partida la fecha de publicación más reciente ya
 * almacenada (createdBy = "import:nvd"), en vez de un fichero de checkpoint
 * aparte, para no depender del disco local del proceso que la ejecuta.
 */
@Service
public class NvdIncrementalImportService {

    private static final Logger log = LoggerFactory.getLogger(NvdIncrementalImportService.class);
    private static final DateTimeFormatter NVD_DATE_FORMAT =
            DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSS");
    private static final int MAX_WINDOW_DAYS = 120; // límite de rango de NVD para pubStartDate/pubEndDate
    private static final int DEFAULT_LOOKBACK_DAYS = 30; // si aún no hay ningún CVE de NVD en la BD

    private final MongoTemplate mongoTemplate;
    private final VulnerabilityRepository vulnerabilityRepository;
    private final String nvdApiKey;

    public NvdIncrementalImportService(
            MongoTemplate mongoTemplate,
            VulnerabilityRepository vulnerabilityRepository,
            @Value("${nvd.api.key:}") String nvdApiKey) {
        this.mongoTemplate = mongoTemplate;
        this.vulnerabilityRepository = vulnerabilityRepository;
        this.nvdApiKey = nvdApiKey;
    }

    public NvdCheckResult checkForNewVulnerabilities() throws IOException, InterruptedException {
        LocalDateTime since = latestKnownPublishedDate().minusMinutes(5); // pequeño solape de seguridad
        LocalDateTime now = LocalDateTime.now();

        if (!since.isBefore(now)) {
            return new NvdCheckResult(0, since, now);
        }

        NvdCveClient client = new NvdCveClient(nvdApiKey);
        int added = 0;
        LocalDateTime windowStart = since;

        while (windowStart.isBefore(now)) {
            LocalDateTime maxWindowEnd = windowStart.plusDays(MAX_WINDOW_DAYS);
            LocalDateTime windowEnd = maxWindowEnd.isAfter(now) ? now : maxWindowEnd;

            added += importWindow(client, windowStart, windowEnd);
            windowStart = windowEnd;
        }

        log.info("Comprobación incremental de NVD: {} vulnerabilidades nuevas entre {} y {}", added, since, now);
        return new NvdCheckResult(added, since, now);
    }

    private int importWindow(NvdCveClient client, LocalDateTime start, LocalDateTime end)
            throws IOException, InterruptedException {
        String pubStart = NVD_DATE_FORMAT.format(start);
        String pubEnd = NVD_DATE_FORMAT.format(end);

        int startIndex = 0;
        int totalResults;
        int added = 0;

        do {
            JsonNode page = client.fetchPageByPublishedDate(pubStart, pubEnd, startIndex);
            JsonNode vulnerabilities = page.path("vulnerabilities");
            totalResults = page.path("totalResults").asInt(0);
            int pageSize = vulnerabilities.size();

            if (pageSize > 0) {
                added += insertNewOnly(vulnerabilities);
            }
            startIndex += pageSize;
        } while (startIndex < totalResults);

        return added;
    }

    private int insertNewOnly(JsonNode vulnerabilities) {
        List<String> pageIds = new ArrayList<>();
        for (JsonNode item : vulnerabilities) {
            pageIds.add(item.path("cve").path("id").asText());
        }

        Set<String> existing = new HashSet<>();
        for (Vulnerability v : vulnerabilityRepository.findByNameIn(pageIds)) {
            existing.add(v.getName());
        }

        List<Vulnerability> batch = new ArrayList<>();
        for (JsonNode item : vulnerabilities) {
            String id = item.path("cve").path("id").asText();
            if (existing.contains(id)) {
                continue;
            }
            batch.add(CveMapper.toVulnerability(item.path("cve")));
        }

        if (!batch.isEmpty()) {
            mongoTemplate.insert(batch, Vulnerability.class);
        }
        return batch.size();
    }

    private LocalDateTime latestKnownPublishedDate() {
        Query query = Query.query(Criteria.where("createdBy").is("import:nvd"))
                .with(Sort.by(Sort.Direction.DESC, "createdAt"))
                .limit(1);
        Vulnerability latest = mongoTemplate.findOne(query, Vulnerability.class);
        return latest != null ? latest.getCreatedAt() : LocalDateTime.now().minusDays(DEFAULT_LOOKBACK_DAYS);
    }

    public record NvdCheckResult(int added, LocalDateTime checkedFrom, LocalDateTime checkedTo) {
    }
}

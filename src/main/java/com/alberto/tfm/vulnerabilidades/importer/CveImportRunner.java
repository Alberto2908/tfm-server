package com.alberto.tfm.vulnerabilidades.importer;

import com.alberto.tfm.vulnerabilidades.models.Vulnerability;
import com.alberto.tfm.vulnerabilidades.repository.VulnerabilityRepository;
import com.fasterxml.jackson.databind.JsonNode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.stereotype.Component;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Importa TODOS los CVE reales desde la API de NVD mediante un barrido
 * completo (sin filtrar por CWE), categorizando cada uno según sus propios
 * CWE (o "Other" si no coincide con ninguna categoría del catálogo). Se
 * insertan ya verificados (createdBy/verifiedBy = "import:nvd").
 *
 * Tarea puntual: solo se ejecuta si import.cve.enabled=true. Se autolimita por
 * espacio estimado (import.cve.budget-mb) para no agotar el almacenamiento de
 * MongoDB. Comprueba por lote si el CVE ya existe (para no duplicar los
 * importados en ejecuciones anteriores, p.ej. el barrido filtrado previo) y
 * guarda progreso en un fichero de checkpoint para poder reanudar sin repetir
 * trabajo.
 */
@Component
@ConditionalOnProperty(name = "import.cve.enabled", havingValue = "true")
public class CveImportRunner implements CommandLineRunner {

    private static final Logger log = LoggerFactory.getLogger(CveImportRunner.class);
    private static final String CHECKPOINT_KEY = "FULL_SWEEP";
    private static final int BATCH_SIZE = 500;
    private static final int ESTIMATED_OVERHEAD_BYTES = 300; // nombres de campo + estructura BSON

    private final MongoTemplate mongoTemplate;
    private final VulnerabilityRepository vulnerabilityRepository;
    private final ConfigurableApplicationContext applicationContext;
    private final String nvdApiKey;
    private final long budgetBytes;

    public CveImportRunner(
            MongoTemplate mongoTemplate,
            VulnerabilityRepository vulnerabilityRepository,
            ConfigurableApplicationContext applicationContext,
            @Value("${nvd.api.key:}") String nvdApiKey,
            @Value("${import.cve.budget-mb:350}") long budgetMb) {
        this.mongoTemplate = mongoTemplate;
        this.vulnerabilityRepository = vulnerabilityRepository;
        this.applicationContext = applicationContext;
        this.nvdApiKey = nvdApiKey;
        this.budgetBytes = budgetMb * 1024L * 1024L;
    }

    @Override
    public void run(String... args) throws Exception {
        if (nvdApiKey == null || nvdApiKey.isBlank()) {
            log.warn("import.cve.enabled=true pero no se ha definido NVD_API_KEY. Se continúa sin key "
                    + "(límite de 5 peticiones/30s, mucho más lento).");
        }

        NvdCveClient client = new NvdCveClient(nvdApiKey);
        ImportCheckpointStore checkpoint = new ImportCheckpointStore(Path.of("cve-import-progress.properties"));

        int startIndex = checkpoint.nextStartIndex(CHECKPOINT_KEY);
        boolean exhausted = checkpoint.isExhausted(CHECKPOINT_KEY);

        long importedBytes = 0L;
        int importedCount = 0;
        int skippedDuplicates = 0;
        List<Vulnerability> batch = new ArrayList<>(BATCH_SIZE);

        log.info("Importación completa de CVEs iniciada desde startIndex={}. Presupuesto: {} MB",
                startIndex, budgetBytes / (1024 * 1024));

        boolean stoppedByError = false;

        while (!exhausted && importedBytes < budgetBytes) {
            JsonNode page;
            try {
                page = client.fetchPage(startIndex);
            } catch (Exception e) {
                log.error("Fallo consultando NVD en startIndex={}, se detiene la importación", startIndex, e);
                stoppedByError = true;
                break;
            }

            JsonNode vulnerabilities = page.path("vulnerabilities");
            int totalResults = page.path("totalResults").asInt(0);
            int pageSize = vulnerabilities.size();

            Set<String> existingIds = existingIdsInPage(vulnerabilities);

            for (JsonNode item : vulnerabilities) {
                JsonNode cveNode = item.path("cve");
                String cveId = cveNode.path("id").asText();

                if (existingIds.contains(cveId)) {
                    skippedDuplicates++;
                    continue;
                }

                Vulnerability vulnerability = CveMapper.toVulnerability(cveNode);
                batch.add(vulnerability);
                importedBytes += estimateSize(vulnerability);

                if (batch.size() >= BATCH_SIZE) {
                    flushBatch(batch);
                    importedCount += batch.size();
                    batch.clear();
                    log.info("Progreso: {} nuevas ({} ya existían) - ~{} MB de {} MB - startIndex {}/{}",
                            importedCount, skippedDuplicates, importedBytes / (1024 * 1024),
                            budgetBytes / (1024 * 1024), startIndex, totalResults);
                }

                if (importedBytes >= budgetBytes) {
                    break;
                }
            }

            startIndex += pageSize;
            exhausted = pageSize == 0 || startIndex >= totalResults;
            checkpoint.update(CHECKPOINT_KEY, startIndex, exhausted);
        }

        if (!batch.isEmpty()) {
            flushBatch(batch);
            importedCount += batch.size();
        }

        String reason;
        if (stoppedByError) {
            reason = "error de red/API a mitad de importación (progreso guardado, reanudable)";
        } else if (importedBytes >= budgetBytes) {
            reason = "se alcanzó el presupuesto de espacio configurado";
        } else {
            reason = "se ha recorrido todo el catálogo de NVD";
        }
        log.info("Importación de CVEs finalizada: {} nuevas insertadas, {} ya existían (~{} MB). "
                + "Motivo de parada: {}", importedCount, skippedDuplicates, importedBytes / (1024 * 1024), reason);

        // Tarea puntual: se cierra la aplicación al terminar en vez de quedarse
        // como servidor web, para poder ejecutarla en segundo plano y detectar
        // cuándo ha acabado.
        int exitCode = SpringApplication.exit(applicationContext, () -> 0);
        System.exit(exitCode);
    }

    private Set<String> existingIdsInPage(JsonNode vulnerabilities) {
        List<String> pageIds = new ArrayList<>();
        for (JsonNode item : vulnerabilities) {
            pageIds.add(item.path("cve").path("id").asText());
        }
        if (pageIds.isEmpty()) {
            return Set.of();
        }
        Set<String> existing = new HashSet<>();
        for (Vulnerability v : vulnerabilityRepository.findByNameIn(pageIds)) {
            existing.add(v.getName());
        }
        return existing;
    }

    private void flushBatch(List<Vulnerability> batch) {
        mongoTemplate.insert(batch, Vulnerability.class);
    }

    private long estimateSize(Vulnerability vulnerability) {
        long total = ESTIMATED_OVERHEAD_BYTES;
        total += length(vulnerability.getName());
        total += length(vulnerability.getDescription());
        total += length(vulnerability.getSeverity());
        total += length(vulnerability.getCategory());
        total += length(vulnerability.getFramework());
        total += length(vulnerability.getAffectedEndpoint());
        total += length(vulnerability.getPayloadExample());
        total += length(vulnerability.getImpact());
        total += length(vulnerability.getMitigation());
        total += length(vulnerability.getReferenceURL());
        total += length(vulnerability.getCreatedBy());
        total += length(vulnerability.getVerifiedBy());
        return total;
    }

    private int length(String value) {
        return value == null ? 0 : value.length();
    }
}

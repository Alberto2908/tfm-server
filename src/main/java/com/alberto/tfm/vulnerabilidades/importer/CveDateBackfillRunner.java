package com.alberto.tfm.vulnerabilidades.importer;

import com.alberto.tfm.vulnerabilidades.models.Vulnerability;
import com.fasterxml.jackson.databind.JsonNode;
import com.mongodb.bulk.BulkWriteResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.data.mongodb.core.BulkOperations;
import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.data.mongodb.core.query.Criteria;
import org.springframework.data.mongodb.core.query.Query;
import org.springframework.data.mongodb.core.query.Update;
import org.springframework.stereotype.Component;

import java.nio.file.Path;

/**
 * Tarea puntual: recorre de nuevo NVD y actualiza SOLO createdAt/verifiedAt de
 * los CVE ya importados (createdBy/verifiedBy = "import:nvd"), corrigiendo el
 * bug de CveMapper.publishedDate() que hacía que todos quedaran con la fecha
 * de importación en vez de la fecha real de publicación del CVE.
 *
 * No inserta nada nuevo (para eso está CveImportRunner). Usa su propio
 * checkpoint ("DATE_BACKFILL_SWEEP") para poder reanudar sin repetir trabajo.
 */
@Component
@ConditionalOnProperty(name = "backfill.dates.enabled", havingValue = "true")
public class CveDateBackfillRunner implements CommandLineRunner {

    private static final Logger log = LoggerFactory.getLogger(CveDateBackfillRunner.class);
    private static final String CHECKPOINT_KEY = "DATE_BACKFILL_SWEEP";

    private final MongoTemplate mongoTemplate;
    private final ConfigurableApplicationContext applicationContext;
    private final String nvdApiKey;

    public CveDateBackfillRunner(
            MongoTemplate mongoTemplate,
            ConfigurableApplicationContext applicationContext,
            @Value("${nvd.api.key:}") String nvdApiKey) {
        this.mongoTemplate = mongoTemplate;
        this.applicationContext = applicationContext;
        this.nvdApiKey = nvdApiKey;
    }

    @Override
    public void run(String... args) throws Exception {
        if (nvdApiKey == null || nvdApiKey.isBlank()) {
            log.warn("backfill.dates.enabled=true pero no se ha definido NVD_API_KEY. Se continúa sin key "
                    + "(límite de 5 peticiones/30s, mucho más lento).");
        }

        NvdCveClient client = new NvdCveClient(nvdApiKey);
        ImportCheckpointStore checkpoint = new ImportCheckpointStore(Path.of("cve-import-progress.properties"));

        int startIndex = checkpoint.nextStartIndex(CHECKPOINT_KEY);
        boolean exhausted = checkpoint.isExhausted(CHECKPOINT_KEY);

        long updatedCount = 0;
        long notMatchedCount = 0;

        log.info("Backfill de fechas iniciado desde startIndex={}", startIndex);

        while (!exhausted) {
            JsonNode page;
            try {
                page = client.fetchPage(startIndex);
            } catch (Exception e) {
                log.error("Fallo consultando NVD en startIndex={}, se detiene el backfill", startIndex, e);
                break;
            }

            JsonNode vulnerabilities = page.path("vulnerabilities");
            int totalResults = page.path("totalResults").asInt(0);
            int pageSize = vulnerabilities.size();

            if (pageSize > 0) {
                BulkOperations bulkOps =
                        mongoTemplate.bulkOps(BulkOperations.BulkMode.UNORDERED, Vulnerability.class);
                int queued = 0;

                for (JsonNode item : vulnerabilities) {
                    Vulnerability mapped = CveMapper.toVulnerability(item.path("cve"));

                    Query query = Query.query(
                            Criteria.where("name").is(mapped.getName()).and("verified").is(true));
                    Update update = new Update()
                            .set("createdAt", mapped.getCreatedAt())
                            .set("verifiedAt", mapped.getVerifiedAt());

                    bulkOps.updateOne(query, update);
                    queued++;
                }

                if (queued > 0) {
                    BulkWriteResult result = bulkOps.execute();
                    updatedCount += result.getModifiedCount();
                    notMatchedCount += (queued - result.getMatchedCount());
                }
            }

            startIndex += pageSize;
            exhausted = pageSize == 0 || startIndex >= totalResults;
            checkpoint.update(CHECKPOINT_KEY, startIndex, exhausted);

            log.info("Progreso backfill de fechas: {} actualizados hasta ahora (startIndex {}/{})",
                    updatedCount, startIndex, totalResults);
        }

        log.info("Backfill de fechas finalizado: {} documentos actualizados "
                + "({} CVE de NVD no encontrados en la base de datos)", updatedCount, notMatchedCount);

        int exitCode = SpringApplication.exit(applicationContext, () -> 0);
        System.exit(exitCode);
    }
}

package com.alberto.tfm.vulnerabilidades.importer;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Properties;

/**
 * Guarda el progreso de la importación (por CWE: siguiente startIndex y si ya
 * se agotó) en un fichero local, para poder reanudar sin repetir trabajo ni
 * duplicar vulnerabilidades ya insertadas.
 */
final class ImportCheckpointStore {

    private static final Logger log = LoggerFactory.getLogger(ImportCheckpointStore.class);

    private final Path file;
    private final Properties properties = new Properties();

    ImportCheckpointStore(Path file) {
        this.file = file;
        load();
    }

    private void load() {
        if (!Files.exists(file)) {
            return;
        }
        try (InputStream in = Files.newInputStream(file)) {
            properties.load(in);
        } catch (IOException e) {
            log.warn("No se pudo leer el checkpoint en {}, se empieza de cero", file, e);
        }
    }

    int nextStartIndex(String cweId) {
        return Integer.parseInt(properties.getProperty(cweId + ".startIndex", "0"));
    }

    boolean isExhausted(String cweId) {
        return Boolean.parseBoolean(properties.getProperty(cweId + ".exhausted", "false"));
    }

    void update(String cweId, int nextStartIndex, boolean exhausted) {
        properties.setProperty(cweId + ".startIndex", String.valueOf(nextStartIndex));
        properties.setProperty(cweId + ".exhausted", String.valueOf(exhausted));
        save();
    }

    private void save() {
        try (OutputStream out = Files.newOutputStream(file)) {
            properties.store(out, "Progreso de importacion de CVEs (NVD) - no editar a mano");
        } catch (IOException e) {
            log.error("No se pudo guardar el checkpoint en {}", file, e);
        }
    }
}

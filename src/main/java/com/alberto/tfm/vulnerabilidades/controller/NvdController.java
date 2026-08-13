package com.alberto.tfm.vulnerabilidades.controller;

import com.alberto.tfm.vulnerabilidades.importer.NvdIncrementalImportService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;

/**
 * Comprobación manual (solo admin, ver SecurityConfig) de nuevas
 * vulnerabilidades publicadas en NVD desde la última importación conocida.
 */
@RestController
@CrossOrigin(origins = "http://localhost:4200")
@RequestMapping("/api/nvd")
public class NvdController {

    private final NvdIncrementalImportService incrementalImportService;

    public NvdController(NvdIncrementalImportService incrementalImportService) {
        this.incrementalImportService = incrementalImportService;
    }

    @PostMapping("/check-updates")
    public ResponseEntity<NvdIncrementalImportService.NvdCheckResult> checkUpdates() {
        try {
            return ResponseEntity.ok(incrementalImportService.checkForNewVulnerabilities());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return ResponseEntity.internalServerError().build();
        } catch (IOException e) {
            return ResponseEntity.internalServerError().build();
        }
    }
}

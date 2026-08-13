package com.alberto.tfm.vulnerabilidades.controller;

import com.alberto.tfm.vulnerabilidades.dto.DashboardStatsResponse;
import com.alberto.tfm.vulnerabilidades.export.DashboardPdfReportWriter;
import com.alberto.tfm.vulnerabilidades.service.VulnerabilityService;
import org.springframework.http.ContentDisposition;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.mvc.method.annotation.StreamingResponseBody;

import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

/**
 * Estadísticas agregadas para la pestaña Dashboard. Requiere sesión iniciada
 * (ver SecurityConfig) - visible para cualquier usuario logueado, no solo admin.
 */
@RestController
@CrossOrigin(origins = "http://localhost:4200")
@RequestMapping("/api/dashboard")
public class DashboardController {

    private static final DateTimeFormatter FILENAME_TIMESTAMP = DateTimeFormatter.ofPattern("yyyyMMdd_HHmm");

    private final VulnerabilityService vulnerabilityService;
    private final DashboardPdfReportWriter pdfReportWriter;

    public DashboardController(VulnerabilityService vulnerabilityService, DashboardPdfReportWriter pdfReportWriter) {
        this.vulnerabilityService = vulnerabilityService;
        this.pdfReportWriter = pdfReportWriter;
    }

    @GetMapping("/stats")
    public DashboardStatsResponse stats() {
        return vulnerabilityService.getDashboardStats();
    }

    @GetMapping("/export")
    public ResponseEntity<StreamingResponseBody> export() {
        DashboardStatsResponse stats = vulnerabilityService.getDashboardStats();

        StreamingResponseBody body = out -> pdfReportWriter.write(stats, out);

        String filename = "dashboard_" + FILENAME_TIMESTAMP.format(LocalDateTime.now()) + ".pdf";

        return ResponseEntity.ok()
                .contentType(MediaType.APPLICATION_PDF)
                .header(HttpHeaders.CONTENT_DISPOSITION, ContentDisposition.attachment()
                        .filename(filename, StandardCharsets.UTF_8)
                        .build()
                        .toString())
                .body(body);
    }
}

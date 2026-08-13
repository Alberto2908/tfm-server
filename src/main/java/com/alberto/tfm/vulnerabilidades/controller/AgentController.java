package com.alberto.tfm.vulnerabilidades.controller;

import com.alberto.tfm.vulnerabilidades.agent.VulnerabilityAgentService;
import com.alberto.tfm.vulnerabilidades.models.Vulnerability;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.List;
import java.util.Optional;

/**
 * Endpoints manuales (solo admin, ver SecurityConfig) para disparar el agente
 * a demanda sin esperar a la ejecución programada. Solo existen si
 * agents.enabled=true.
 */
@RestController
@CrossOrigin(origins = "http://localhost:4200")
@RequestMapping("/api/agent")
@ConditionalOnProperty(name = "agents.enabled", havingValue = "true")
public class AgentController {

    private final VulnerabilityAgentService agentService;

    public AgentController(VulnerabilityAgentService agentService) {
        this.agentService = agentService;
    }

    @PostMapping("/discover")
    public ResponseEntity<Vulnerability> discover() {
        Optional<Vulnerability> created = agentService.discoverNew();
        return created.map(ResponseEntity::ok).orElse(ResponseEntity.noContent().build());
    }

    @PostMapping("/verify")
    public ResponseEntity<Void> verify() {
        agentService.verifyPending();
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/sanitize")
    public ResponseEntity<Void> sanitize() {
        agentService.sanitizeAndEnrichExisting();
        return ResponseEntity.noContent().build();
    }

    /** Sube un informe de pentesting / documentación de detección (PDF o texto) y extrae vulnerabilidades. */
    @PostMapping("/ingest-document")
    public ResponseEntity<List<Vulnerability>> ingestDocument(@RequestParam("file") MultipartFile file)
            throws IOException {
        if (file.isEmpty()) {
            return ResponseEntity.badRequest().build();
        }
        List<Vulnerability> created =
                agentService.ingestFromDocument(file.getBytes(), file.getOriginalFilename(), file.getContentType());
        agentService.verifyPending();
        return ResponseEntity.ok(created);
    }

    @PostMapping("/run")
    public ResponseEntity<AgentRunResult> runFullCycle() {
        Optional<Vulnerability> discovered = agentService.discoverNew();
        int pendingBefore = agentService.countPendingAgentItems();
        agentService.verifyPending();
        int pendingAfter = agentService.countPendingAgentItems();
        agentService.sanitizeAndEnrichExisting();

        AgentRunResult result = new AgentRunResult(
                discovered.map(Vulnerability::getName).orElse(null),
                Math.max(0, pendingBefore - pendingAfter));
        return ResponseEntity.ok(result);
    }

    public record AgentRunResult(String discoveredName, int reviewedCount) {
    }
}

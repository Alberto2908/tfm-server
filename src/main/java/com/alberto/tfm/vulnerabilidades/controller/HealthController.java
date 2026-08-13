package com.alberto.tfm.vulnerabilidades.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

/**
 * Endpoint público de vida del servicio. Lo usan el keep-alive de Render
 * (KeepAliveScheduler) y cualquier monitorización externa.
 */
@RestController
public class HealthController {

    @GetMapping("/health")
    public Map<String, Object> health() {
        Map<String, Object> resp = new HashMap<>();
        resp.put("status", "ok");
        resp.put("ts", Instant.now().toString());
        return resp;
    }
}

package com.alberto.tfm.vulnerabilidades.agent;

import lombok.Data;

import java.util.List;

/**
 * Resultado de analizar un documento (informe de pentesting, documentación de
 * detección...): puede contener varias vulnerabilidades distintas.
 */
@Data
public class DocumentIngestResult {

    private List<VulnerabilityDraft> vulnerabilities;
}

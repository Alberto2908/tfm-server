package com.alberto.tfm.vulnerabilidades.agent;

import lombok.Data;

/**
 * Veredicto del agente de verificación sobre una vulnerabilidad candidata.
 */
@Data
public class VerificationResult {

    private boolean technicallyValid;
    private boolean duplicate;
    private String reasoning;
}

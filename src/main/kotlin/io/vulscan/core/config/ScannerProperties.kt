package io.vulscan.core.config

import org.springframework.boot.context.properties.ConfigurationProperties
import org.springframework.boot.context.properties.bind.DefaultValue

@ConfigurationProperties("scanner")
data class ScannerProperties(
    @DefaultValue val scope: Scope,
    @DefaultValue val limits: Limits,
    @DefaultValue val jobs: Jobs,
    @DefaultValue val outbox: Outbox,
    @DefaultValue val secret: Secret,
) {
    data class Scope(
        /** Диапазоны loopback/private/CGNAT, разрешённые для целей (например, сеть docker compose). */
        @DefaultValue val allowedPrivateCidrs: List<String>,
        @DefaultValue("80,443,8080,8443") val allowedPorts: List<Int>,
    )

    data class Limits(
        @DefaultValue("2") val maxActiveScansPerUser: Int,
        @DefaultValue("4") val maxActiveScansGlobal: Int,
    )

    data class Jobs(
        @DefaultValue("2") val maxAttempts: Int,
        @DefaultValue("600") val queueTimeoutSec: Int,
        @DefaultValue("45") val leaseSec: Int,
        @DefaultValue("200") val maxEndpointsPerScan: Int,
    )

    data class Outbox(
        @DefaultValue("500") val pollMs: Long,
        @DefaultValue("50") val batchSize: Int,
    )

    data class Secret(
        /** Ключ AES-256 в Base64 (переменная окружения SCANNER_SECRET_KEY). */
        @DefaultValue("") val keyBase64: String,
    ) {
        override fun toString(): String = "Secret(keyBase64=[REDACTED])"
    }
}

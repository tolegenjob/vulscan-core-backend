package io.vulscan.core.api.dto

import io.vulscan.core.domain.JobStatus
import io.vulscan.core.domain.ResultIntegrity
import io.vulscan.core.domain.ScanStatus
import io.vulscan.kit.contracts.ModuleType
import io.vulscan.kit.contracts.SessionCheck
import io.vulscan.kit.contracts.SqliOptions
import io.vulscan.kit.contracts.XssOptions
import jakarta.validation.Valid
import jakarta.validation.constraints.NotEmpty
import jakarta.validation.constraints.NotNull
import jakarta.validation.constraints.Size
import java.time.Instant
import java.util.UUID

data class IdorRequest(
    @field:NotEmpty val identityIds: List<UUID> = emptyList(),
    val sessionCheck: SessionCheck? = null,
)

data class CreateScanRequest(
    @field:NotNull val targetId: UUID?,
    val policyId: UUID? = null,
    @field:NotEmpty val modules: List<ModuleType> = emptyList(),
    @field:NotEmpty val endpointIds: List<UUID> = emptyList(),
    val xss: XssOptions? = null,
    val sqli: SqliOptions? = null,
    @field:Valid val idor: IdorRequest? = null,
    @field:Size(max = 50) val excludePrefixes: List<String> = emptyList(),
)

data class ScanJobResponse(
    val id: UUID,
    val moduleType: ModuleType,
    val status: JobStatus,
    val attempt: Int,
    val requestsSent: Int,
    val endpointsDone: Int,
    val errorCode: String?,
    val errorMessage: String?,
    val resultIntegrity: ResultIntegrity,
    val startedAt: Instant?,
    val finishedAt: Instant?,
)

data class ScanResponse(
    val id: UUID,
    val targetId: UUID,
    val policyId: UUID,
    val status: ScanStatus,
    val cancelRequested: Boolean,
    val createdAt: Instant,
    val finishedAt: Instant?,
    val jobs: List<ScanJobResponse>,
    val findingCounts: Map<io.vulscan.kit.contracts.Severity, Long> = emptyMap(),
)

data class ScanListItem(val id: UUID, val targetId: UUID, val status: ScanStatus, val createdAt: Instant, val finishedAt: Instant?)

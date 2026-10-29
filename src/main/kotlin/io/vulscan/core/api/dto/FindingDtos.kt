package io.vulscan.core.api.dto

import io.vulscan.core.domain.TriageStatus
import io.vulscan.core.persistence.FindingEntity
import io.vulscan.core.persistence.FindingListRow
import io.vulscan.kit.contracts.ModuleType
import io.vulscan.kit.contracts.Severity
import io.vulscan.kit.contracts.Verdict
import io.vulscan.kit.contracts.VulnType
import jakarta.validation.constraints.NotNull
import java.time.Instant
import java.util.UUID

/** Элемент списка: без `details` и `evidence`. */
data class FindingListItem(
    val id: UUID,
    val scanId: UUID,
    val targetId: UUID,
    val moduleType: ModuleType,
    val vulnType: VulnType,
    val verdict: Verdict,
    val severity: Severity,
    val confidence: Int,
    val method: String,
    val url: String,
    val parameterName: String?,
    val endpointId: UUID?,
    val title: String,
    val triageStatus: TriageStatus,
    val createdAt: Instant,
) {
    companion object {
        fun of(r: FindingListRow) = FindingListItem(
            r.id, r.scanId, r.targetId, r.moduleType, r.vulnType, r.verdict, r.severity, r.confidence, r.method, r.url,
            r.parameterName, r.endpointId, r.title, r.triageStatus, r.createdAt,
        )
    }
}

data class FindingDetailResponse(
    val id: UUID,
    val jobId: UUID,
    val scanId: UUID,
    val targetId: UUID,
    val moduleType: ModuleType,
    val vulnType: VulnType,
    val verdict: Verdict,
    val severity: Severity,
    val confidence: Int,
    val fingerprint: String,
    val endpointId: UUID?,
    val method: String,
    val url: String,
    val parameterName: String?,
    val parameterLocation: String?,
    val title: String,
    val summary: String,
    val recommendation: String,
    val cwe: String,
    val details: Map<String, Any?>,
    val evidence: Map<String, Any?>,
    val triageStatus: TriageStatus,
    val createdAt: Instant,
) {
    companion object {
        fun of(f: FindingEntity) = FindingDetailResponse(
            f.id, f.jobId, f.scanId, f.targetId, f.moduleType, f.vulnType, f.verdict, f.severity, f.confidence.toInt(), f.fingerprint,
            f.endpointId, f.method, f.url, f.parameterName, f.parameterLocation, f.title, f.summary, f.recommendation, f.cwe,
            f.details, f.evidence, f.triageStatus, f.createdAt,
        )
    }
}

data class UpdateFindingRequest(@field:NotNull val triageStatus: TriageStatus?)

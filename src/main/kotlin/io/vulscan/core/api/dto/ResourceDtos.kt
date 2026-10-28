package io.vulscan.core.api.dto

import io.vulscan.kit.contracts.AccessRuleRef
import io.vulscan.kit.contracts.AuthType
import io.vulscan.kit.contracts.HttpMethod
import io.vulscan.kit.contracts.ParameterId
import io.vulscan.kit.contracts.ParameterRef
import io.vulscan.kit.contracts.ScanLimits
import io.vulscan.kit.contracts.Sensitivity
import jakarta.validation.Valid
import jakarta.validation.constraints.NotBlank
import jakarta.validation.constraints.NotNull
import jakarta.validation.constraints.Size
import java.time.Instant
import java.util.UUID

data class CreateEndpointRequest(
    @field:NotNull val method: HttpMethod?,
    @field:NotBlank @field:Size(max = 2000) val url: String?,
    @field:Size(max = 50) val parameters: List<ParameterRef> = emptyList(),
    val idempotent: Boolean = false,
    @field:Size(max = 100) val label: String? = null,
)

data class EndpointResponse(
    val id: UUID,
    val method: HttpMethod,
    val url: String,
    val parameters: List<ParameterRef>,
    val idempotent: Boolean,
    val label: String?,
)

data class ImportOpenApiRequest(
    @field:NotNull val document: Map<String, Any?>?,
    @field:NotBlank @field:Size(max = 300) val serverUrl: String?,
)

data class ImportSkipped(val path: String, val method: String, val reason: String)

data class ImportResponse(val created: Int, val skipped: List<ImportSkipped>)

data class CreateIdentityRequest(
    @field:NotBlank @field:Size(max = 100) val label: String?,
    @field:NotBlank @field:Size(max = 100) val role: String?,
    @field:NotNull val authType: AuthType?,
    val authConfig: Map<String, String> = emptyMap(),
    val secret: Map<String, String> = emptyMap(),
) {
    // Секрет не должен попасть в логи даже при случайном логировании запроса
    override fun toString(): String = "CreateIdentityRequest(label=$label, role=$role, authType=$authType, secret=[REDACTED])"
}

data class IdentityResponse(
    val id: UUID,
    val label: String,
    val role: String,
    val authType: AuthType,
    val authConfig: Map<String, String>,
    val hasSecret: Boolean = true,
)

data class LoginTestResponse(val ok: Boolean, val detail: String)

data class AccessRuleRequest(
    @field:NotNull val endpointId: UUID?,
    @field:NotNull @field:Valid val idParameter: ParameterId?,
    @field:NotBlank @field:Size(max = 200) val idValue: String?,
    @field:NotNull val ownerIdentityId: UUID?,
    @field:NotNull val sensitivity: Sensitivity?,
    val ownerMarkers: List<String> = emptyList(),
    @field:Size(max = 20) val access: List<AccessRuleRef> = emptyList(),
)

data class AccessRuleResponse(
    val id: UUID,
    val endpointId: UUID,
    val idParameter: ParameterId,
    val idValue: String,
    val ownerIdentityId: UUID,
    val sensitivity: Sensitivity,
    val ownerMarkers: List<String>,
    val access: List<AccessRuleRef>,
)

data class PolicyResponse(val id: UUID, val name: String, val limits: ScanLimits)

data class AuditEventResponse(
    val id: UUID,
    val actorId: UUID?,
    val action: String,
    val subjectType: String?,
    val subjectId: UUID?,
    val details: Map<String, Any?>?,
    val createdAt: Instant,
)

package io.vulscan.core.api

import io.vulscan.core.api.dto.AccessRuleRequest
import io.vulscan.core.api.dto.AccessRuleResponse
import io.vulscan.core.api.dto.AuditEventResponse
import io.vulscan.core.api.dto.CreateEndpointRequest
import io.vulscan.core.api.dto.CreateIdentityRequest
import io.vulscan.core.api.dto.EndpointResponse
import io.vulscan.core.api.dto.IdentityResponse
import io.vulscan.core.api.dto.ImportOpenApiRequest
import io.vulscan.core.api.dto.ImportResponse
import io.vulscan.core.api.dto.ImportSkipped
import io.vulscan.core.api.dto.LoginTestResponse
import io.vulscan.core.api.dto.PageResponse
import io.vulscan.core.api.dto.PolicyResponse
import io.vulscan.core.application.AccessRuleService
import io.vulscan.core.application.AuditQueryService
import io.vulscan.core.application.EndpointService
import io.vulscan.core.application.IdentityService
import io.vulscan.core.application.PolicyService
import io.vulscan.core.persistence.ResourceAccessRuleEntity
import io.vulscan.core.persistence.TargetEndpointEntity
import io.vulscan.core.persistence.TestIdentityEntity
import io.vulscan.core.security.AppUserDetails
import jakarta.validation.Valid
import org.springframework.http.HttpStatus
import org.springframework.security.core.annotation.AuthenticationPrincipal
import org.springframework.web.bind.annotation.DeleteMapping
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.ResponseStatus
import org.springframework.web.bind.annotation.RestController
import java.util.UUID

@RestController
@RequestMapping("/api/v1/targets/{targetId}/endpoints")
class EndpointController(private val service: EndpointService) {

    @GetMapping
    fun list(@AuthenticationPrincipal user: AppUserDetails, @PathVariable targetId: UUID) =
        service.list(user.toCurrentUser(), targetId).map(::toResponse)

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    fun create(@AuthenticationPrincipal user: AppUserDetails, @PathVariable targetId: UUID, @Valid @RequestBody body: CreateEndpointRequest) =
        toResponse(service.create(user.toCurrentUser(), targetId, body.method!!, body.url!!, body.parameters, body.idempotent, body.label))

    @PostMapping("/import-openapi")
    fun importOpenApi(@AuthenticationPrincipal user: AppUserDetails, @PathVariable targetId: UUID, @Valid @RequestBody body: ImportOpenApiRequest): ImportResponse {
        val result = service.importOpenApi(user.toCurrentUser(), targetId, body.document!!, body.serverUrl!!)
        return ImportResponse(result.created, result.skipped.map { ImportSkipped(it.path, it.method, it.reason) })
    }

    @DeleteMapping("/{endpointId}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    fun delete(@AuthenticationPrincipal user: AppUserDetails, @PathVariable targetId: UUID, @PathVariable endpointId: UUID) =
        service.delete(user.toCurrentUser(), targetId, endpointId)

    private fun toResponse(e: TargetEndpointEntity) = EndpointResponse(e.id, e.method, e.url, e.parameters, e.idempotent, e.label)
}

@RestController
@RequestMapping("/api/v1/targets/{targetId}/identities")
class IdentityController(private val service: IdentityService) {

    @GetMapping
    fun list(@AuthenticationPrincipal user: AppUserDetails, @PathVariable targetId: UUID) =
        service.list(user.toCurrentUser(), targetId).map(::toResponse)

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    fun create(@AuthenticationPrincipal user: AppUserDetails, @PathVariable targetId: UUID, @Valid @RequestBody body: CreateIdentityRequest) =
        toResponse(service.create(user.toCurrentUser(), targetId, body.label!!, body.role!!, body.authType!!, body.authConfig, body.secret))

    @DeleteMapping("/{identityId}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    fun delete(@AuthenticationPrincipal user: AppUserDetails, @PathVariable targetId: UUID, @PathVariable identityId: UUID) =
        service.delete(user.toCurrentUser(), targetId, identityId)

    @PostMapping("/{identityId}/test-login")
    fun testLogin(@AuthenticationPrincipal user: AppUserDetails, @PathVariable targetId: UUID, @PathVariable identityId: UUID): LoginTestResponse {
        val result = service.testLogin(user.toCurrentUser(), targetId, identityId)
        return LoginTestResponse(result.ok, result.detail)
    }

    private fun toResponse(e: TestIdentityEntity) = IdentityResponse(e.id, e.label, e.role, e.authType, e.authConfig)
}

@RestController
@RequestMapping("/api/v1/targets/{targetId}/access-rules")
class AccessRuleController(private val service: AccessRuleService) {

    @GetMapping
    fun list(@AuthenticationPrincipal user: AppUserDetails, @PathVariable targetId: UUID) =
        service.list(user.toCurrentUser(), targetId).map(::toResponse)

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    fun create(@AuthenticationPrincipal user: AppUserDetails, @PathVariable targetId: UUID, @Valid @RequestBody body: AccessRuleRequest) =
        toResponse(
            service.create(
                user.toCurrentUser(), targetId, body.endpointId!!, body.idParameter!!, body.idValue!!,
                body.ownerIdentityId!!, body.sensitivity!!, body.ownerMarkers, body.access,
            ),
        )

    @DeleteMapping("/{ruleId}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    fun delete(@AuthenticationPrincipal user: AppUserDetails, @PathVariable targetId: UUID, @PathVariable ruleId: UUID) =
        service.delete(user.toCurrentUser(), targetId, ruleId)

    private fun toResponse(r: ResourceAccessRuleEntity) =
        AccessRuleResponse(r.id, r.endpointId, r.idParameter, r.idValue, r.ownerIdentityId, r.sensitivity, r.ownerMarkers, r.access)
}

@RestController
@RequestMapping("/api/v1")
class CatalogController(private val policies: PolicyService, private val audit: AuditQueryService) {

    @GetMapping("/policies")
    fun policies() = policies.list().map { PolicyResponse(it.id, it.name, it.limits) }

    @GetMapping("/audit-events")
    fun auditEvents(
        @AuthenticationPrincipal user: AppUserDetails,
        @RequestParam(defaultValue = "0") page: Int,
        @RequestParam(defaultValue = "50") size: Int,
    ): PageResponse<AuditEventResponse> {
        val result = audit.list(user.toCurrentUser(), page, size)
        return PageResponse(
            result.content.map { AuditEventResponse(it.id, it.actorId, it.action, it.subjectType, it.subjectId, it.details, it.createdAt) },
            result.number, result.size, result.totalElements,
        )
    }
}

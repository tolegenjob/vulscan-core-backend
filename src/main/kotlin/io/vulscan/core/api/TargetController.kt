package io.vulscan.core.api

import io.vulscan.core.api.dto.CreateTargetRequest
import io.vulscan.core.api.dto.PageResponse
import io.vulscan.core.api.dto.TargetResponse
import io.vulscan.core.api.dto.VerificationInfo
import io.vulscan.core.application.TargetService
import io.vulscan.core.application.TargetVerificationService
import io.vulscan.core.domain.TargetStatus
import io.vulscan.core.persistence.TargetEntity
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
@RequestMapping("/api/v1/targets")
class TargetController(
    private val service: TargetService,
    private val verification: TargetVerificationService,
) {
    @GetMapping
    fun list(
        @AuthenticationPrincipal user: AppUserDetails,
        @RequestParam(defaultValue = "0") page: Int,
        @RequestParam(defaultValue = "20") size: Int,
    ): PageResponse<TargetResponse> {
        val result = service.list(user.toCurrentUser(), page, size)
        return PageResponse(result.content.map(::toResponse), result.number, result.size, result.totalElements)
    }

    @GetMapping("/{id}")
    fun get(@AuthenticationPrincipal user: AppUserDetails, @PathVariable id: UUID) = toResponse(service.get(user.toCurrentUser(), id))

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    fun create(@AuthenticationPrincipal user: AppUserDetails, @Valid @RequestBody body: CreateTargetRequest) =
        toResponse(service.create(user.toCurrentUser(), body.name!!, body.baseUrl!!))

    @PostMapping("/{id}/verify")
    fun verify(@AuthenticationPrincipal user: AppUserDetails, @PathVariable id: UUID) = toResponse(service.verify(user.toCurrentUser(), id))

    @PostMapping("/{id}/approve")
    fun approve(@AuthenticationPrincipal user: AppUserDetails, @PathVariable id: UUID) = toResponse(service.approve(user.toCurrentUser(), id))

    @DeleteMapping("/{id}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    fun delete(@AuthenticationPrincipal user: AppUserDetails, @PathVariable id: UUID) = service.delete(user.toCurrentUser(), id)

    private fun toResponse(t: TargetEntity) = TargetResponse(
        id = t.id, ownerId = t.ownerId, name = t.name, baseUrl = t.baseUrl, status = t.status, allowedHosts = t.allowedHosts,
        verification = if (t.status == TargetStatus.PENDING_VERIFICATION) {
            VerificationInfo("FILE", verification.verificationPath(t.verificationToken), t.verificationToken)
        } else {
            null
        },
        verifiedAt = t.verifiedAt, createdAt = t.createdAt,
    )
}

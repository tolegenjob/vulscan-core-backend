package io.vulscan.core.api

import io.vulscan.core.api.dto.CreateScanRequest
import io.vulscan.core.api.dto.PageResponse
import io.vulscan.core.api.dto.ScanJobResponse
import io.vulscan.core.api.dto.ScanListItem
import io.vulscan.core.api.dto.ScanResponse
import io.vulscan.core.application.IdorCommand
import io.vulscan.core.application.ScanCommand
import io.vulscan.core.application.ScanService
import io.vulscan.core.application.ScanView
import io.vulscan.core.domain.RateLimitedException
import io.vulscan.core.security.AppUserDetails
import io.vulscan.core.security.SlidingWindowLimiter
import jakarta.validation.Valid
import org.springframework.http.HttpStatus
import org.springframework.security.core.annotation.AuthenticationPrincipal
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
@RequestMapping("/api/v1/scans")
class ScanController(private val service: ScanService) {
    private val createLimiter = SlidingWindowLimiter(max = 10, windowMs = 60_000)

    @PostMapping
    @ResponseStatus(HttpStatus.ACCEPTED)
    fun create(@AuthenticationPrincipal user: AppUserDetails, @Valid @RequestBody body: CreateScanRequest): ScanResponse {
        val retryAfter = createLimiter.tryAcquire(user.id.toString())
        if (retryAfter > 0) throw RateLimitedException(retryAfter)
        val command = ScanCommand(
            targetId = body.targetId!!, policyId = body.policyId, modules = body.modules, endpointIds = body.endpointIds,
            xss = body.xss, sqli = body.sqli, idor = body.idor?.let { IdorCommand(it.identityIds, it.sessionCheck) },
            excludePrefixes = body.excludePrefixes,
        )
        return toResponse(service.create(user.toCurrentUser(), command))
    }

    @GetMapping
    fun list(
        @AuthenticationPrincipal user: AppUserDetails,
        @RequestParam(defaultValue = "0") page: Int,
        @RequestParam(defaultValue = "20") size: Int,
    ): PageResponse<ScanListItem> {
        val result = service.list(user.toCurrentUser(), page, size)
        return PageResponse(result.content.map { ScanListItem(it.id, it.targetId, it.status, it.createdAt, it.finishedAt) }, result.number, result.size, result.totalElements)
    }

    @GetMapping("/{id}")
    fun get(@AuthenticationPrincipal user: AppUserDetails, @PathVariable id: UUID) = toResponse(service.get(user.toCurrentUser(), id))

    @PostMapping("/{id}/cancel")
    fun cancel(@AuthenticationPrincipal user: AppUserDetails, @PathVariable id: UUID) = toResponse(service.cancel(user.toCurrentUser(), id))

    @PostMapping("/{id}/rerun")
    @ResponseStatus(HttpStatus.ACCEPTED)
    fun rerun(@AuthenticationPrincipal user: AppUserDetails, @PathVariable id: UUID) = toResponse(service.rerun(user.toCurrentUser(), id))

    private fun toResponse(view: ScanView) = ScanResponse(
        id = view.scan.id, targetId = view.scan.targetId, policyId = view.scan.policyId, status = view.scan.status,
        cancelRequested = view.scan.cancelRequested, createdAt = view.scan.createdAt, finishedAt = view.scan.finishedAt,
        findingCounts = io.vulscan.kit.contracts.Severity.entries.associateWith { view.findingCounts[it] ?: 0L },
        jobs = view.jobs.sortedBy { it.moduleType }.map {
            ScanJobResponse(
                it.id, it.moduleType, it.status, it.attempt, it.requestsSent, it.endpointsDone, it.errorCode, it.errorMessage,
                it.resultIntegrity, it.startedAt, it.finishedAt,
            )
        },
    )
}

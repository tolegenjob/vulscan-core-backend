package io.vulscan.core.api

import io.vulscan.core.api.dto.FindingDetailResponse
import io.vulscan.core.api.dto.FindingListItem
import io.vulscan.core.api.dto.PageResponse
import io.vulscan.core.api.dto.UpdateFindingRequest
import io.vulscan.core.application.FindingQueryService
import io.vulscan.core.domain.TriageStatus
import io.vulscan.core.persistence.FindingFilter
import io.vulscan.core.security.AppUserDetails
import io.vulscan.kit.contracts.ModuleType
import io.vulscan.kit.contracts.Severity
import io.vulscan.kit.contracts.Verdict
import io.vulscan.kit.contracts.VulnType
import jakarta.validation.Valid
import org.springframework.security.core.annotation.AuthenticationPrincipal
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PatchMapping
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController
import java.util.UUID

@RestController
@RequestMapping("/api/v1/findings")
class FindingController(private val service: FindingQueryService) {

    @GetMapping
    fun list(
        @AuthenticationPrincipal user: AppUserDetails,
        @RequestParam(required = false) scanId: UUID?,
        @RequestParam(required = false) targetId: UUID?,
        @RequestParam(required = false) moduleType: ModuleType?,
        @RequestParam(required = false) vulnType: VulnType?,
        @RequestParam(required = false) severity: Severity?,
        @RequestParam(required = false) verdict: Verdict?,
        @RequestParam(required = false) minConfidence: Int?,
        @RequestParam(required = false) triageStatus: TriageStatus?,
        @RequestParam(required = false) endpoint: UUID?,
        @RequestParam(required = false) q: String?,
        @RequestParam(required = false) sort: String?,
        @RequestParam(defaultValue = "0") page: Int,
        @RequestParam(defaultValue = "25") size: Int,
    ): PageResponse<FindingListItem> {
        val filter = FindingFilter(scanId, targetId, moduleType, vulnType, severity, verdict, minConfidence, triageStatus, endpoint, q)
        val result = service.list(user.toCurrentUser(), filter, sort, page, size)
        return PageResponse(result.content.map(FindingListItem::of), result.number, result.size, result.totalElements)
    }

    @GetMapping("/{id}")
    fun get(@AuthenticationPrincipal user: AppUserDetails, @PathVariable id: UUID) =
        FindingDetailResponse.of(service.get(user.toCurrentUser(), id))

    @PatchMapping("/{id}")
    fun update(@AuthenticationPrincipal user: AppUserDetails, @PathVariable id: UUID, @Valid @RequestBody body: UpdateFindingRequest) =
        FindingDetailResponse.of(service.triage(user.toCurrentUser(), id, body.triageStatus!!))
}

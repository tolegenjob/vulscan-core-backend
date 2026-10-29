package io.vulscan.core.api

import io.vulscan.core.application.ClaimOutcome
import io.vulscan.core.application.JobControlService
import io.vulscan.core.domain.ErrorCodes
import io.vulscan.core.domain.GoneException
import io.vulscan.core.domain.ValidationFailedException
import io.vulscan.core.security.ModuleWorker
import io.vulscan.kit.contracts.ClaimRequest
import io.vulscan.kit.contracts.ClaimResponse
import io.vulscan.kit.contracts.HeartbeatRequest
import io.vulscan.kit.contracts.HeartbeatResponse
import io.vulscan.kit.contracts.IdentityCredential
import org.springframework.http.CacheControl
import org.springframework.http.ResponseEntity
import org.springframework.security.core.annotation.AuthenticationPrincipal
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController
import java.util.UUID

/** Внутренний API для модулей обнаружения; доступен только по сервисному токену. */
@RestController
@RequestMapping("/internal/v1/jobs")
class InternalJobController(private val control: JobControlService) {

    @PostMapping("/{jobId}/claim")
    fun claim(@AuthenticationPrincipal worker: ModuleWorker, @PathVariable jobId: UUID, @RequestBody request: ClaimRequest): ClaimResponse {
        if (request.workerId != worker.workerId) throw ValidationFailedException("workerId does not match X-Worker-Id")
        return when (val outcome = control.claim(worker, jobId, request.attempt)) {
            is ClaimOutcome.Granted -> outcome.response
            ClaimOutcome.Cancelled -> throw GoneException(ErrorCodes.JOB_CANCELLED, "Scan was cancelled")
        }
    }

    @PostMapping("/{jobId}/heartbeat")
    fun heartbeat(@AuthenticationPrincipal worker: ModuleWorker, @PathVariable jobId: UUID, @RequestBody request: HeartbeatRequest): HeartbeatResponse =
        control.heartbeat(worker, jobId, request.attempt, request.requestsSent, request.endpointsDone)

    @GetMapping("/{jobId}/identities")
    fun identities(
        @AuthenticationPrincipal worker: ModuleWorker,
        @PathVariable jobId: UUID,
        @RequestParam attempt: Int,
    ): ResponseEntity<List<IdentityCredential>> =
        ResponseEntity.ok().cacheControl(CacheControl.noStore()).body(control.identitiesFor(worker, jobId, attempt))
}

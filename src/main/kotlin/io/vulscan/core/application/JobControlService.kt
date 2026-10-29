package io.vulscan.core.application

import io.vulscan.core.config.ScannerProperties
import io.vulscan.core.domain.ConflictException
import io.vulscan.core.domain.ErrorCodes
import io.vulscan.core.domain.ForbiddenException
import io.vulscan.core.domain.GoneException
import io.vulscan.core.domain.JobStateMachine
import io.vulscan.core.domain.JobStatus
import io.vulscan.core.domain.NotFoundException
import io.vulscan.core.domain.RateLimitedException
import io.vulscan.core.domain.ScanStatusAggregator
import io.vulscan.core.persistence.AuditEventRepository
import io.vulscan.core.persistence.ScanEntity
import io.vulscan.core.persistence.ScanJobEntity
import io.vulscan.core.persistence.ScanJobRepository
import io.vulscan.core.persistence.ScanRepository
import io.vulscan.core.persistence.TestIdentityRepository
import io.vulscan.core.security.EncryptedSecret
import io.vulscan.core.security.ModuleWorker
import io.vulscan.core.security.SecretCipher
import io.vulscan.kit.contracts.AuthSpec
import io.vulscan.kit.contracts.ClaimResponse
import io.vulscan.kit.contracts.HeartbeatResponse
import io.vulscan.kit.contracts.IdentityCredential
import io.vulscan.kit.contracts.Json
import io.vulscan.kit.contracts.ModuleType
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional
import java.time.Instant
import java.util.UUID

sealed interface ClaimOutcome {
    data class Granted(val response: ClaimResponse) : ClaimOutcome

    /** Скан отменён до начала работы: задание закрыто, модуль должен остановиться (HTTP 410). */
    data object Cancelled : ClaimOutcome
}

/** Управление выполнением заданий для модулей: захват, продление lease, выдача секретов. */
@Service
class JobControlService(
    private val jobs: ScanJobRepository,
    private val scans: ScanRepository,
    private val identities: TestIdentityRepository,
    private val audit: AuditService,
    private val auditEvents: AuditEventRepository,
    private val cipher: SecretCipher,
    private val properties: ScannerProperties,
    private val refresher: ScanStatusRefresher,
    private val metrics: io.vulscan.core.observability.Metrics,
) {

    @Transactional
    fun claim(worker: ModuleWorker, jobId: UUID, attempt: Int): ClaimOutcome {
        val scan = lockScanOf(worker, jobId)
        val leaseUntil = Instant.now().plusSeconds(properties.jobs.leaseSec.toLong())
        val rows = jobs.claim(jobId, attempt, worker.workerId, leaseUntil)
        val job = jobs.findById(jobId).orElseThrow { NotFoundException("Job not found") }
        if (rows == 0) {
            if (job.status == JobStatus.CANCELLED) throw GoneException(ErrorCodes.JOB_CANCELLED, "Job was cancelled")
            throw ConflictException("Job cannot be claimed (status ${job.status}, attempt ${job.attempt})", ErrorCodes.JOB_NOT_CLAIMABLE)
        }
        if (scan.cancelRequested) {
            cancelRunning(job)
            refresher.refresh(job.scanId)
            return ClaimOutcome.Cancelled
        }
        metrics.jobTransition(JobStatus.QUEUED, JobStatus.RUNNING)
        refresher.refresh(job.scanId)
        return ClaimOutcome.Granted(ClaimResponse(leaseUntil, HEARTBEAT_INTERVAL_SEC))
    }

    @Transactional
    fun heartbeat(worker: ModuleWorker, jobId: UUID, attempt: Int, requestsSent: Int, endpointsDone: Int): HeartbeatResponse {
        val scan = lockScanOf(worker, jobId)
        val leaseUntil = Instant.now().plusSeconds(properties.jobs.leaseSec.toLong())
        val rows = jobs.extendLease(jobId, attempt, worker.workerId, leaseUntil, requestsSent, endpointsDone)
        if (rows == 0) throw ConflictException("Lease is not held by this worker", ErrorCodes.LEASE_LOST)
        val job = jobs.findById(jobId).orElseThrow { NotFoundException("Job not found") }
        if (scan.cancelRequested) {
            cancelRunning(job)
            refresher.refresh(job.scanId)
            return HeartbeatResponse(cancel = true, leaseExpiresAt = leaseUntil)
        }
        return HeartbeatResponse(cancel = false, leaseExpiresAt = leaseUntil)
    }

    /** Расшифрованные учётные данные выдаются только IDOR-воркеру, владеющему lease, и не более [MAX_IDENTITY_CALLS] раз. */
    @Transactional
    fun identitiesFor(worker: ModuleWorker, jobId: UUID, attempt: Int): List<IdentityCredential> {
        val job = jobs.lockById(jobId) ?: throw NotFoundException("Job not found")
        if (worker.moduleType != ModuleType.IDOR || job.moduleType != ModuleType.IDOR) throw ForbiddenException()
        if (job.status != JobStatus.RUNNING || job.workerId != worker.workerId || job.attempt != attempt) throw ForbiddenException()
        if (auditEvents.countByActionAndSubjectId(ACTION_ISSUED, jobId) >= MAX_IDENTITY_CALLS) throw RateLimitedException(RETRY_AFTER_SEC)

        val scan = scans.findById(job.scanId).orElseThrow { NotFoundException("Scan not found") }
        val command = Json.mapper.convertValue(scan.config, ScanCommand::class.java)
        val ids = command.idor?.identityIds.orEmpty()
        val result = identities.findAllById(ids).filter { it.targetId == scan.targetId }.map { identity ->
            @Suppress("UNCHECKED_CAST")
            val secret = Json.read(String(cipher.decrypt(EncryptedSecret(identity.keyVersion, identity.secretEncrypted)), Charsets.UTF_8), Map::class.java) as Map<String, String>
            IdentityCredential(identity.id, identity.label, identity.role, AuthSpec(identity.authType, identity.authConfig, secret))
        }
        // В аудит не попадают ни секреты, ни их значения
        audit.record(ACTION_ISSUED, null, "JOB", jobId, mapOf("workerId" to worker.workerId, "attempt" to attempt, "count" to result.size))
        return result
    }

    /** Проверяет, что задание принадлежит модулю токена, и берёт блокировку скана (порядок: скан, затем задание). */
    private fun lockScanOf(worker: ModuleWorker, jobId: UUID): ScanEntity {
        val job = jobs.findById(jobId).orElseThrow { NotFoundException("Job not found") }
        if (job.moduleType != worker.moduleType) throw ForbiddenException()
        return scans.lockById(job.scanId) ?: throw NotFoundException("Scan not found")
    }

    private fun cancelRunning(job: ScanJobEntity) {
        JobStateMachine.transition(job.status, JobStatus.CANCELLED)
        metrics.jobTransition(job.status, JobStatus.CANCELLED)
        job.status = JobStatus.CANCELLED
        job.finishedAt = Instant.now()
        jobs.save(job)
    }

    companion object {
        const val HEARTBEAT_INTERVAL_SEC = 10
        const val MAX_IDENTITY_CALLS = 3L
        const val RETRY_AFTER_SEC = 60L
        const val ACTION_ISSUED = "IDENTITY_SECRETS_ISSUED"
    }
}

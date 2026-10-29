package io.vulscan.core.application

import io.vulscan.core.config.ScannerProperties
import io.vulscan.core.domain.JobStateMachine
import io.vulscan.core.domain.JobStatus
import io.vulscan.core.persistence.ScanJobEntity
import io.vulscan.core.persistence.ScanJobRepository
import io.vulscan.core.persistence.ScanRepository
import org.slf4j.LoggerFactory
import org.springframework.data.domain.PageRequest
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional
import java.time.Instant
import java.util.UUID

/**
 * Восстановление зависших заданий. Каждое действие выполняется в своей транзакции: блокируется скан, затем задание
 * (тот же порядок, что в остальном коде), условие проверяется заново, поэтому два экземпляра watchdog не удвоят действие.
 */
@Service
class JobRecoveryService(
    private val jobs: ScanJobRepository,
    private val scans: ScanRepository,
    private val requeuer: JobRequeuer,
    private val refresher: ScanStatusRefresher,
    private val properties: ScannerProperties,
) {
    private val log = LoggerFactory.getLogger(javaClass)

    fun lostLease(now: Instant, limit: Int): List<UUID> = jobs.findLostLease(now, PageRequest.ofSize(limit))

    fun staleQueued(now: Instant, limit: Int): List<UUID> =
        jobs.findStaleQueued(now.minusSeconds(properties.jobs.queueTimeoutSec.toLong()), PageRequest.ofSize(limit))

    fun pastDeadline(now: Instant, limit: Int): List<UUID> = jobs.findPastDeadline(now, PageRequest.ofSize(limit))

    /** RUNNING с истёкшим lease: повторный запуск, а при исчерпании попыток или отмене скана — финальный статус. */
    @Transactional
    fun recoverLostLease(jobId: UUID, now: Instant = Instant.now()): Boolean {
        val job = lock(jobId) ?: return false
        if (job.status != JobStatus.RUNNING || job.leaseExpiresAt?.isBefore(now) != true) return false
        val cancelRequested = scans.findById(job.scanId).map { it.cancelRequested }.orElse(false)
        when {
            cancelRequested -> finish(job, JobStatus.CANCELLED, null, null)
            job.attempt < properties.jobs.maxAttempts -> requeuer.requeue(job)
            else -> finish(job, JobStatus.FAILED, "HEARTBEAT_LOST", "Worker stopped sending heartbeats")
        }
        log.warn("Recovered job {} after lost lease (attempt {})", jobId, job.attempt)
        refresher.refresh(job.scanId)
        return true
    }

    /** QUEUED дольше queueTimeout: модуль не забрал задание. */
    @Transactional
    fun expireQueued(jobId: UUID, now: Instant = Instant.now()): Boolean {
        val job = lock(jobId) ?: return false
        val limit = now.minusSeconds(properties.jobs.queueTimeoutSec.toLong())
        if (job.status != JobStatus.QUEUED || job.queuedAt?.isBefore(limit) != true) return false
        if (job.attempt < properties.jobs.maxAttempts) {
            requeuer.requeue(job)
        } else {
            finish(job, JobStatus.FAILED, "QUEUE_TIMEOUT", "No worker picked up the job in time")
        }
        log.warn("Queued job {} timed out (attempt {})", jobId, job.attempt)
        refresher.refresh(job.scanId)
        return true
    }

    /** RUNNING после deadline: завершается без повтора, найденные ранее findings сохраняются. */
    @Transactional
    fun expireDeadline(jobId: UUID, now: Instant = Instant.now()): Boolean {
        val job = lock(jobId) ?: return false
        if (job.status != JobStatus.RUNNING || !job.deadlineAt.isBefore(now)) return false
        finish(job, JobStatus.FAILED, "DEADLINE_EXCEEDED", "Job exceeded its deadline")
        log.warn("Job {} exceeded its deadline", jobId)
        refresher.refresh(job.scanId)
        return true
    }

    private fun lock(jobId: UUID): ScanJobEntity? {
        val scanId = jobs.findById(jobId).orElse(null)?.scanId ?: return null
        scans.lockById(scanId) ?: return null
        return jobs.lockById(jobId)
    }

    private fun finish(job: ScanJobEntity, status: JobStatus, code: String?, message: String?) {
        JobStateMachine.transition(job.status, status)
        job.status = status
        job.finishedAt = Instant.now()
        job.errorCode = code
        job.errorMessage = message
        jobs.save(job)
    }
}

package io.vulscan.core.application

import io.vulscan.core.config.ScannerProperties
import io.vulscan.core.domain.JobStateMachine
import io.vulscan.core.domain.JobStatus
import io.vulscan.core.domain.ResultIntegrity
import io.vulscan.core.persistence.FindingRepository
import io.vulscan.core.persistence.ProcessedMessageRepository
import io.vulscan.core.persistence.ScanRepository
import io.vulscan.core.persistence.ScanJobRepository
import io.vulscan.kit.contracts.FindingReportedPayload
import io.vulscan.kit.contracts.JobCompletedPayload
import io.vulscan.kit.contracts.JobFailedPayload
import io.vulscan.kit.contracts.Json
import io.vulscan.kit.contracts.MessageType
import io.vulscan.kit.contracts.RawEnvelope
import org.slf4j.LoggerFactory
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional
import java.time.Instant
import java.util.UUID

sealed interface ResultOutcome {
    data object Applied : ResultOutcome

    data object Duplicate : ResultOutcome

    /** Сообщение валидно, но не относится к текущему состоянию (устаревшая попытка, терминальное задание). */
    data class Ignored(val reason: String) : ResultOutcome

    /** Сообщение нельзя обработать никогда; его нужно отправить в DLQ. */
    data class Dead(val reason: String, val detail: String? = null) : ResultOutcome
}

/** Обработка событий модулей. Каждое сообщение применяется в одной транзакции вместе с записью о дедупликации. */
@Service
class JobResultService(
    private val jobs: ScanJobRepository,
    private val scans: ScanRepository,
    private val findings: FindingRepository,
    private val processed: ProcessedMessageRepository,
    private val refresher: ScanStatusRefresher,
    private val requeuer: JobRequeuer,
    private val audit: AuditService,
    private val properties: ScannerProperties,
    private val metrics: io.vulscan.core.observability.Metrics,
) {
    private val log = LoggerFactory.getLogger(javaClass)

    @Transactional
    fun handle(rawValue: String?): ResultOutcome {
        if (rawValue.isNullOrBlank()) return ResultOutcome.Dead(INVALID_ENVELOPE, "empty message")
        val envelope = try {
            Json.readEnvelope(rawValue)
        } catch (e: Exception) {
            return ResultOutcome.Dead(INVALID_ENVELOPE, e.javaClass.simpleName)
        }
        val parsed = try {
            when (envelope.type) {
                MessageType.FINDING_REPORTED -> Json.payloadAs(envelope, FindingReportedPayload::class.java)
                MessageType.JOB_COMPLETED -> Json.payloadAs(envelope, JobCompletedPayload::class.java)
                MessageType.JOB_FAILED -> Json.payloadAs(envelope, JobFailedPayload::class.java)
                MessageType.SCAN_JOB -> return ResultOutcome.Dead(UNEXPECTED_TYPE, envelope.type.name)
            }
        } catch (e: Exception) {
            return ResultOutcome.Dead(INVALID_PAYLOAD, e.javaClass.simpleName)
        }
        if (processed.markProcessed(envelope.messageId, CONSUMER) == 0) return ResultOutcome.Duplicate
        return when (parsed) {
            is FindingReportedPayload -> onFinding(parsed)
            is JobCompletedPayload -> onCompleted(parsed)
            is JobFailedPayload -> onFailed(parsed)
            else -> ResultOutcome.Dead(UNEXPECTED_TYPE)
        }
    }

    private fun onFinding(p: FindingReportedPayload): ResultOutcome {
        val job = jobs.findById(p.jobId).orElse(null) ?: return ResultOutcome.Dead(UNKNOWN_JOB, p.jobId.toString())
        if (p.attempt > job.attempt) return ResultOutcome.Dead(INVALID_FINDING, "attempt from the future")
        val f = p.finding
        if (f.moduleType != job.moduleType) return ResultOutcome.Dead(INVALID_FINDING, "module mismatch")
        if (f.confidence !in 1..99) return ResultOutcome.Dead(INVALID_FINDING, "confidence out of range")
        if (!FINGERPRINT.matches(f.fingerprint)) return ResultOutcome.Dead(INVALID_FINDING, "bad fingerprint")
        val evidence = Json.write(f.evidence)
        val details = Json.write(f.details)
        if (evidence.toByteArray().size > MAX_JSON_BYTES || details.toByteArray().size > MAX_JSON_BYTES) {
            return ResultOutcome.Dead(INVALID_FINDING, "evidence too large")
        }
        val targetId = scans.findById(job.scanId).orElse(null)?.targetId ?: return ResultOutcome.Dead(UNKNOWN_JOB, p.jobId.toString())
        // target_id и scan_id берутся из задания, а не из сообщения
        findings.insertIgnore(
            UUID.randomUUID(), job.id, job.scanId, targetId, f.moduleType.name, f.vulnType.name, f.verdict.name, f.severity.name,
            f.confidence, f.fingerprint, f.endpointId, f.method.name, f.url, f.parameter?.name, f.parameter?.location?.name,
            f.title, f.summary, f.recommendation, f.cwe, details, evidence,
        )
        return ResultOutcome.Applied
    }

    private fun onCompleted(p: JobCompletedPayload): ResultOutcome {
        val job = jobs.findById(p.jobId).orElse(null) ?: return ResultOutcome.Dead(UNKNOWN_JOB, p.jobId.toString())
        if (p.attempt != job.attempt) return ResultOutcome.Ignored("stale attempt")
        if (job.status != JobStatus.RUNNING) return ResultOutcome.Ignored("job is ${job.status}")
        JobStateMachine.transition(job.status, JobStatus.COMPLETED)
        metrics.jobTransition(job.status, JobStatus.COMPLETED)
        job.status = JobStatus.COMPLETED
        job.finishedAt = Instant.now()
        job.stats = p.stats
        job.requestsSent = p.stats.requestsSent
        job.endpointsDone = p.stats.endpointsTested
        val stored = findings.countByJobId(job.id)
        if (stored < p.stats.findingsCount) {
            job.resultIntegrity = ResultIntegrity.INCOMPLETE
            audit.record("RESULT_INCOMPLETE", null, "JOB", job.id, mapOf("reported" to p.stats.findingsCount, "stored" to stored))
        }
        jobs.save(job)
        refresher.refresh(job.scanId)
        return ResultOutcome.Applied
    }

    private fun onFailed(p: JobFailedPayload): ResultOutcome {
        val job = jobs.findById(p.jobId).orElse(null) ?: return ResultOutcome.Dead(UNKNOWN_JOB, p.jobId.toString())
        if (p.attempt != job.attempt) return ResultOutcome.Ignored("stale attempt")
        if (job.status != JobStatus.RUNNING) return ResultOutcome.Ignored("job is ${job.status}")
        if (p.retryable && job.attempt < properties.jobs.maxAttempts) {
            requeuer.requeue(job)
            log.info("Job {} requeued after {} (attempt {})", job.id, p.errorCode, job.attempt)
        } else {
            JobStateMachine.transition(job.status, JobStatus.FAILED)
            metrics.jobTransition(job.status, JobStatus.FAILED)
            job.status = JobStatus.FAILED
            job.finishedAt = Instant.now()
            job.errorCode = p.errorCode.name
            job.errorMessage = p.message.take(MAX_MESSAGE)
            p.stats?.let {
                job.stats = it
                job.requestsSent = it.requestsSent
            }
            jobs.save(job)
        }
        refresher.refresh(job.scanId)
        return ResultOutcome.Applied
    }

    companion object {
        const val CONSUMER = "core-results"
        const val INVALID_ENVELOPE = "INVALID_ENVELOPE"
        const val INVALID_PAYLOAD = "INVALID_PAYLOAD"
        const val INVALID_FINDING = "INVALID_FINDING"
        const val UNEXPECTED_TYPE = "UNEXPECTED_TYPE"
        const val UNKNOWN_JOB = "UNKNOWN_JOB"
        private const val MAX_JSON_BYTES = 16 * 1024
        private const val MAX_MESSAGE = 500
        private val FINGERPRINT = Regex("^[0-9a-f]{64}$")
    }
}

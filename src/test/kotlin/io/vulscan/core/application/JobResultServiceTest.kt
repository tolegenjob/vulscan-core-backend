package io.vulscan.core.application

import io.vulscan.core.domain.JobStatus
import io.vulscan.core.domain.ResultIntegrity
import io.vulscan.core.domain.ScanStatus
import io.vulscan.core.persistence.OutboxEventEntity
import io.vulscan.core.persistence.OutboxEventRepository
import io.vulscan.core.persistence.PersistenceTestBase
import io.vulscan.core.support.ResultMessages
import io.vulscan.kit.contracts.JobErrorCode
import io.vulscan.kit.contracts.KafkaTopics
import io.vulscan.kit.contracts.ModuleType
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import java.time.Instant
import java.util.UUID

class JobResultServiceTest : PersistenceTestBase() {
    @Autowired lateinit var service: JobResultService
    @Autowired lateinit var outbox: OutboxEventRepository

    private fun runningJob(attempt: Int = 1): Chain {
        val chain = newChain()
        val job = jobs.findById(chain.jobId).orElseThrow()
        job.status = JobStatus.RUNNING
        job.attempt = attempt
        job.workerId = "w-1"
        jobs.saveAndFlush(job)
        outbox.saveAndFlush(
            OutboxEventEntity(
                aggregateId = chain.jobId, topic = KafkaTopics.jobsFor(ModuleType.XSS), messageKey = chain.jobId.toString(),
                payload = mapOf(
                    "schemaVersion" to 1, "messageId" to UUID.randomUUID().toString(), "type" to "SCAN_JOB",
                    "correlationId" to UUID.randomUUID().toString(), "occurredAt" to Instant.now().toString(),
                    "payload" to mapOf("jobId" to chain.jobId.toString(), "attempt" to 1),
                ),
                headers = mapOf("type" to "SCAN_JOB"), status = io.vulscan.core.domain.OutboxStatus.SENT,
            ),
        )
        return chain
    }

    private fun outboxCount(jobId: UUID) = outbox.findAll().count { it.aggregateId == jobId }

    @Test
    fun `retryable failure on the first attempt requeues the job`() {
        val c = runningJob(attempt = 1)
        val outcome = service.handle(ResultMessages.failed(c.jobId, attempt = 1, retryable = true, code = JobErrorCode.TARGET_UNREACHABLE))
        assertThat(outcome).isEqualTo(ResultOutcome.Applied)
        val job = jobs.findById(c.jobId).orElseThrow()
        assertThat(job.status).isEqualTo(JobStatus.QUEUED)
        assertThat(job.attempt).isEqualTo(2)
        assertThat(job.workerId).isNull()
        val created = outbox.findAll().filter { it.aggregateId == c.jobId && it.status.name == "PENDING" }
        assertThat(created).hasSize(1)
        @Suppress("UNCHECKED_CAST")
        assertThat((created.single().payload["payload"] as Map<String, Any?>)["attempt"]).isEqualTo(2)
    }

    @Test
    fun `retryable failure on the last attempt fails the job`() {
        val c = runningJob(attempt = 2)
        service.handle(ResultMessages.failed(c.jobId, attempt = 2, retryable = true))
        val job = jobs.findById(c.jobId).orElseThrow()
        assertThat(job.status).isEqualTo(JobStatus.FAILED)
        assertThat(job.errorCode).isEqualTo("INTERNAL_ERROR")
        assertThat(outboxCount(c.jobId)).isEqualTo(1)
        assertThat(scans.findById(c.scanId).orElseThrow().status).isEqualTo(ScanStatus.FAILED)
    }

    @Test
    fun `non retryable failure fails the job without outbox`() {
        val c = runningJob()
        service.handle(ResultMessages.failed(c.jobId, retryable = false))
        assertThat(jobs.findById(c.jobId).orElseThrow().status).isEqualTo(JobStatus.FAILED)
        assertThat(outboxCount(c.jobId)).isEqualTo(1)
    }

    @Test
    fun `completion of a stale attempt is ignored`() {
        val c = runningJob(attempt = 2)
        val outcome = service.handle(ResultMessages.completed(c.jobId, attempt = 1))
        assertThat(outcome).isInstanceOf(ResultOutcome.Ignored::class.java)
        assertThat(jobs.findById(c.jobId).orElseThrow().status).isEqualTo(JobStatus.RUNNING)
    }

    @Test
    fun `completion marks the job and the scan completed`() {
        val c = runningJob()
        service.handle(ResultMessages.finding(c.jobId))
        service.handle(ResultMessages.completed(c.jobId, findingsCount = 1))
        val job = jobs.findById(c.jobId).orElseThrow()
        assertThat(job.status).isEqualTo(JobStatus.COMPLETED)
        assertThat(job.resultIntegrity).isEqualTo(ResultIntegrity.OK)
        assertThat(job.stats!!.requestsSent).isEqualTo(10)
        assertThat(scans.findById(c.scanId).orElseThrow().status).isEqualTo(ScanStatus.COMPLETED)
    }

    @Test
    fun `finding takes target and scan from the job and rejects invalid data`() {
        val c = runningJob()
        assertThat(service.handle(ResultMessages.finding(c.jobId))).isEqualTo(ResultOutcome.Applied)
        val saved = findings.findAll().single { it.jobId == c.jobId }
        assertThat(saved.scanId).isEqualTo(c.scanId)
        assertThat(saved.targetId).isEqualTo(c.targetId)
        assertThat(saved.parameterName).isEqualTo("q")

        assertThat(service.handle(ResultMessages.finding(c.jobId, confidence = 100))).isInstanceOf(ResultOutcome.Dead::class.java)
        assertThat(service.handle(ResultMessages.finding(c.jobId, fingerprint = "not-a-fingerprint"))).isInstanceOf(ResultOutcome.Dead::class.java)
        assertThat(service.handle(ResultMessages.finding(c.jobId, module = ModuleType.SQLI))).isInstanceOf(ResultOutcome.Dead::class.java)
        val unknown = service.handle(ResultMessages.finding(UUID.randomUUID()))
        assertThat(unknown).isInstanceOf(ResultOutcome.Dead::class.java)
        assertThat((unknown as ResultOutcome.Dead).reason).isEqualTo(JobResultService.UNKNOWN_JOB)
        assertThat(findings.findAll().count { it.jobId == c.jobId }).isEqualTo(1)
    }

    @Test
    fun `late finding after failure is still stored without changing the job`() {
        val c = runningJob()
        service.handle(ResultMessages.failed(c.jobId))
        assertThat(service.handle(ResultMessages.finding(c.jobId))).isEqualTo(ResultOutcome.Applied)
        assertThat(jobs.findById(c.jobId).orElseThrow().status).isEqualTo(JobStatus.FAILED)
        assertThat(findings.findAll().count { it.jobId == c.jobId }).isEqualTo(1)
    }

    @Test
    fun `garbage is dead lettered`() {
        assertThat(service.handle("{not json")).isInstanceOf(ResultOutcome.Dead::class.java)
        assertThat(service.handle(null)).isInstanceOf(ResultOutcome.Dead::class.java)
        assertThat(service.handle("""{"schemaVersion":1}""")).isInstanceOf(ResultOutcome.Dead::class.java)
    }
}

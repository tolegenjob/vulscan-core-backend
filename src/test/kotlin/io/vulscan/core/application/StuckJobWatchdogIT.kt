package io.vulscan.core.application

import io.vulscan.core.domain.JobStatus
import io.vulscan.core.domain.OutboxStatus
import io.vulscan.core.domain.ScanStatus
import io.vulscan.core.persistence.OutboxEventEntity
import io.vulscan.core.persistence.OutboxEventRepository
import io.vulscan.core.persistence.PersistenceTestBase
import io.vulscan.core.scheduling.StuckJobWatchdog
import io.vulscan.kit.contracts.KafkaTopics
import io.vulscan.kit.contracts.ModuleType
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import java.time.Instant
import java.util.UUID
import java.util.concurrent.Callable
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

class StuckJobWatchdogIT : PersistenceTestBase() {
    @Autowired lateinit var watchdog: StuckJobWatchdog
    @Autowired lateinit var recovery: JobRecoveryService
    @Autowired lateinit var outbox: OutboxEventRepository

    private fun job(
        status: JobStatus,
        attempt: Int = 1,
        leaseExpired: Boolean = false,
        queuedAgoSec: Long? = null,
        deadlineInSec: Long = 600,
    ): Chain {
        val chain = newChain()
        val j = jobs.findById(chain.jobId).orElseThrow()
        j.status = status
        j.attempt = attempt
        j.workerId = if (status == JobStatus.RUNNING) "w-1" else null
        j.leaseExpiresAt = if (status == JobStatus.RUNNING) Instant.now().plusSeconds(if (leaseExpired) -30 else 60) else null
        j.queuedAt = queuedAgoSec?.let { Instant.now().minusSeconds(it) }
        j.deadlineAt = Instant.now().plusSeconds(deadlineInSec)
        jobs.saveAndFlush(j)
        outbox.saveAndFlush(
            OutboxEventEntity(
                aggregateId = chain.jobId, topic = KafkaTopics.jobsFor(ModuleType.XSS), messageKey = chain.jobId.toString(),
                payload = mapOf(
                    "schemaVersion" to 1, "messageId" to UUID.randomUUID().toString(), "type" to "SCAN_JOB",
                    "correlationId" to UUID.randomUUID().toString(), "occurredAt" to Instant.now().toString(),
                    "payload" to mapOf("jobId" to chain.jobId.toString(), "attempt" to attempt),
                ),
                headers = mapOf("type" to "SCAN_JOB"), status = OutboxStatus.SENT,
            ),
        )
        return chain
    }

    private fun pendingOutbox(jobId: UUID) = outbox.findAll().filter { it.aggregateId == jobId && it.status == OutboxStatus.PENDING }

    @Test
    fun `lost lease on the first attempt requeues the job with a new outbox message`() {
        val c = job(JobStatus.RUNNING, attempt = 1, leaseExpired = true)
        assertThat(watchdog.runOnce()).isGreaterThanOrEqualTo(1)
        val after = jobs.findById(c.jobId).orElseThrow()
        assertThat(after.status).isEqualTo(JobStatus.QUEUED)
        assertThat(after.attempt).isEqualTo(2)
        assertThat(after.workerId).isNull()
        val created = pendingOutbox(c.jobId)
        assertThat(created).hasSize(1)
        @Suppress("UNCHECKED_CAST")
        assertThat((created.single().payload["payload"] as Map<String, Any?>)["attempt"]).isEqualTo(2)
    }

    @Test
    fun `lost lease on the last attempt fails the job`() {
        val c = job(JobStatus.RUNNING, attempt = 2, leaseExpired = true)
        watchdog.runOnce()
        val after = jobs.findById(c.jobId).orElseThrow()
        assertThat(after.status).isEqualTo(JobStatus.FAILED)
        assertThat(after.errorCode).isEqualTo("HEARTBEAT_LOST")
        assertThat(pendingOutbox(c.jobId)).isEmpty()
        assertThat(scans.findById(c.scanId).orElseThrow().status).isEqualTo(ScanStatus.FAILED)
    }

    @Test
    fun `healthy running job is left alone`() {
        val c = job(JobStatus.RUNNING, leaseExpired = false)
        watchdog.runOnce()
        assertThat(jobs.findById(c.jobId).orElseThrow().status).isEqualTo(JobStatus.RUNNING)
    }

    @Test
    fun `queued job older than the timeout is retried then failed`() {
        val first = job(JobStatus.QUEUED, attempt = 1, queuedAgoSec = 100_000)
        watchdog.runOnce()
        val retried = jobs.findById(first.jobId).orElseThrow()
        assertThat(retried.status).isEqualTo(JobStatus.QUEUED)
        assertThat(retried.attempt).isEqualTo(2)
        assertThat(pendingOutbox(first.jobId)).hasSize(1)

        val last = job(JobStatus.QUEUED, attempt = 2, queuedAgoSec = 100_000)
        watchdog.runOnce()
        val failed = jobs.findById(last.jobId).orElseThrow()
        assertThat(failed.status).isEqualTo(JobStatus.FAILED)
        assertThat(failed.errorCode).isEqualTo("QUEUE_TIMEOUT")

        val fresh = job(JobStatus.QUEUED, queuedAgoSec = 5)
        watchdog.runOnce()
        assertThat(jobs.findById(fresh.jobId).orElseThrow().status).isEqualTo(JobStatus.QUEUED)
        assertThat(jobs.findById(fresh.jobId).orElseThrow().attempt).isEqualTo(1)
    }

    @Test
    fun `job past its deadline fails without a retry`() {
        val c = job(JobStatus.RUNNING, attempt = 1, leaseExpired = true, deadlineInSec = -10)
        watchdog.runOnce()
        val after = jobs.findById(c.jobId).orElseThrow()
        assertThat(after.status).isEqualTo(JobStatus.FAILED)
        assertThat(after.errorCode).isEqualTo("DEADLINE_EXCEEDED")
        assertThat(pendingOutbox(c.jobId)).isEmpty()
    }

    @Test
    fun `lost lease of a cancelled scan cancels the job instead of restarting it`() {
        val c = job(JobStatus.RUNNING, attempt = 1, leaseExpired = true)
        val scan = scans.findById(c.scanId).orElseThrow()
        scan.cancelRequested = true
        scan.status = ScanStatus.CANCELLING
        scans.saveAndFlush(scan)
        watchdog.runOnce()
        assertThat(jobs.findById(c.jobId).orElseThrow().status).isEqualTo(JobStatus.CANCELLED)
        assertThat(scans.findById(c.scanId).orElseThrow().status).isEqualTo(ScanStatus.CANCELLED)
        assertThat(pendingOutbox(c.jobId)).isEmpty()
    }

    @Test
    fun `two watchdogs acting at once recover the job once`() {
        val c = job(JobStatus.RUNNING, attempt = 1, leaseExpired = true)
        val pool = Executors.newFixedThreadPool(2)
        val start = CountDownLatch(1)
        val futures = (1..2).map {
            pool.submit(Callable { start.await(); recovery.recoverLostLease(c.jobId) })
        }
        start.countDown()
        val results = futures.map { it.get(30, TimeUnit.SECONDS) }
        pool.shutdown()
        assertThat(results.count { it }).isEqualTo(1)
        assertThat(jobs.findById(c.jobId).orElseThrow().attempt).isEqualTo(2)
        assertThat(pendingOutbox(c.jobId)).hasSize(1)
    }
}

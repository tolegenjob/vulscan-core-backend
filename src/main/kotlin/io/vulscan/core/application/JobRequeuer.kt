package io.vulscan.core.application

import io.vulscan.core.domain.JobStateMachine
import io.vulscan.core.domain.JobStatus
import io.vulscan.core.messaging.OutboxEventFactory
import io.vulscan.core.persistence.OutboxEventRepository
import io.vulscan.core.persistence.ScanJobEntity
import io.vulscan.core.persistence.ScanJobRepository
import org.springframework.stereotype.Component
import java.time.Instant

/** Возвращает задание в очередь с новой попыткой: статус QUEUED, attempt+1 и новое сообщение в outbox. */
@Component
class JobRequeuer(private val jobs: ScanJobRepository, private val outbox: OutboxEventRepository) {

    fun requeue(job: ScanJobEntity) {
        JobStateMachine.transition(job.status, JobStatus.QUEUED)
        val previous = outbox.findFirstByAggregateIdOrderByCreatedAtDesc(job.id)
            ?: throw IllegalStateException("No outbox message found for job ${job.id}")
        job.status = JobStatus.QUEUED
        job.attempt += 1
        job.workerId = null
        job.leaseExpiresAt = null
        job.queuedAt = Instant.now()
        jobs.save(job)
        outbox.save(OutboxEventFactory.retryOf(previous, job.attempt))
    }
}

package io.vulscan.core.messaging

import io.vulscan.core.config.ScannerProperties
import io.vulscan.core.domain.JobStateMachine
import io.vulscan.core.domain.JobStatus
import io.vulscan.core.domain.OutboxStatus
import io.vulscan.core.domain.ScanStatusAggregator
import io.vulscan.core.persistence.OutboxEventEntity
import io.vulscan.core.persistence.OutboxEventRepository
import io.vulscan.core.persistence.ScanJobRepository
import io.vulscan.core.persistence.ScanRepository
import io.vulscan.kit.contracts.Envelope
import io.vulscan.kit.contracts.Json
import io.vulscan.kit.contracts.KafkaTopics
import io.vulscan.kit.contracts.MessageType
import io.vulscan.kit.contracts.ModuleType
import io.vulscan.kit.contracts.ScanJobPayload
import org.slf4j.LoggerFactory
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty
import org.springframework.context.annotation.Configuration
import org.springframework.kafka.config.TopicBuilder
import org.springframework.kafka.core.KafkaAdmin
import org.springframework.kafka.core.KafkaTemplate
import org.springframework.scheduling.annotation.EnableScheduling
import org.springframework.scheduling.annotation.Scheduled
import org.springframework.stereotype.Component
import org.springframework.transaction.support.TransactionTemplate
import java.time.Instant
import java.util.UUID
import java.util.concurrent.TimeUnit
import org.springframework.context.annotation.Bean
import org.apache.kafka.clients.admin.NewTopic

/** Создание outbox-записей для сообщений Core -> модули. */
object OutboxEventFactory {
    const val TYPE_HEADER = "type"

    @Suppress("UNCHECKED_CAST")
    fun jobMessage(payload: ScanJobPayload, correlationId: UUID): OutboxEventEntity {
        val envelope = Envelope(type = MessageType.SCAN_JOB, correlationId = correlationId, payload = payload)
        return OutboxEventEntity(
            aggregateId = payload.jobId,
            topic = KafkaTopics.jobsFor(payload.moduleType),
            messageKey = payload.jobId.toString(),
            payload = Json.mapper.convertValue(envelope, Map::class.java) as Map<String, Any?>,
            headers = mapOf(TYPE_HEADER to MessageType.SCAN_JOB.name, "correlationId" to correlationId.toString()),
            nextAttemptAt = Instant.now(),
        )
    }

    /** Копия сообщения задания для новой попытки: новый messageId, тот же jobId, `attempt` увеличен. */
    @Suppress("UNCHECKED_CAST")
    fun retryOf(previous: OutboxEventEntity, attempt: Int): OutboxEventEntity {
        val envelope = previous.payload.toMutableMap()
        envelope["messageId"] = UUID.randomUUID().toString()
        envelope["occurredAt"] = Instant.now().toString()
        val inner = (envelope["payload"] as Map<String, Any?>).toMutableMap()
        inner["attempt"] = attempt
        envelope["payload"] = inner
        return OutboxEventEntity(
            aggregateId = previous.aggregateId, topic = previous.topic, messageKey = previous.messageKey,
            payload = envelope, headers = previous.headers, nextAttemptAt = Instant.now(),
        )
    }

    fun serializedSize(payload: ScanJobPayload, correlationId: UUID): Int =
        Json.write(Envelope(type = MessageType.SCAN_JOB, correlationId = correlationId, payload = payload)).toByteArray().size
}

fun interface OutboxSender {
    /** Отправляет сообщение и ждёт подтверждения брокера; при неудаче бросает исключение. */
    fun send(topic: String, key: String, value: String)
}

@Component
class KafkaOutboxSender(private val kafka: KafkaTemplate<String, String>) : OutboxSender {
    override fun send(topic: String, key: String, value: String) {
        kafka.send(topic, key, value).get(5, TimeUnit.SECONDS)
    }
}

/** Публикует записи outbox в Kafka. Безопасен для нескольких экземпляров благодаря FOR UPDATE SKIP LOCKED. */
class OutboxRelay(
    private val outbox: OutboxEventRepository,
    private val jobs: ScanJobRepository,
    private val scans: ScanRepository,
    private val tx: TransactionTemplate,
    private val sender: OutboxSender,
    private val batchSize: Int = 50,
    /** Хук для тестов: вызывается после отправки и до фиксации транзакции. */
    var afterSend: () -> Unit = {},
) {
    private val log = LoggerFactory.getLogger(OutboxRelay::class.java)

    /** @return число опубликованных сообщений. */
    fun publishBatch(): Int = tx.execute { publishInTransaction() } ?: 0

    private fun publishInTransaction(): Int {
        val pending = outbox.lockPending(batchSize)
        var sent = 0
        for (event in pending) {
            try {
                sender.send(event.topic, event.messageKey, Json.write(event.payload))
                afterSend()
            } catch (e: Exception) {
                event.attempts += 1
                event.nextAttemptAt = Instant.now().plusSeconds(minOf(1L shl minOf(event.attempts, 6), 60L))
                outbox.save(event)
                log.warn("Outbox event {} was not published (attempt {}): {}", event.id, event.attempts, e.javaClass.simpleName)
                break
            }
            event.status = OutboxStatus.SENT
            event.sentAt = Instant.now()
            outbox.save(event)
            if (event.headers[OutboxEventFactory.TYPE_HEADER] == MessageType.SCAN_JOB.name) markQueued(event.aggregateId)
            sent++
        }
        return sent
    }

    private fun markQueued(jobId: UUID) {
        val scanId = jobs.findScanId(jobId) ?: return
        val scan = scans.lockById(scanId) ?: return
        val job = jobs.findById(jobId).orElse(null) ?: return
        // Повторная публикация не должна менять уже продвинувшееся задание
        if (job.status != JobStatus.PENDING) return
        JobStateMachine.transition(job.status, JobStatus.QUEUED)
        job.status = JobStatus.QUEUED
        job.queuedAt = Instant.now()
        jobs.save(job)
        scan.status = ScanStatusAggregator.aggregate(jobs.findByScanId(scan.id).map { it.status }, scan.cancelRequested)
        scans.save(scan)
    }
}

@Configuration
@EnableScheduling
class OutboxConfig {
    @Bean
    fun outboxRelay(
        outbox: OutboxEventRepository,
        jobs: ScanJobRepository,
        scans: ScanRepository,
        tx: TransactionTemplate,
        sender: OutboxSender,
        properties: ScannerProperties,
    ) = OutboxRelay(outbox, jobs, scans, tx, sender, properties.outbox.batchSize)

    @Bean
    fun topics(): KafkaAdmin.NewTopics {
        val names = ModuleType.entries.map { KafkaTopics.jobsFor(it) } + listOf(KafkaTopics.JOB_EVENTS, KafkaTopics.DLQ)
        return KafkaAdmin.NewTopics(*names.map { TopicBuilder.name(it).partitions(1).replicas(1).build() }.toTypedArray<NewTopic>())
    }
}

@Component
@ConditionalOnProperty(name = ["scanner.outbox.enabled"], havingValue = "true", matchIfMissing = true)
class OutboxScheduler(private val relay: OutboxRelay) {
    private val log = LoggerFactory.getLogger(OutboxScheduler::class.java)

    @Scheduled(fixedDelayString = "\${scanner.outbox.poll-ms:500}")
    fun poll() {
        try {
            relay.publishBatch()
        } catch (e: Exception) {
            log.error("Outbox poll failed", e)
        }
    }
}

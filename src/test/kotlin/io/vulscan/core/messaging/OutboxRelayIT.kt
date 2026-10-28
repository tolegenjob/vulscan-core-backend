package io.vulscan.core.messaging

import io.vulscan.core.domain.JobStatus
import io.vulscan.core.domain.OutboxStatus
import io.vulscan.core.persistence.OutboxEventEntity
import io.vulscan.core.persistence.OutboxEventRepository
import io.vulscan.core.persistence.PersistenceTestBase
import io.vulscan.core.persistence.ScanJobRepository
import io.vulscan.core.persistence.ScanRepository
import io.vulscan.kit.contracts.KafkaTopics
import io.vulscan.kit.contracts.ModuleType
import org.apache.kafka.clients.consumer.ConsumerConfig
import org.apache.kafka.clients.consumer.KafkaConsumer
import org.apache.kafka.common.serialization.StringDeserializer
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.transaction.support.TransactionTemplate
import java.time.Duration
import java.time.Instant
import java.util.Properties
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors

class OutboxRelayIT : PersistenceTestBase() {
    @Autowired lateinit var outbox: OutboxEventRepository
    @Autowired lateinit var scanJobs: ScanJobRepository
    @Autowired lateinit var scanRepo: ScanRepository
    @Autowired lateinit var tx: TransactionTemplate
    @Autowired lateinit var sender: OutboxSender
    @Autowired lateinit var kafkaContainer: org.testcontainers.kafka.KafkaContainer
    private val bootstrap get() = kafkaContainer.bootstrapServers

    private fun relay(batch: Int = 50, s: OutboxSender = sender) = OutboxRelay(outbox, scanJobs, scanRepo, tx, s, batch)

    private fun event(chain: Chain): OutboxEventEntity = outbox.saveAndFlush(
        OutboxEventEntity(
            aggregateId = chain.jobId, topic = KafkaTopics.jobsFor(ModuleType.XSS), messageKey = chain.jobId.toString(),
            payload = mapOf("jobId" to chain.jobId.toString()), headers = mapOf("type" to "SCAN_JOB"), nextAttemptAt = Instant.now(),
        ),
    )

    private fun countByKey(keys: Set<String>, waitSec: Long = 8): Map<String, Int> {
        val consumer = KafkaConsumer<String, String>(
            Properties().apply {
                put(ConsumerConfig.BOOTSTRAP_SERVERS_CONFIG, bootstrap)
                put(ConsumerConfig.GROUP_ID_CONFIG, "it-" + UUID.randomUUID())
                put(ConsumerConfig.KEY_DESERIALIZER_CLASS_CONFIG, StringDeserializer::class.java.name)
                put(ConsumerConfig.VALUE_DESERIALIZER_CLASS_CONFIG, StringDeserializer::class.java.name)
                put(ConsumerConfig.AUTO_OFFSET_RESET_CONFIG, "earliest")
            },
        )
        val counts = mutableMapOf<String, Int>()
        consumer.use {
            it.subscribe(listOf(KafkaTopics.jobsFor(ModuleType.XSS)))
            val end = System.currentTimeMillis() + waitSec * 1000
            while (System.currentTimeMillis() < end) {
                it.poll(Duration.ofMillis(300)).forEach { r -> if (r.key() in keys) counts.merge(r.key(), 1, Int::plus) }
            }
        }
        return counts
    }

    @Test
    fun `pending event is published and job becomes queued`() {
        val chain = newChain()
        val ev = event(chain)
        relay().publishBatch()
        assertThat(outbox.findById(ev.id).orElseThrow().status).isEqualTo(OutboxStatus.SENT)
        assertThat(scanJobs.findById(chain.jobId).orElseThrow().status).isEqualTo(JobStatus.QUEUED)
        assertThat(countByKey(setOf(chain.jobId.toString()))[chain.jobId.toString()]).isEqualTo(1)
    }

    @Test
    fun `failed send keeps the event pending and backs off`() {
        val chain = newChain()
        val ev = event(chain)
        val failing = OutboxSender { _, _, _ -> throw IllegalStateException("kafka down") }
        relay(s = failing).publishBatch()
        val after = outbox.findById(ev.id).orElseThrow()
        assertThat(after.status).isEqualTo(OutboxStatus.PENDING)
        assertThat(after.attempts).isEqualTo(1)
        assertThat(after.nextAttemptAt).isAfter(Instant.now())
        assertThat(scanJobs.findById(chain.jobId).orElseThrow().status).isEqualTo(JobStatus.PENDING)

        // после восстановления событие публикуется
        after.nextAttemptAt = Instant.now().minusSeconds(1)
        outbox.saveAndFlush(after)
        relay().publishBatch()
        assertThat(outbox.findById(ev.id).orElseThrow().status).isEqualTo(OutboxStatus.SENT)
    }

    @Test
    fun `parallel relays publish every event exactly once`() {
        val chains = (1..6).map { newChain() }
        chains.forEach { event(it) }
        val pool = Executors.newFixedThreadPool(2)
        val start = CountDownLatch(1)
        val tasks = (1..2).map {
            pool.submit {
                val r = relay(batch = 1)
                start.await()
                repeat(10) { r.publishBatch() }
            }
        }
        start.countDown()
        tasks.forEach { it.get() }
        pool.shutdown()
        val keys = chains.map { it.jobId.toString() }.toSet()
        val counts = countByKey(keys)
        assertThat(counts.keys).isEqualTo(keys)
        assertThat(counts.values).allMatch { it == 1 }
    }

    @Test
    fun `crash after send republishes but queues the job once`() {
        val chain = newChain()
        val ev = event(chain)
        val crashing = relay()
        crashing.afterSend = { throw IllegalStateException("crash before commit") }
        crashing.publishBatch()
        assertThat(outbox.findById(ev.id).orElseThrow().status).isEqualTo(OutboxStatus.PENDING)

        val stored = outbox.findById(ev.id).orElseThrow()
        stored.nextAttemptAt = Instant.now().minusSeconds(1)
        outbox.saveAndFlush(stored)
        relay().publishBatch()

        assertThat(outbox.findById(ev.id).orElseThrow().status).isEqualTo(OutboxStatus.SENT)
        assertThat(scanJobs.findById(chain.jobId).orElseThrow().status).isEqualTo(JobStatus.QUEUED)
        assertThat(countByKey(setOf(chain.jobId.toString()))[chain.jobId.toString()]).isEqualTo(2)

        // повторная публикация уже QUEUED-задания не ломает состояние
        val again = outbox.saveAndFlush(event(chain))
        relay().publishBatch()
        assertThat(outbox.findById(again.id).orElseThrow().status).isEqualTo(OutboxStatus.SENT)
        assertThat(scanJobs.findById(chain.jobId).orElseThrow().status).isEqualTo(JobStatus.QUEUED)
    }
}

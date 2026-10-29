package io.vulscan.core.messaging

import io.vulscan.core.application.JobResultService
import io.vulscan.core.domain.JobStatus
import io.vulscan.core.domain.ResultIntegrity
import io.vulscan.core.persistence.PersistenceTestBase
import io.vulscan.core.persistence.ProcessedMessageRepository
import io.vulscan.core.support.ResultMessages
import io.vulscan.kit.contracts.KafkaTopics
import org.apache.kafka.clients.consumer.ConsumerConfig
import org.apache.kafka.clients.consumer.KafkaConsumer
import org.apache.kafka.common.serialization.StringDeserializer
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.mockito.ArgumentMatchers
import org.mockito.Mockito
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.kafka.core.KafkaTemplate
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean
import java.time.Duration
import java.util.Properties
import java.util.UUID

class JobEventsConsumerIT : PersistenceTestBase() {
    @Autowired lateinit var kafka: KafkaTemplate<String, String>
    @Autowired lateinit var processed: ProcessedMessageRepository
    @Autowired lateinit var kafkaContainer: org.testcontainers.kafka.KafkaContainer
    @MockitoSpyBean lateinit var service: JobResultService

    private fun runningJob(): Chain {
        val chain = newChain()
        val job = jobs.findById(chain.jobId).orElseThrow()
        job.status = JobStatus.RUNNING
        jobs.saveAndFlush(job)
        return chain
    }

    private fun send(jobId: UUID, value: String) {
        kafka.send(KafkaTopics.JOB_EVENTS, jobId.toString(), value).get()
    }

    private fun await(seconds: Long = 30, condition: () -> Boolean) {
        val end = System.currentTimeMillis() + seconds * 1000
        while (System.currentTimeMillis() < end) {
            if (condition()) return
            Thread.sleep(200)
        }
        throw AssertionError("Condition was not met in $seconds s")
    }

    private fun findingCount(jobId: UUID) = findings.findAll().count { it.jobId == jobId }

    private fun jobStatus(jobId: UUID) = jobs.findById(jobId).orElseThrow().status

    @Test
    fun `finding message is stored once`() {
        val c = runningJob()
        send(c.jobId, ResultMessages.finding(c.jobId))
        await { findingCount(c.jobId) == 1 }
    }

    @Test
    fun `same message delivered twice creates one row`() {
        val c = runningJob()
        val id = UUID.randomUUID()
        val msg = ResultMessages.finding(c.jobId, messageId = id)
        send(c.jobId, msg)
        send(c.jobId, msg)
        send(c.jobId, ResultMessages.completed(c.jobId, findingsCount = 1))
        await { jobStatus(c.jobId) == JobStatus.COMPLETED }
        assertThat(findingCount(c.jobId)).isEqualTo(1)
        assertThat(processed.findById(id)).isPresent()
    }

    @Test
    fun `different messages with the same fingerprint create one row`() {
        val c = runningJob()
        val fp = ResultMessages.fingerprint()
        send(c.jobId, ResultMessages.finding(c.jobId, fingerprint = fp))
        send(c.jobId, ResultMessages.finding(c.jobId, fingerprint = fp))
        send(c.jobId, ResultMessages.completed(c.jobId, findingsCount = 1))
        await { jobStatus(c.jobId) == JobStatus.COMPLETED }
        assertThat(findingCount(c.jobId)).isEqualTo(1)
        assertThat(jobs.findById(c.jobId).orElseThrow().resultIntegrity).isEqualTo(ResultIntegrity.OK)
    }

    @Test
    fun `missing findings mark the result incomplete`() {
        val c = runningJob()
        send(c.jobId, ResultMessages.finding(c.jobId))
        send(c.jobId, ResultMessages.finding(c.jobId))
        send(c.jobId, ResultMessages.completed(c.jobId, findingsCount = 3))
        await { jobStatus(c.jobId) == JobStatus.COMPLETED }
        assertThat(jobs.findById(c.jobId).orElseThrow().resultIntegrity).isEqualTo(ResultIntegrity.INCOMPLETE)
    }

    @Test
    fun `broken json goes to the dead letter topic and consumption continues`() {
        val c = runningJob()
        val marker = "broken-" + UUID.randomUUID()
        kafka.send(KafkaTopics.JOB_EVENTS, c.jobId.toString(), "{ $marker").get()
        send(c.jobId, ResultMessages.finding(c.jobId))
        await { findingCount(c.jobId) == 1 }
        assertThat(readDlq(marker)).isNotEmpty()
    }

    @Test
    fun `failure inside the transaction is retried until it succeeds`() {
        val c = runningJob()
        Mockito.doThrow(IllegalStateException("db down")).doCallRealMethod().`when`(service).handle(ArgumentMatchers.any())
        send(c.jobId, ResultMessages.finding(c.jobId))
        await { findingCount(c.jobId) == 1 }
        Mockito.verify(service, Mockito.atLeast(2)).handle(ArgumentMatchers.any())
    }

    private fun readDlq(marker: String): List<String> {
        val consumer = KafkaConsumer<String, String>(
            Properties().apply {
                put(ConsumerConfig.BOOTSTRAP_SERVERS_CONFIG, kafkaContainer.bootstrapServers)
                put(ConsumerConfig.GROUP_ID_CONFIG, "it-" + UUID.randomUUID())
                put(ConsumerConfig.KEY_DESERIALIZER_CLASS_CONFIG, StringDeserializer::class.java.name)
                put(ConsumerConfig.VALUE_DESERIALIZER_CLASS_CONFIG, StringDeserializer::class.java.name)
                put(ConsumerConfig.AUTO_OFFSET_RESET_CONFIG, "earliest")
            },
        )
        val found = mutableListOf<String>()
        consumer.use {
            it.subscribe(listOf(KafkaTopics.DLQ))
            val end = System.currentTimeMillis() + 15_000
            while (System.currentTimeMillis() < end && found.isEmpty()) {
                it.poll(Duration.ofMillis(300)).forEach { r -> if (r.value().contains(marker)) found += r.value() }
            }
        }
        return found
    }
}

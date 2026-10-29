package io.vulscan.core.observability

import io.vulscan.kit.contracts.KafkaTopics
import org.springframework.boot.health.contributor.Health
import org.springframework.boot.health.contributor.HealthIndicator
import org.springframework.kafka.core.KafkaTemplate
import org.springframework.stereotype.Component

/** Readiness: брокер отвечает на запрос метаданных топика заданий. */
@Component("kafkaProducer")
class KafkaProducerHealthIndicator(private val kafka: KafkaTemplate<String, String>) : HealthIndicator {
    override fun health(): Health =
        try {
            kafka.partitionsFor(KafkaTopics.JOB_EVENTS)
            Health.up().build()
        } catch (e: Exception) {
            Health.down().withDetail("error", e.javaClass.simpleName).build()
        }
}

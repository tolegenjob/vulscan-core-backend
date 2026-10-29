package io.vulscan.core.messaging

import io.vulscan.core.application.JobResultService
import io.vulscan.core.application.ResultOutcome
import io.vulscan.kit.contracts.Json
import io.vulscan.kit.contracts.KafkaTopics
import org.apache.kafka.clients.consumer.ConsumerRecord
import org.slf4j.LoggerFactory
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.kafka.annotation.KafkaListener
import org.springframework.kafka.core.KafkaTemplate
import org.springframework.kafka.listener.DefaultErrorHandler
import org.springframework.kafka.support.Acknowledgment
import org.springframework.stereotype.Component
import org.springframework.util.backoff.FixedBackOff
import java.util.concurrent.TimeUnit

/**
 * Читает события модулей. Offset подтверждается только после коммита транзакции обработки;
 * необрабатываемые сообщения уходят в DLQ, после чего offset тоже подтверждается.
 */
@Component
@ConditionalOnProperty("scanner.results.enabled", havingValue = "true", matchIfMissing = true)
class JobEventsConsumer(
    private val results: JobResultService,
    private val kafka: KafkaTemplate<String, String>,
) {
    private val log = LoggerFactory.getLogger(javaClass)

    @KafkaListener(topics = [KafkaTopics.JOB_EVENTS], groupId = "core-results")
    fun onMessage(record: ConsumerRecord<String, String>, ack: Acknowledgment) {
        val outcome = results.handle(record.value())
        if (outcome is ResultOutcome.Dead) {
            log.warn("Dead letter: {} ({}) at {}-{}@{}", outcome.reason, outcome.detail, record.topic(), record.partition(), record.offset())
            sendToDlq(record, outcome)
        }
        ack.acknowledge()
    }

    private fun sendToDlq(record: ConsumerRecord<String, String>, outcome: ResultOutcome.Dead) {
        val body = Json.write(
            mapOf(
                "reason" to outcome.reason,
                "detail" to outcome.detail,
                "sourceTopic" to record.topic(),
                "partition" to record.partition(),
                "offset" to record.offset(),
                "key" to record.key(),
                "value" to record.value()?.take(MAX_DLQ_VALUE),
            ),
        )
        kafka.send(KafkaTopics.DLQ, record.key(), body).get(5, TimeUnit.SECONDS)
    }

    private companion object {
        const val MAX_DLQ_VALUE = 64 * 1024
    }
}

@Configuration
class ConsumerErrorHandlingConfig {
    /** Временные сбои (БД, DLQ) повторяются бесконечно: offset не подтверждается, пока сообщение не обработано. */
    @Bean
    fun kafkaErrorHandler() = DefaultErrorHandler(FixedBackOff(1000L, FixedBackOff.UNLIMITED_ATTEMPTS))
}

package io.vulscan.core.observability

import io.micrometer.core.instrument.Gauge
import io.micrometer.core.instrument.MeterRegistry
import io.vulscan.core.domain.JobStatus
import io.vulscan.core.domain.OutboxStatus
import io.vulscan.core.persistence.OutboxEventRepository
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.stereotype.Component

/** Бизнес-метрики Core. Теги имеют ограниченный набор значений (статусы, виды восстановления). */
@Component
class Metrics(private val registry: MeterRegistry) {

    fun scanCreated() {
        registry.counter("scanner.scans.created").increment()
    }

    fun jobTransition(from: JobStatus, to: JobStatus) {
        registry.counter("scanner.jobs.transitions", "from", from.name, "to", to.name).increment()
    }

    fun watchdogRecovery(kind: String) {
        registry.counter("scanner.watchdog.recoveries", "kind", kind).increment()
    }
}

@Configuration
class MetricsGauges {
    @Bean
    fun outboxPendingGauge(registry: MeterRegistry, outbox: OutboxEventRepository): Gauge =
        Gauge.builder("scanner.outbox.pending") { outbox.countByStatus(OutboxStatus.PENDING).toDouble() }.register(registry)
}

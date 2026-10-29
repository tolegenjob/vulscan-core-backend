package io.vulscan.core.scheduling

import io.vulscan.core.application.JobRecoveryService
import org.slf4j.LoggerFactory
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty
import org.springframework.scheduling.annotation.Scheduled
import org.springframework.stereotype.Component
import java.time.Instant

/** Один проход проверки зависших заданий; расписание задаёт [WatchdogScheduler]. */
@Component
class StuckJobWatchdog(private val recovery: JobRecoveryService) {
    private val log = LoggerFactory.getLogger(javaClass)

    /** @return число заданий, над которыми выполнено действие. */
    fun runOnce(now: Instant = Instant.now()): Int {
        var acted = 0
        // Порядок важен: deadline не должен превращаться в повторный запуск по потере lease
        acted += process(recovery.pastDeadline(now, BATCH)) { recovery.expireDeadline(it, now) }
        acted += process(recovery.lostLease(now, BATCH)) { recovery.recoverLostLease(it, now) }
        acted += process(recovery.staleQueued(now, BATCH)) { recovery.expireQueued(it, now) }
        return acted
    }

    private fun process(ids: List<java.util.UUID>, action: (java.util.UUID) -> Boolean): Int =
        ids.count { id ->
            try {
                action(id)
            } catch (e: Exception) {
                log.error("Watchdog failed for job {}", id, e)
                false
            }
        }

    private companion object {
        const val BATCH = 20
    }
}

@Component
@ConditionalOnProperty(name = ["scanner.watchdog.enabled"], havingValue = "true", matchIfMissing = true)
class WatchdogScheduler(private val watchdog: StuckJobWatchdog) {
    private val log = LoggerFactory.getLogger(javaClass)

    @Scheduled(fixedDelayString = "\${scanner.watchdog.poll-ms:15000}", initialDelayString = "\${scanner.watchdog.poll-ms:15000}")
    fun tick() {
        try {
            watchdog.runOnce()
        } catch (e: Exception) {
            log.error("Watchdog pass failed", e)
        }
    }
}

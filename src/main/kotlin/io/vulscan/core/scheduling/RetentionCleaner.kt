package io.vulscan.core.scheduling

import org.slf4j.LoggerFactory
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.scheduling.annotation.Scheduled
import org.springframework.stereotype.Component
import java.sql.Timestamp
import java.time.Duration
import java.time.Instant

/** Удаляет служебные записи старше срока хранения; истёкшие сессии убирает сам Spring Session (cleanup-cron). */
@Component
class RetentionCleaner(private val jdbc: JdbcTemplate) {
    private val log = LoggerFactory.getLogger(javaClass)

    @Scheduled(cron = "\${scanner.retention.cron:0 30 3 * * *}")
    fun scheduled() {
        try {
            clean()
        } catch (e: Exception) {
            log.error("Retention cleanup failed", e)
        }
    }

    /** @return число удалённых строк. */
    fun clean(now: Instant = Instant.now(), keep: Duration = Duration.ofDays(7)): Int {
        val cutoff = Timestamp.from(now.minus(keep))
        val messages = jdbc.update("DELETE FROM processed_messages WHERE processed_at < ?", cutoff)
        val events = jdbc.update("DELETE FROM outbox_events WHERE status = 'SENT' AND sent_at < ?", cutoff)
        if (messages + events > 0) log.info("Retention cleanup removed {} processed messages and {} outbox events", messages, events)
        return messages + events
    }
}

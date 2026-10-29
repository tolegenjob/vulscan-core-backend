package io.vulscan.core.application

import io.vulscan.core.domain.ScanStatus
import io.vulscan.core.security.CurrentUser
import io.vulscan.kit.contracts.ModuleType
import io.vulscan.kit.contracts.Severity
import io.vulscan.kit.contracts.Verdict
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional
import java.time.Instant
import java.util.UUID

data class RecentScan(val id: UUID, val targetId: UUID, val status: ScanStatus, val createdAt: Instant, val finishedAt: Instant?)

data class DashboardSummary(
    val openFindingsBySeverity: Map<Severity, Long>,
    val openFindingsByModule: Map<ModuleType, Long>,
    val openFindingsByVerdict: Map<Verdict, Long>,
    val activeScans: Long,
    val recentScans: List<RecentScan>,
    val avgScanDurationSec: Double?,
)

/** Сводка по последним [RECENT_SCANS] сканам пользователя; стоимость запросов не зависит от истории. */
@Service
class DashboardService(private val jdbc: NamedParameterJdbcTemplate) {

    @Transactional(readOnly = true)
    fun summary(user: CurrentUser): DashboardSummary {
        val params = MapSqlParameterSource().addValue("admin", user.isAdmin).addValue("uid", user.id).addValue("n", RECENT_SCANS)
        val recent = "(SELECT id FROM scans WHERE (CAST(:admin AS boolean) OR started_by = :uid) ORDER BY created_at DESC LIMIT :n)"

        fun <K : Enum<K>> counts(column: String, entries: Array<K>): Map<K, Long> {
            val found = jdbc.query(
                "SELECT $column AS k, count(*) AS c FROM findings WHERE scan_id IN $recent AND triage_status = 'OPEN' GROUP BY $column",
                params,
            ) { rs, _ -> rs.getString("k") to rs.getLong("c") }.toMap()
            return entries.associateWith { found[it.name] ?: 0L }
        }

        val active = jdbc.queryForObject(
            "SELECT count(*) FROM scans WHERE (CAST(:admin AS boolean) OR started_by = :uid) AND status IN ('PENDING','RUNNING','CANCELLING')",
            params, Long::class.java,
        ) ?: 0L
        val recentScans = jdbc.query(
            "SELECT id, target_id, status, created_at, finished_at FROM scans WHERE (CAST(:admin AS boolean) OR started_by = :uid) ORDER BY created_at DESC LIMIT 5",
            params,
        ) { rs, _ ->
            RecentScan(
                rs.getObject("id", UUID::class.java), rs.getObject("target_id", UUID::class.java), ScanStatus.valueOf(rs.getString("status")),
                rs.getTimestamp("created_at").toInstant(), rs.getTimestamp("finished_at")?.toInstant(),
            )
        }
        val avg = jdbc.queryForObject(
            "SELECT avg(extract(epoch FROM (finished_at - created_at))) FROM scans WHERE id IN $recent " +
                "AND finished_at IS NOT NULL AND status IN ('COMPLETED','PARTIALLY_COMPLETED')",
            params, Double::class.javaObjectType,
        )
        return DashboardSummary(
            counts("severity", Severity.entries.toTypedArray()),
            counts("module_type", ModuleType.entries.toTypedArray()),
            counts("verdict", Verdict.entries.toTypedArray()),
            active, recentScans, avg,
        )
    }

    private companion object {
        const val RECENT_SCANS = 50
    }
}

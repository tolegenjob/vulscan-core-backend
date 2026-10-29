package io.vulscan.core.application

import io.vulscan.core.domain.ScanStatusAggregator
import io.vulscan.core.persistence.ScanJobRepository
import io.vulscan.core.persistence.ScanRepository
import org.springframework.stereotype.Component
import java.time.Instant
import java.util.UUID

/** Пересчитывает статус скана по статусам его заданий. Вызывается в транзакции из каждого места, меняющего статус задания. */
@Component
class ScanStatusRefresher(private val scans: ScanRepository, private val jobs: ScanJobRepository) {

    fun refresh(scanId: UUID) {
        val scan = scans.lockById(scanId) ?: return
        scan.status = ScanStatusAggregator.aggregate(jobs.findByScanId(scanId).map { it.status }, scan.cancelRequested)
        if (!scan.status.isActive && scan.finishedAt == null) scan.finishedAt = Instant.now()
        scans.save(scan)
    }
}

package io.vulscan.core.domain

import io.vulscan.core.domain.JobStatus.CANCELLED
import io.vulscan.core.domain.JobStatus.COMPLETED
import io.vulscan.core.domain.JobStatus.FAILED
import io.vulscan.core.domain.JobStatus.PENDING
import io.vulscan.core.domain.JobStatus.QUEUED
import io.vulscan.core.domain.JobStatus.RUNNING

/** Допустимые переходы статуса задания (таблица B.7). */
object JobStateMachine {
    private val ALLOWED: Set<Pair<JobStatus, JobStatus>> = setOf(
        PENDING to QUEUED,
        PENDING to CANCELLED,
        QUEUED to CANCELLED,
        QUEUED to RUNNING,
        QUEUED to FAILED,
        QUEUED to QUEUED,
        RUNNING to QUEUED,
        RUNNING to COMPLETED,
        RUNNING to FAILED,
        RUNNING to CANCELLED,
    )

    fun isAllowed(from: JobStatus, to: JobStatus) = (from to to) in ALLOWED

    fun transition(from: JobStatus, to: JobStatus) {
        if (!isAllowed(from, to)) throw IllegalStateTransitionException("Job cannot move from $from to $to")
    }

    fun isTerminal(status: JobStatus) = status == COMPLETED || status == FAILED || status == CANCELLED
}

/** Итоговый статус сканирования по статусам заданий (таблица B.7). */
object ScanStatusAggregator {
    fun aggregate(jobs: Collection<JobStatus>, cancelRequested: Boolean): ScanStatus {
        if (jobs.isEmpty()) return ScanStatus.PENDING
        val allTerminal = jobs.all(JobStateMachine::isTerminal)
        if (!allTerminal) {
            return when {
                cancelRequested -> ScanStatus.CANCELLING
                jobs.all { it == PENDING } -> ScanStatus.PENDING
                else -> ScanStatus.RUNNING
            }
        }
        return when {
            cancelRequested -> ScanStatus.CANCELLED
            jobs.none { it == FAILED || it == CANCELLED } -> ScanStatus.COMPLETED
            jobs.any { it == COMPLETED } -> ScanStatus.PARTIALLY_COMPLETED
            else -> ScanStatus.FAILED
        }
    }
}

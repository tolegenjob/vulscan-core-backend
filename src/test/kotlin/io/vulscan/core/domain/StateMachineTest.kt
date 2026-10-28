package io.vulscan.core.domain

import io.vulscan.core.domain.JobStatus.CANCELLED
import io.vulscan.core.domain.JobStatus.COMPLETED
import io.vulscan.core.domain.JobStatus.FAILED
import io.vulscan.core.domain.JobStatus.PENDING
import io.vulscan.core.domain.JobStatus.QUEUED
import io.vulscan.core.domain.JobStatus.RUNNING
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.Arguments
import org.junit.jupiter.params.provider.MethodSource
import java.util.stream.Stream

class StateMachineTest {

    private val allowed = setOf(
        PENDING to QUEUED, PENDING to CANCELLED, QUEUED to CANCELLED, QUEUED to RUNNING, QUEUED to FAILED, QUEUED to QUEUED,
        RUNNING to QUEUED, RUNNING to COMPLETED, RUNNING to FAILED, RUNNING to CANCELLED,
    )

    @Test
    fun `every pair of statuses is decided by the table`() {
        for (from in JobStatus.entries) {
            for (to in JobStatus.entries) {
                if ((from to to) in allowed) {
                    JobStateMachine.transition(from, to)
                } else {
                    assertThatThrownBy { JobStateMachine.transition(from, to) }
                        .`as`("$from -> $to").isInstanceOf(IllegalStateTransitionException::class.java)
                }
            }
        }
    }

    @Test
    fun `terminal statuses have no way out`() {
        listOf(COMPLETED, FAILED, CANCELLED).forEach { from ->
            JobStatus.entries.forEach { to -> assertThat(JobStateMachine.isAllowed(from, to)).isFalse() }
        }
    }

    companion object {
        @JvmStatic
        fun aggregates(): Stream<Arguments> = Stream.of(
            Arguments.of(listOf(PENDING, PENDING), false, ScanStatus.PENDING),
            Arguments.of(listOf(QUEUED, PENDING), false, ScanStatus.RUNNING),
            Arguments.of(listOf(RUNNING, COMPLETED), false, ScanStatus.RUNNING),
            Arguments.of(listOf(RUNNING, COMPLETED), true, ScanStatus.CANCELLING),
            Arguments.of(listOf(COMPLETED, COMPLETED), false, ScanStatus.COMPLETED),
            Arguments.of(listOf(COMPLETED), false, ScanStatus.COMPLETED),
            Arguments.of(listOf(COMPLETED, FAILED), false, ScanStatus.PARTIALLY_COMPLETED),
            Arguments.of(listOf(COMPLETED, CANCELLED), false, ScanStatus.PARTIALLY_COMPLETED),
            Arguments.of(listOf(FAILED, FAILED), false, ScanStatus.FAILED),
            Arguments.of(listOf(FAILED, CANCELLED), false, ScanStatus.FAILED),
            Arguments.of(listOf(CANCELLED, CANCELLED), true, ScanStatus.CANCELLED),
            Arguments.of(listOf(COMPLETED, CANCELLED), true, ScanStatus.CANCELLED),
            Arguments.of(listOf(PENDING, PENDING), true, ScanStatus.CANCELLING),
        )
    }

    @ParameterizedTest
    @MethodSource("aggregates")
    fun `scan status follows the aggregation table`(jobs: List<JobStatus>, cancel: Boolean, expected: ScanStatus) {
        assertThat(ScanStatusAggregator.aggregate(jobs, cancel)).isEqualTo(expected)
    }
}

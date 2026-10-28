package io.vulscan.core.security

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class SlidingWindowLimiterTest {
    @Test
    fun `limits per key and recovers after the window`() {
        var now = 0L
        val limiter = SlidingWindowLimiter(2, 1000) { now }
        assertThat(limiter.tryAcquire("a")).isZero()
        assertThat(limiter.tryAcquire("a")).isZero()
        assertThat(limiter.tryAcquire("a")).isPositive()
        assertThat(limiter.tryAcquire("b")).isZero()
        now = 1001
        assertThat(limiter.tryAcquire("a")).isZero()
    }
}

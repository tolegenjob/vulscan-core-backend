package io.vulscan.core.observability

import ch.qos.logback.classic.Level
import ch.qos.logback.classic.Logger
import ch.qos.logback.classic.LoggerContext
import ch.qos.logback.classic.spi.LoggingEvent
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class RedactingMessageConverterTest {
    private val converter = RedactingMessageConverter()

    private fun format(message: String, vararg args: Any): String {
        val logger = LoggerContext().getLogger("test")
        return converter.convert(LoggingEvent(Logger::class.java.name, logger, Level.INFO, message, null, args))
    }

    @Test
    fun `secret values are masked in log messages`() {
        val out = format("login failed for password={} token=abc123", "S3cretPassw0rd!")
        assertThat(out).doesNotContain("S3cretPassw0rd!").doesNotContain("abc123")
    }

    @Test
    fun `ordinary messages are unchanged`() {
        assertThat(format("Recovered job {} after lost lease (attempt {})", "j-1", 2)).isEqualTo("Recovered job j-1 after lost lease (attempt 2)")
    }
}

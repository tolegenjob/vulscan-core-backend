package io.vulscan.core.application

import com.sun.net.httpserver.HttpServer
import io.vulscan.core.config.ScannerProperties
import io.vulscan.core.domain.ConflictException
import io.vulscan.core.domain.ErrorCodes
import io.vulscan.core.persistence.TargetEntity
import io.vulscan.kit.contracts.AllowedHost
import io.vulscan.kit.net.HostResolver
import org.assertj.core.api.Assertions.assertThatCode
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.net.InetAddress
import java.net.InetSocketAddress

class TargetVerificationServiceTest {
    private lateinit var server: HttpServer
    private val token = "tok123"
    private var mode = "ok"

    private val resolver = HostResolver { InetAddress.getByName("127.0.0.1").let(::listOf) }

    @BeforeEach
    fun start() {
        server = HttpServer.create(InetSocketAddress(InetAddress.getByName("127.0.0.1"), 0), 0)
        server.createContext("/") { ex ->
            val port = server.address.port
            when (mode) {
                "ok" -> reply(ex, 200, token)
                "wrong" -> reply(ex, 200, "other")
                "missing" -> reply(ex, 404, "")
                "redirect" -> {
                    ex.responseHeaders.add("Location", "http://evil.test:$port/x")
                    ex.sendResponseHeaders(302, -1)
                    ex.close()
                }
            }
        }
        server.start()
    }

    @AfterEach
    fun stop() = server.stop(0)

    private fun reply(ex: com.sun.net.httpserver.HttpExchange, status: Int, body: String) {
        val bytes = body.toByteArray()
        ex.sendResponseHeaders(status, if (bytes.isEmpty()) -1 else bytes.size.toLong())
        if (bytes.isNotEmpty()) ex.responseBody.use { it.write(bytes) }
        ex.close()
    }

    private fun service() = TargetVerificationService(
        ScannerProperties(
            scope = ScannerProperties.Scope(listOf("127.0.0.0/8"), listOf(80)),
            limits = ScannerProperties.Limits(2, 4),
            jobs = ScannerProperties.Jobs(2, 600, 45, 200),
            outbox = ScannerProperties.Outbox(500, 50, false),
            secret = ScannerProperties.Secret("", 1),
            serviceTokens = ScannerProperties.ServiceTokens("", "", ""),
            bootstrapAdmin = ScannerProperties.BootstrapAdmin("", ""),
        ),
        resolver,
    )

    private fun target() = TargetEntity(
        baseUrl = "http://app.test:${server.address.port}", name = "t", verificationToken = token,
        allowedHosts = listOf(AllowedHost("app.test", listOf(server.address.port))),
    )

    @Test
    fun `matching token verifies`() {
        assertThatCode { service().check(target()) }.doesNotThrowAnyException()
    }

    @Test
    fun `wrong content missing file and foreign redirect fail verification`() {
        listOf("wrong", "missing", "redirect").forEach { m ->
            mode = m
            assertThatThrownBy { service().check(target()) }
                .`as`(m)
                .isInstanceOf(ConflictException::class.java)
                .extracting { (it as ConflictException).code }.isEqualTo(ErrorCodes.VERIFICATION_FAILED)
        }
    }
}

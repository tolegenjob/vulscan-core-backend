package io.vulscan.core.security

import io.vulscan.core.support.InternalApiClient
import io.vulscan.core.support.PostgresTestBase
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.springframework.boot.test.web.server.LocalServerPort
import java.util.UUID

class InternalApiSecurityIT : PostgresTestBase() {
    @LocalServerPort private var port: Int = 0
    private val client by lazy { InternalApiClient(port) }
    private val body = """{"attempt":1,"workerId":"w-1"}"""

    @Test
    fun `missing or wrong token is unauthorized`() {
        val path = "/internal/v1/jobs/${UUID.randomUUID()}/claim"
        assertThat(client.post(path, body, null).statusCode()).isEqualTo(401)
        assertThat(client.post(path, body, "wrong").statusCode()).isEqualTo(401)
    }

    @Test
    fun `missing worker id is unauthorized`() {
        assertThat(client.post("/internal/v1/jobs/${UUID.randomUUID()}/claim", body, InternalApiClient.XSS, null).statusCode()).isEqualTo(401)
    }

    @Test
    fun `user session endpoints do not accept service tokens`() {
        assertThat(client.get("/api/v1/scans", InternalApiClient.XSS).statusCode()).isEqualTo(401)
    }

    @Test
    fun `token of another module cannot touch the job`() {
        // чужое задание выглядит как отсутствующее для любого токена; принадлежность модулю проверяется в JobControlServiceIT
        val r = client.post("/internal/v1/jobs/${UUID.randomUUID()}/claim", body, InternalApiClient.IDOR)
        assertThat(r.statusCode()).isEqualTo(404)
    }
}

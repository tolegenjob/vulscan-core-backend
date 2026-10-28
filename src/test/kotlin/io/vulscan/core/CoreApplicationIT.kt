package io.vulscan.core

import io.vulscan.core.support.PostgresTestBase
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.springframework.boot.test.web.server.LocalServerPort
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse

class CoreApplicationIT : PostgresTestBase() {

    @LocalServerPort
    private var port: Int = 0

    @Test
    fun `context starts and health is UP`() {
        val request = HttpRequest.newBuilder(URI("http://localhost:$port/actuator/health")).GET().build()
        val response = HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.ofString())
        assertThat(response.statusCode()).isEqualTo(200)
        assertThat(response.body()).contains("\"status\":\"UP\"")
        assertThat(response.headers().firstValue("X-Correlation-Id")).isPresent()
    }
}

package io.vulscan.core.security

import io.vulscan.core.support.PostgresTestBase
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.springframework.boot.test.web.server.LocalServerPort
import java.net.CookieManager
import java.net.CookiePolicy
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse

class SecurityIT : PostgresTestBase() {

    @LocalServerPort
    private var port: Int = 0

    private fun client() = HttpClient.newBuilder().cookieHandler(CookieManager(null, CookiePolicy.ACCEPT_ALL)).build()

    private fun url(path: String) = URI("http://localhost:$port$path")

    private fun HttpClient.get(path: String, headers: Map<String, String> = emptyMap()): HttpResponse<String> {
        val b = HttpRequest.newBuilder(url(path)).GET()
        headers.forEach { (k, v) -> b.header(k, v) }
        return send(b.build(), HttpResponse.BodyHandlers.ofString())
    }

    private fun HttpClient.post(path: String, body: String = "", headers: Map<String, String> = emptyMap()): HttpResponse<String> {
        val b = HttpRequest.newBuilder(url(path)).header("Content-Type", "application/json").POST(HttpRequest.BodyPublishers.ofString(body))
        headers.forEach { (k, v) -> b.header(k, v) }
        return send(b.build(), HttpResponse.BodyHandlers.ofString())
    }

    private fun HttpClient.loginAdmin(): String {
        val response = post("/api/v1/auth/login", """{"username":"admin","password":"admin-pass-123"}""")
        assertThat(response.statusCode()).isEqualTo(200)
        return Regex("\"csrfToken\":\"([^\"]+)\"").find(response.body())!!.groupValues[1]
    }

    @Test
    fun `api without a session is unauthenticated`() {
        val response = client().get("/api/v1/auth/me")
        assertThat(response.statusCode()).isEqualTo(401)
        assertThat(response.body()).contains("\"code\":\"UNAUTHENTICATED\"")
    }

    @Test
    fun `login gives a session and me works`() {
        val c = client()
        c.loginAdmin()
        val me = c.get("/api/v1/auth/me")
        assertThat(me.statusCode()).isEqualTo(200)
        assertThat(me.body()).contains("\"username\":\"admin\"").contains("\"role\":\"ADMIN\"").doesNotContain("password")
    }

    @Test
    fun `post without csrf token is forbidden and with token is allowed`() {
        val c = client()
        val csrf = c.loginAdmin()
        assertThat(c.post("/api/v1/auth/logout").statusCode()).isEqualTo(403)
        assertThat(c.post("/api/v1/auth/logout", headers = mapOf("X-XSRF-TOKEN" to csrf)).statusCode()).isEqualTo(204)
        assertThat(c.get("/api/v1/auth/me").statusCode()).isEqualTo(401)
    }

    @Test
    fun `wrong password is rejected and repeated attempts are rate limited`() {
        val c = client()
        val body = """{"username":"ratelimited-user","password":"wrong"}"""
        repeat(5) {
            val r = c.post("/api/v1/auth/login", body)
            assertThat(r.statusCode()).isEqualTo(401)
            assertThat(r.body()).contains("BAD_CREDENTIALS")
        }
        val limited = c.post("/api/v1/auth/login", body)
        assertThat(limited.statusCode()).isEqualTo(429)
        assertThat(limited.headers().firstValue("Retry-After")).isPresent()
    }

    @Test
    fun `internal api requires a service token`() {
        val c = client()
        assertThat(c.get("/internal/v1/jobs/x/identities").statusCode()).isEqualTo(401)
        assertThat(c.get("/internal/v1/jobs/x/identities", mapOf("Authorization" to "Bearer wrong", "X-Worker-Id" to "w")).statusCode()).isEqualTo(401)
        assertThat(c.get("/internal/v1/jobs/x/identities", mapOf("Authorization" to "Bearer test-token-xss")).statusCode()).isEqualTo(401)
        val ok = c.get("/internal/v1/jobs/x/identities", mapOf("Authorization" to "Bearer test-token-xss", "X-Worker-Id" to "w"))
        assertThat(ok.statusCode()).isNotIn(401, 403)
    }

    @Test
    fun `health is open and everything else is closed`() {
        val c = client()
        assertThat(c.get("/actuator/health").statusCode()).isEqualTo(200)
        assertThat(c.get("/actuator/info").statusCode()).isIn(401, 403)
    }

    @Test
    fun `session cookie is http only`() {
        val response = client().post("/api/v1/auth/login", """{"username":"admin","password":"admin-pass-123"}""")
        val cookies = response.headers().allValues("Set-Cookie")
        assertThat(cookies.any { it.startsWith("SESSION=") || it.startsWith("JSESSIONID=") }).isTrue()
        assertThat(cookies.filter { it.startsWith("SESSION=") || it.startsWith("JSESSIONID=") }.all { it.contains("HttpOnly") }).isTrue()
    }
}

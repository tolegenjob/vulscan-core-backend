package io.vulscan.core.application

import io.vulscan.core.domain.UserRole
import io.vulscan.core.persistence.OutboxEventRepository
import io.vulscan.core.persistence.ScanJobRepository
import io.vulscan.core.persistence.ScanRepository
import io.vulscan.core.persistence.UserEntity
import io.vulscan.core.persistence.UserRepository
import io.vulscan.core.support.ApiClient
import io.vulscan.core.support.PostgresTestBase
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.web.server.LocalServerPort
import org.springframework.security.crypto.password.PasswordEncoder
import java.util.UUID
import java.util.concurrent.Callable
import java.util.concurrent.Executors

class ScanServiceIT : PostgresTestBase() {
    @LocalServerPort private var port: Int = 0
    @Autowired lateinit var users: UserRepository
    @Autowired lateinit var encoder: PasswordEncoder
    @Autowired lateinit var scans: ScanRepository
    @Autowired lateinit var jobs: ScanJobRepository
    @Autowired lateinit var outbox: OutboxEventRepository

    private fun client(role: UserRole = UserRole.USER): ApiClient {
        val name = "u-" + UUID.randomUUID().toString().take(8)
        users.save(UserEntity(username = name, passwordHash = encoder.encode("pw-$name")!!, role = role))
        return ApiClient(port).also { assertThat(it.login(name, "pw-$name").statusCode()).isEqualTo(200) }
    }

    private class Env(val client: ApiClient, val targetId: String, val host: String, val endpointId: String)

    private fun env(approve: Boolean = true, user: ApiClient = client()): Env {
        val host = "app-${UUID.randomUUID().toString().take(6)}.test"
        val t = user.post("/api/v1/targets", """{"name":"lab","baseUrl":"http://$host:8080"}""")
        val targetId = user.field(t, "id")
        if (approve) assertThat(client(UserRole.ADMIN).post("/api/v1/targets/$targetId/approve").statusCode()).isEqualTo(200)
        val e = user.post("/api/v1/targets/$targetId/endpoints", """{"method":"GET","url":"http://$host:8080/search","parameters":[{"name":"q","location":"QUERY"}],"idempotent":true}""")
        return Env(user, targetId, host, user.field(e, "id"))
    }

    private fun scanBody(e: Env, modules: String = """["XSS","SQLI"]""") =
        """{"targetId":"${e.targetId}","modules":$modules,"endpointIds":["${e.endpointId}"]}"""

    @Test
    fun `valid request creates scan jobs and outbox entries without publishing`() {
        val e = env()
        val r = e.client.post("/api/v1/scans", scanBody(e))
        assertThat(r.statusCode()).isEqualTo(202)
        assertThat(r.body()).contains("\"status\":\"PENDING\"").contains("XSS").contains("SQLI")
        val scanId = UUID.fromString(e.client.field(r, "id"))
        val scanJobs = jobs.findByScanId(scanId)
        assertThat(scanJobs).hasSize(2)
        val events = outbox.findAll().filter { ev -> scanJobs.any { it.id == ev.aggregateId } }
        assertThat(events).hasSize(2)
        assertThat(events).allMatch { it.status.name == "PENDING" && it.topic.startsWith("scan.jobs.") }
    }

    @Test
    fun `unverified target is rejected`() {
        val e = env(approve = false)
        val r = e.client.post("/api/v1/scans", scanBody(e))
        assertThat(r.statusCode()).isEqualTo(409)
        assertThat(r.body()).contains("TARGET_NOT_VERIFIED")
    }

    @Test
    fun `endpoint of another target is not found`() {
        val mine = env()
        val other = env()
        val r = mine.client.post("/api/v1/scans", """{"targetId":"${mine.targetId}","modules":["XSS"],"endpointIds":["${other.endpointId}"]}""")
        assertThat(r.statusCode()).isEqualTo(404)
    }

    @Test
    fun `request validation`() {
        val e = env()
        assertThat(e.client.post("/api/v1/scans", scanBody(e, "[]")).statusCode()).isEqualTo(400)
        assertThat(e.client.post("/api/v1/scans", scanBody(e, """["XSS","XSS"]""")).statusCode()).isEqualTo(400)
        assertThat(e.client.post("/api/v1/scans", scanBody(e, """["IDOR"]""")).statusCode()).isEqualTo(400)
    }

    @Test
    fun `oversized job is rejected and nothing is stored`() {
        val e = env()
        val before = scans.count()
        val big = "x".repeat(4000)
        val params = (0 until 50).joinToString(",") { """{"name":"p$it","location":"QUERY","sampleValue":"$big"}""" }
        val ids = (0 until 6).map { i ->
            val r = e.client.post("/api/v1/targets/${e.targetId}/endpoints", """{"method":"GET","url":"http://${e.host}:8080/big$i","parameters":[$params]}""")
            assertThat(r.statusCode()).isEqualTo(201)
            e.client.field(r, "id")
        }
        val r = e.client.post("/api/v1/scans", """{"targetId":"${e.targetId}","modules":["XSS"],"endpointIds":[${ids.joinToString(",") { "\"$it\"" }}]}""")
        assertThat(r.statusCode()).isEqualTo(422)
        assertThat(r.body()).contains("PAYLOAD_TOO_LARGE")
        assertThat(scans.count()).isEqualTo(before)
    }

    @Test
    fun `third active scan of a user is rejected`() {
        val e = env()
        assertThat(e.client.post("/api/v1/scans", scanBody(e, """["XSS"]""")).statusCode()).isEqualTo(202)
        assertThat(e.client.post("/api/v1/scans", scanBody(e, """["XSS"]""")).statusCode()).isEqualTo(202)
        val third = e.client.post("/api/v1/scans", scanBody(e, """["XSS"]"""))
        assertThat(third.statusCode()).isEqualTo(429)
        assertThat(third.body()).contains("TOO_MANY_ACTIVE_SCANS")
    }

    @Test
    fun `parallel requests cannot exceed the active limit`() {
        val e = env()
        val pool = Executors.newFixedThreadPool(5)
        val results = pool.invokeAll((1..5).map { Callable { e.client.post("/api/v1/scans", scanBody(e, """["XSS"]""")).statusCode() } }).map { it.get() }
        pool.shutdown()
        assertThat(results.count { it == 202 }).isEqualTo(2)
        assertThat(results.count { it == 429 }).isEqualTo(3)
    }

    @Test
    fun `scans are private to their owner and cancel works`() {
        val e = env()
        val id = e.client.field(e.client.post("/api/v1/scans", scanBody(e, """["XSS"]""")), "id")
        assertThat(client().get("/api/v1/scans/$id").statusCode()).isEqualTo(404)
        assertThat(e.client.get("/api/v1/scans/$id").statusCode()).isEqualTo(200)
        assertThat(e.client.get("/api/v1/scans").body()).contains(id)

        val cancelled = e.client.post("/api/v1/scans/$id/cancel")
        assertThat(cancelled.statusCode()).isEqualTo(200)
        assertThat(cancelled.body()).contains("\"status\":\"CANCELLED\"").contains("\"cancelRequested\":true")
        assertThat(e.client.post("/api/v1/scans/$id/cancel").statusCode()).isEqualTo(409)

        val rerun = e.client.post("/api/v1/scans/$id/rerun")
        assertThat(rerun.statusCode()).isEqualTo(202)
        assertThat(e.client.field(rerun, "id")).isNotEqualTo(id)
    }
}

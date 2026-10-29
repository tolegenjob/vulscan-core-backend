package io.vulscan.core.application

import io.vulscan.core.domain.JobStatus
import io.vulscan.core.domain.OutboxStatus
import io.vulscan.core.domain.ScanStatus
import io.vulscan.core.domain.UserRole
import io.vulscan.core.persistence.OutboxEventRepository
import io.vulscan.core.persistence.ScanJobRepository
import io.vulscan.core.persistence.ScanRepository
import io.vulscan.core.persistence.UserEntity
import io.vulscan.core.persistence.UserRepository
import io.vulscan.core.support.ApiClient
import io.vulscan.core.support.InternalApiClient
import io.vulscan.core.support.PostgresTestBase
import io.vulscan.kit.contracts.ModuleType
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.web.server.LocalServerPort
import org.springframework.security.crypto.password.PasswordEncoder
import java.time.Instant
import java.util.UUID

class ScanCancelIT : PostgresTestBase() {
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

    private fun newScan(user: ApiClient): UUID {
        val host = "app-${UUID.randomUUID().toString().take(6)}.test"
        val targetId = user.field(user.post("/api/v1/targets", """{"name":"lab","baseUrl":"http://$host:8080"}"""), "id")
        assertThat(client(UserRole.ADMIN).post("/api/v1/targets/$targetId/approve").statusCode()).isEqualTo(200)
        val endpointId = user.field(
            user.post("/api/v1/targets/$targetId/endpoints", """{"method":"GET","url":"http://$host:8080/s","parameters":[{"name":"q","location":"QUERY"}],"idempotent":true}"""),
            "id",
        )
        return UUID.fromString(user.field(user.post("/api/v1/scans", """{"targetId":"$targetId","modules":["XSS","SQLI"],"endpointIds":["$endpointId"]}"""), "id"))
    }

    @Test
    fun `cancelling a pending scan cancels every job and publishes nothing`() {
        val user = client()
        val scanId = newScan(user)
        val jobIds = jobs.findByScanId(scanId).map { it.id }
        assertThat(user.post("/api/v1/scans/$scanId/cancel").statusCode()).isEqualTo(200)

        assertThat(jobs.findByScanId(scanId).map { it.status }).containsOnly(JobStatus.CANCELLED)
        assertThat(scans.findById(scanId).orElseThrow().status).isEqualTo(ScanStatus.CANCELLED)
        val events = outbox.findAll().filter { it.aggregateId in jobIds }
        assertThat(events).hasSize(2)
        assertThat(events).allMatch { it.status == OutboxStatus.SENT && it.headers["cancelled"] == "true" }
    }

    @Test
    fun `cancelling a running scan is idempotent and finishes after the heartbeat`() {
        val user = client()
        val scanId = newScan(user)
        val xss = jobs.findByScanId(scanId).first { it.moduleType == ModuleType.XSS }
        xss.status = JobStatus.QUEUED
        xss.queuedAt = Instant.now()
        jobs.save(xss)
        val internal = InternalApiClient(port)
        assertThat(internal.post("/internal/v1/jobs/${xss.id}/claim", """{"attempt":1,"workerId":"w-1"}""", InternalApiClient.XSS).statusCode()).isEqualTo(200)

        val first = user.post("/api/v1/scans/$scanId/cancel")
        assertThat(first.statusCode()).isEqualTo(200)
        assertThat(first.body()).contains("\"status\":\"CANCELLING\"")
        assertThat(user.post("/api/v1/scans/$scanId/cancel").statusCode()).isEqualTo(200)
        assertThat(scans.findById(scanId).orElseThrow().status).isEqualTo(ScanStatus.CANCELLING)

        val hb = internal.post("/internal/v1/jobs/${xss.id}/heartbeat", """{"attempt":1,"requestsSent":1,"endpointsDone":0}""", InternalApiClient.XSS)
        assertThat(hb.body()).contains("\"cancel\":true")
        assertThat(scans.findById(scanId).orElseThrow().status).isEqualTo(ScanStatus.CANCELLED)
    }

    @Test
    fun `cancelling a finished scan is a conflict`() {
        val user = client()
        val scanId = newScan(user)
        assertThat(user.post("/api/v1/scans/$scanId/cancel").statusCode()).isEqualTo(200)
        val again = user.post("/api/v1/scans/$scanId/cancel")
        assertThat(again.statusCode()).isEqualTo(409)
        assertThat(again.body()).contains("SCAN_ALREADY_FINISHED")
    }

    @Test
    fun `another user cannot cancel the scan`() {
        val owner = client()
        val scanId = newScan(owner)
        assertThat(client().post("/api/v1/scans/$scanId/cancel").statusCode()).isEqualTo(404)
    }
}

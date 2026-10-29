package io.vulscan.core.application

import io.vulscan.core.domain.JobStatus
import io.vulscan.core.domain.ScanStatus
import io.vulscan.core.domain.UserRole
import io.vulscan.core.persistence.AuditEventRepository
import io.vulscan.core.persistence.ScanJobEntity
import io.vulscan.core.persistence.ScanJobRepository
import io.vulscan.core.persistence.ScanRepository
import io.vulscan.core.persistence.TestIdentityEntity
import io.vulscan.core.persistence.TestIdentityRepository
import io.vulscan.core.persistence.UserEntity
import io.vulscan.core.persistence.UserRepository
import io.vulscan.core.security.SecretCipher
import io.vulscan.core.support.ApiClient
import io.vulscan.core.support.InternalApiClient
import io.vulscan.core.support.PostgresTestBase
import io.vulscan.kit.contracts.AuthType
import io.vulscan.kit.contracts.Json
import io.vulscan.kit.contracts.ModuleType
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.web.server.LocalServerPort
import org.springframework.security.crypto.password.PasswordEncoder
import java.time.Instant
import java.util.UUID
import java.util.concurrent.Callable
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors

class JobControlServiceIT : PostgresTestBase() {
    @LocalServerPort private var port: Int = 0
    @Autowired lateinit var users: UserRepository
    @Autowired lateinit var encoder: PasswordEncoder
    @Autowired lateinit var scans: ScanRepository
    @Autowired lateinit var jobs: ScanJobRepository
    @Autowired lateinit var identities: TestIdentityRepository
    @Autowired lateinit var audits: AuditEventRepository
    @Autowired lateinit var cipher: SecretCipher

    private val internal by lazy { InternalApiClient(port) }

    private class Fixture(val user: ApiClient, val scanId: UUID, val targetId: UUID, val jobs: Map<ModuleType, UUID>)

    private fun client(role: UserRole = UserRole.USER): ApiClient {
        val name = "u-" + UUID.randomUUID().toString().take(8)
        users.save(UserEntity(username = name, passwordHash = encoder.encode("pw-$name")!!, role = role))
        return ApiClient(port).also { assertThat(it.login(name, "pw-$name").statusCode()).isEqualTo(200) }
    }

    /** Создаёт скан XSS+SQLI через API и переводит его задания в QUEUED (relay в тестах выключен). */
    private fun fixture(): Fixture {
        val user = client()
        val host = "app-${UUID.randomUUID().toString().take(6)}.test"
        val targetId = user.field(user.post("/api/v1/targets", """{"name":"lab","baseUrl":"http://$host:8080"}"""), "id")
        assertThat(client(UserRole.ADMIN).post("/api/v1/targets/$targetId/approve").statusCode()).isEqualTo(200)
        val endpointId = user.field(
            user.post("/api/v1/targets/$targetId/endpoints", """{"method":"GET","url":"http://$host:8080/s","parameters":[{"name":"q","location":"QUERY"}],"idempotent":true}"""),
            "id",
        )
        val scanId = UUID.fromString(
            user.field(user.post("/api/v1/scans", """{"targetId":"$targetId","modules":["XSS","SQLI"],"endpointIds":["$endpointId"]}"""), "id"),
        )
        val byModule = jobs.findByScanId(scanId).onEach {
            it.status = JobStatus.QUEUED
            it.queuedAt = Instant.now()
            jobs.save(it)
        }.associate { it.moduleType to it.id }
        return Fixture(user, scanId, UUID.fromString(targetId), byModule)
    }

    private fun claimBody(attempt: Int = 1, worker: String = "w-1") = """{"attempt":$attempt,"workerId":"$worker"}"""
    private fun hbBody(attempt: Int = 1) = """{"attempt":$attempt,"requestsSent":5,"endpointsDone":1}"""

    /** Добавляет к скану IDOR-задание в статусе RUNNING и две идентичности с зашифрованными секретами. */
    private fun addIdorJob(f: Fixture, worker: String = "w-1"): UUID {
        val ids = listOf("alice", "bob").map { label ->
            val enc = cipher.encrypt("""{"token":"SECRET-$label"}""".toByteArray())
            identities.save(
                TestIdentityEntity(
                    targetId = f.targetId, label = label, role = "USER", authType = AuthType.BEARER_STATIC,
                    secretEncrypted = enc.bytes, keyVersion = enc.keyVersion,
                ),
            ).id
        }
        val scan = scans.findById(f.scanId).orElseThrow()
        scan.config = scan.config + ("idor" to mapOf("identityIds" to ids.map { it.toString() }))
        scans.save(scan)
        val job = jobs.save(
            ScanJobEntity(
                scanId = f.scanId, moduleType = ModuleType.IDOR, status = JobStatus.RUNNING, attempt = 1, workerId = worker,
                leaseExpiresAt = Instant.now().plusSeconds(60), deadlineAt = Instant.now().plusSeconds(600),
            ),
        )
        return job.id
    }

    @Test
    fun `claim grants the lease and marks the scan running`() {
        val f = fixture()
        val r = internal.post("/internal/v1/jobs/${f.jobs[ModuleType.XSS]}/claim", claimBody(), InternalApiClient.XSS)
        assertThat(r.statusCode()).isEqualTo(200)
        assertThat(r.body()).contains("leaseExpiresAt").contains("\"heartbeatIntervalSec\":10")
        val job = jobs.findById(f.jobs[ModuleType.XSS]!!).orElseThrow()
        assertThat(job.status).isEqualTo(JobStatus.RUNNING)
        assertThat(job.workerId).isEqualTo("w-1")
        assertThat(job.startedAt).isNotNull()
        assertThat(scans.findById(f.scanId).orElseThrow().status).isEqualTo(ScanStatus.RUNNING)
    }

    @Test
    fun `two parallel claims of one job give one success and one conflict`() {
        val f = fixture()
        val jobId = f.jobs[ModuleType.XSS]
        val pool = Executors.newFixedThreadPool(2)
        val start = CountDownLatch(1)
        val results = pool.invokeAll(
            listOf("w-a", "w-b").map { w ->
                Callable {
                    start.await()
                    internal.post("/internal/v1/jobs/$jobId/claim", claimBody(worker = w), InternalApiClient.XSS, w).statusCode()
                }
            },
        ).also { start.countDown() }.map { it.get() }
        pool.shutdown()
        assertThat(results.sorted()).containsExactly(200, 409)
    }

    @Test
    fun `claim with a wrong attempt is rejected`() {
        val f = fixture()
        val r = internal.post("/internal/v1/jobs/${f.jobs[ModuleType.XSS]}/claim", claimBody(attempt = 2), InternalApiClient.XSS)
        assertThat(r.statusCode()).isEqualTo(409)
        assertThat(r.body()).contains("JOB_NOT_CLAIMABLE")
        assertThat(jobs.findById(f.jobs[ModuleType.XSS]!!).orElseThrow().status).isEqualTo(JobStatus.QUEUED)
    }

    @Test
    fun `claim of an unknown job is 404 and worker id must match the header`() {
        assertThat(internal.post("/internal/v1/jobs/${UUID.randomUUID()}/claim", claimBody(), InternalApiClient.XSS).statusCode()).isEqualTo(404)
        val f = fixture()
        val mismatch = internal.post("/internal/v1/jobs/${f.jobs[ModuleType.XSS]}/claim", claimBody(worker = "other"), InternalApiClient.XSS, "w-1")
        assertThat(mismatch.statusCode()).isEqualTo(400)
    }

    @Test
    fun `heartbeat extends the lease and stores progress`() {
        val f = fixture()
        val id = f.jobs[ModuleType.XSS]
        internal.post("/internal/v1/jobs/$id/claim", claimBody(), InternalApiClient.XSS)
        val r = internal.post("/internal/v1/jobs/$id/heartbeat", hbBody(), InternalApiClient.XSS)
        assertThat(r.statusCode()).isEqualTo(200)
        assertThat(r.body()).contains("\"cancel\":false")
        val job = jobs.findById(id!!).orElseThrow()
        assertThat(job.requestsSent).isEqualTo(5)
        assertThat(job.endpointsDone).isEqualTo(1)
    }

    @Test
    fun `heartbeat from another worker is a lease loss`() {
        val f = fixture()
        val id = f.jobs[ModuleType.XSS]
        internal.post("/internal/v1/jobs/$id/claim", claimBody(), InternalApiClient.XSS)
        val r = internal.post("/internal/v1/jobs/$id/heartbeat", hbBody(), InternalApiClient.XSS, "w-2")
        assertThat(r.statusCode()).isEqualTo(409)
        assertThat(r.body()).contains("LEASE_LOST")
    }

    @Test
    fun `cancelled scan stops the running job on heartbeat`() {
        val f = fixture()
        val xss = f.jobs[ModuleType.XSS]
        internal.post("/internal/v1/jobs/$xss/claim", claimBody(), InternalApiClient.XSS)
        assertThat(f.user.post("/api/v1/scans/${f.scanId}/cancel").statusCode()).isEqualTo(200)
        assertThat(scans.findById(f.scanId).orElseThrow().status).isEqualTo(ScanStatus.CANCELLING)

        val r = internal.post("/internal/v1/jobs/$xss/heartbeat", hbBody(), InternalApiClient.XSS)
        assertThat(r.statusCode()).isEqualTo(200)
        assertThat(r.body()).contains("\"cancel\":true")
        assertThat(jobs.findById(xss!!).orElseThrow().status).isEqualTo(JobStatus.CANCELLED)
        assertThat(scans.findById(f.scanId).orElseThrow().status).isEqualTo(ScanStatus.CANCELLED)
        // queued SQLI job was cancelled immediately by the cancel call
        assertThat(jobs.findById(f.jobs[ModuleType.SQLI]!!).orElseThrow().status).isEqualTo(JobStatus.CANCELLED)
        // после отмены lease больше не продлевается
        assertThat(internal.post("/internal/v1/jobs/$xss/heartbeat", hbBody(), InternalApiClient.XSS).statusCode()).isEqualTo(409)
    }

    @Test
    fun `claim of a cancelled job is gone`() {
        val f = fixture()
        f.user.post("/api/v1/scans/${f.scanId}/cancel")
        val r = internal.post("/internal/v1/jobs/${f.jobs[ModuleType.XSS]}/claim", claimBody(), InternalApiClient.XSS)
        assertThat(r.statusCode()).isEqualTo(410)
        assertThat(r.body()).contains("JOB_CANCELLED")
    }

    @Test
    fun `identities are issued only to the idor worker holding the lease`() {
        val f = fixture()
        val idorJob = addIdorJob(f)
        val path = "/internal/v1/jobs/$idorJob/identities?attempt=1"

        assertThat(internal.get(path, InternalApiClient.XSS).statusCode()).isEqualTo(403)
        assertThat(internal.get(path, InternalApiClient.IDOR, "w-other").statusCode()).isEqualTo(403)
        assertThat(internal.get("/internal/v1/jobs/$idorJob/identities?attempt=2", InternalApiClient.IDOR).statusCode()).isEqualTo(403)

        val ok = internal.get(path, InternalApiClient.IDOR)
        assertThat(ok.statusCode()).isEqualTo(200)
        assertThat(ok.headers().firstValue("Cache-Control").orElse("")).contains("no-store")
        assertThat(ok.body()).contains("SECRET-alice").contains("SECRET-bob")
        val events = audits.findAll().filter { it.action == "IDENTITY_SECRETS_ISSUED" && it.subjectId == idorJob }
        assertThat(events).hasSize(1)
        assertThat(Json.write(events.single().details!!)).doesNotContain("SECRET")
    }

    @Test
    fun `identities are limited to three calls per job`() {
        val f = fixture()
        val idorJob = addIdorJob(f)
        val path = "/internal/v1/jobs/$idorJob/identities?attempt=1"
        repeat(3) { assertThat(internal.get(path, InternalApiClient.IDOR).statusCode()).isEqualTo(200) }
        assertThat(internal.get(path, InternalApiClient.IDOR).statusCode()).isEqualTo(429)
    }
}

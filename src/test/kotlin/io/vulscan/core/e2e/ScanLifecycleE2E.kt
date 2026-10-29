package io.vulscan.core.e2e

import io.vulscan.core.domain.JobStatus
import io.vulscan.core.domain.ScanStatus
import io.vulscan.core.domain.UserRole
import io.vulscan.core.persistence.FindingRepository
import io.vulscan.core.persistence.ScanJobRepository
import io.vulscan.core.persistence.ScanRepository
import io.vulscan.core.persistence.UserEntity
import io.vulscan.core.persistence.UserRepository
import io.vulscan.core.support.ApiClient
import io.vulscan.core.support.PostgresTestBase
import io.vulscan.kit.contracts.ContractExamples
import io.vulscan.kit.contracts.Fingerprint
import io.vulscan.kit.contracts.FindingPayload
import io.vulscan.kit.contracts.FindingReportedPayload
import io.vulscan.kit.contracts.Json
import io.vulscan.kit.contracts.ModuleType
import io.vulscan.kit.net.ScopeDenial
import io.vulscan.kit.net.ScopeViolationException
import io.vulscan.kit.worker.DetectionEngine
import io.vulscan.kit.worker.JobContext
import io.vulscan.kit.worker.WorkerProperties
import io.vulscan.kit.worker.WorkerRuntime
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.web.server.LocalServerPort
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.test.context.TestPropertySource
import java.util.UUID

/** Сквозной сценарий без UI: Core, PostgreSQL, Kafka и настоящие воркеры на kit с простыми движками. */
@TestPropertySource(properties = ["scanner.outbox.enabled=true", "scanner.outbox.poll-ms=200"])
class ScanLifecycleE2E : PostgresTestBase() {
    @LocalServerPort private var port: Int = 0
    @Autowired lateinit var users: UserRepository
    @Autowired lateinit var encoder: PasswordEncoder
    @Autowired lateinit var scans: ScanRepository
    @Autowired lateinit var jobs: ScanJobRepository
    @Autowired lateinit var findings: FindingRepository
    @Autowired lateinit var kafkaContainer: org.testcontainers.kafka.KafkaContainer

    private val runtimes = mutableListOf<WorkerRuntime>()

    @AfterEach
    fun stopWorkers() {
        runtimes.forEach { it.stop() }
        runtimes.clear()
    }

    /** Движок, который сообщает по одной находке на endpoint задания. */
    private class EchoEngine(override val moduleType: ModuleType) : DetectionEngine {
        override fun run(ctx: JobContext) {
            ctx.job.endpoints.forEach { endpoint ->
                ctx.report(finding(ctx.job.moduleType, endpoint.url, endpoint.endpointId))
                ctx.stats.findingReported()
                ctx.stats.endpointTested()
            }
        }
    }

    /** Движок, который сразу падает без повторов. */
    private class FailingEngine(override val moduleType: ModuleType) : DetectionEngine {
        override fun run(ctx: JobContext) {
            throw ScopeViolationException(ScopeDenial.OUT_OF_SCOPE, "blocked by test")
        }
    }

    private fun startWorker(engine: DetectionEngine, token: String) {
        val runtime = WorkerRuntime.create(
            engine,
            WorkerProperties(
                coreBaseUrl = "http://localhost:$port", serviceToken = token, bootstrapServers = kafkaContainer.bootstrapServers,
                consumerGroup = "e2e-" + engine.moduleType.name.lowercase() + "-" + UUID.randomUUID(),
            ),
        )
        runtime.start()
        runtimes += runtime
    }

    private fun await(seconds: Long = 90, condition: () -> Boolean) {
        val end = System.currentTimeMillis() + seconds * 1000
        while (System.currentTimeMillis() < end) {
            if (condition()) return
            Thread.sleep(300)
        }
        throw AssertionError("Condition was not met in $seconds s")
    }

    private fun client(role: UserRole): ApiClient {
        val name = "u-" + UUID.randomUUID().toString().take(8)
        users.save(UserEntity(username = name, passwordHash = encoder.encode("pw-$name")!!, role = role))
        return ApiClient(port).also { assertThat(it.login(name, "pw-$name").statusCode()).isEqualTo(200) }
    }

    private fun createScan(user: ApiClient): UUID {
        val host = "app-${UUID.randomUUID().toString().take(6)}.test"
        val targetId = user.field(user.post("/api/v1/targets", """{"name":"lab","baseUrl":"http://$host:8080"}"""), "id")
        assertThat(client(UserRole.ADMIN).post("/api/v1/targets/$targetId/approve").statusCode()).isEqualTo(200)
        val e1 = user.field(user.post("/api/v1/targets/$targetId/endpoints", """{"method":"GET","url":"http://$host:8080/search","parameters":[{"name":"q","location":"QUERY"}],"idempotent":true}"""), "id")
        val e2 = user.field(user.post("/api/v1/targets/$targetId/endpoints", """{"method":"GET","url":"http://$host:8080/items","parameters":[{"name":"id","location":"QUERY"}],"idempotent":true}"""), "id")
        val response = user.post("/api/v1/scans", """{"targetId":"$targetId","modules":["XSS","SQLI"],"endpointIds":["$e1","$e2"]}""")
        assertThat(response.statusCode()).isEqualTo(202)
        return UUID.fromString(user.field(response, "id"))
    }

    @Test
    fun `scan with two healthy modules completes and stores findings`() {
        startWorker(EchoEngine(ModuleType.XSS), "test-token-xss")
        startWorker(EchoEngine(ModuleType.SQLI), "test-token-sqli")
        val user = client(UserRole.USER)
        val scanId = createScan(user)

        await { scans.findById(scanId).orElseThrow().status == ScanStatus.COMPLETED }
        val scanJobs = jobs.findByScanId(scanId)
        assertThat(scanJobs).hasSize(2).allMatch { it.status == JobStatus.COMPLETED && it.attempt == 1 }
        val stored = findings.findAll().filter { it.scanId == scanId }
        assertThat(stored).hasSize(4)
        assertThat(stored.map { it.moduleType }.toSet()).containsExactlyInAnyOrder(ModuleType.XSS, ModuleType.SQLI)

        val api = user.get("/api/v1/scans/$scanId")
        assertThat(api.body()).contains("\"status\":\"COMPLETED\"").contains("\"findingCounts\"")
        assertThat(user.get("/api/v1/findings?scanId=$scanId").body()).contains("\"total\":4")
    }

    @Test
    fun `failure of one module without retry gives a partially completed scan`() {
        startWorker(EchoEngine(ModuleType.XSS), "test-token-xss")
        startWorker(FailingEngine(ModuleType.SQLI), "test-token-sqli")
        val user = client(UserRole.USER)
        val scanId = createScan(user)

        await { scans.findById(scanId).orElseThrow().status == ScanStatus.PARTIALLY_COMPLETED }
        val byModule = jobs.findByScanId(scanId).associateBy { it.moduleType }
        assertThat(byModule[ModuleType.XSS]!!.status).isEqualTo(JobStatus.COMPLETED)
        assertThat(byModule[ModuleType.SQLI]!!.status).isEqualTo(JobStatus.FAILED)
        assertThat(byModule[ModuleType.SQLI]!!.errorCode).isEqualTo("SCOPE_VIOLATION")
        assertThat(findings.findAll().filter { it.scanId == scanId }.map { it.moduleType }.toSet()).containsExactly(ModuleType.XSS)
    }

    @Test
    fun `scan waits while no worker is running and finishes once one starts`() {
        val user = client(UserRole.USER)
        val scanId = createScan(user)
        Thread.sleep(2000)
        assertThat(scans.findById(scanId).orElseThrow().status).isIn(ScanStatus.PENDING, ScanStatus.RUNNING)
        startWorker(EchoEngine(ModuleType.XSS), "test-token-xss")
        startWorker(EchoEngine(ModuleType.SQLI), "test-token-sqli")
        await { scans.findById(scanId).orElseThrow().status == ScanStatus.COMPLETED }
    }

    companion object {
        fun finding(module: ModuleType, url: String, endpointId: UUID): FindingPayload {
            val template = Json.payloadAs(Json.readEnvelope(ContractExamples.valid("finding-xss.json")), FindingReportedPayload::class.java).finding
            return template.copy(
                moduleType = module, url = url, endpointId = endpointId,
                fingerprint = Fingerprint.of(module.name, url, endpointId.toString()),
            )
        }
    }
}

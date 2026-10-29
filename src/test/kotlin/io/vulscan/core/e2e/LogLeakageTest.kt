package io.vulscan.core.e2e

import io.vulscan.core.domain.JobStatus
import io.vulscan.core.domain.UserRole
import io.vulscan.core.messaging.OutboxRelay
import io.vulscan.core.persistence.AuditEventRepository
import io.vulscan.core.persistence.OutboxEventRepository
import io.vulscan.core.persistence.ScanJobRepository
import io.vulscan.core.persistence.UserEntity
import io.vulscan.core.persistence.UserRepository
import io.vulscan.core.support.ApiClient
import io.vulscan.core.support.InternalApiClient
import io.vulscan.core.support.PostgresTestBase
import io.vulscan.kit.contracts.Json
import io.vulscan.kit.contracts.KafkaTopics
import io.vulscan.kit.contracts.ModuleType
import org.apache.kafka.clients.consumer.ConsumerConfig
import org.apache.kafka.clients.consumer.KafkaConsumer
import org.apache.kafka.common.serialization.StringDeserializer
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtendWith
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.system.CapturedOutput
import org.springframework.boot.test.system.OutputCaptureExtension
import org.springframework.boot.test.web.server.LocalServerPort
import org.springframework.security.crypto.password.PasswordEncoder
import java.time.Duration
import java.time.Instant
import java.util.Properties
import java.util.UUID

/** Секреты идентичностей не должны попадать в логи, ответы пользовательского API, аудит и сообщения Kafka. */
@ExtendWith(OutputCaptureExtension::class)
class LogLeakageTest : PostgresTestBase() {
    @LocalServerPort private var port: Int = 0
    @Autowired lateinit var users: UserRepository
    @Autowired lateinit var encoder: PasswordEncoder
    @Autowired lateinit var jobs: ScanJobRepository
    @Autowired lateinit var audits: AuditEventRepository
    @Autowired lateinit var outbox: OutboxEventRepository
    @Autowired lateinit var relay: OutboxRelay
    @Autowired lateinit var kafkaContainer: org.testcontainers.kafka.KafkaContainer

    private val password = "S3cretPassw0rd!"
    private val token = "BobT0kenValue-9f3a7c"

    private fun client(role: UserRole): ApiClient {
        val name = "u-" + UUID.randomUUID().toString().take(8)
        users.save(UserEntity(username = name, passwordHash = encoder.encode("pw-$name")!!, role = role))
        return ApiClient(port).also { assertThat(it.login(name, "pw-$name").statusCode()).isEqualTo(200) }
    }

    private fun kafkaDump(): String {
        val consumer = KafkaConsumer<String, String>(
            Properties().apply {
                put(ConsumerConfig.BOOTSTRAP_SERVERS_CONFIG, kafkaContainer.bootstrapServers)
                put(ConsumerConfig.GROUP_ID_CONFIG, "dump-" + UUID.randomUUID())
                put(ConsumerConfig.KEY_DESERIALIZER_CLASS_CONFIG, StringDeserializer::class.java.name)
                put(ConsumerConfig.VALUE_DESERIALIZER_CLASS_CONFIG, StringDeserializer::class.java.name)
                put(ConsumerConfig.AUTO_OFFSET_RESET_CONFIG, "earliest")
            },
        )
        val builder = StringBuilder()
        consumer.use {
            it.subscribe(ModuleType.entries.map(KafkaTopics::jobsFor) + KafkaTopics.JOB_EVENTS + KafkaTopics.DLQ)
            val end = System.currentTimeMillis() + 8_000
            while (System.currentTimeMillis() < end) it.poll(Duration.ofMillis(300)).forEach { r -> builder.append(r.value()).append('\n') }
        }
        return builder.toString()
    }

    @Test
    fun `identity secrets never leak`(output: CapturedOutput) {
        val user = client(UserRole.USER)
        val responses = StringBuilder()
        fun record(response: java.net.http.HttpResponse<String>): java.net.http.HttpResponse<String> {
            responses.append(response.body()).append('\n')
            return response
        }

        val host = "app-${UUID.randomUUID().toString().take(6)}.test"
        val targetId = user.field(record(user.post("/api/v1/targets", """{"name":"lab","baseUrl":"http://$host:8080"}""")), "id")
        record(client(UserRole.ADMIN).post("/api/v1/targets/$targetId/approve"))
        val endpointId = user.field(record(user.post("/api/v1/targets/$targetId/endpoints", """{"method":"GET","url":"http://$host:8080/orders/1","idempotent":true}""")), "id")
        val alice = user.field(
            record(
                user.post(
                    "/api/v1/targets/$targetId/identities",
                    """{"label":"alice","role":"USER","authType":"FORM_LOGIN","authConfig":{"loginUrl":"http://$host:8080/login","usernameField":"u","passwordField":"p"},"secret":{"username":"alice","password":"$password"}}""",
                ),
            ),
            "id",
        )
        val bob = user.field(
            record(user.post("/api/v1/targets/$targetId/identities", """{"label":"bob","role":"USER","authType":"BEARER_STATIC","secret":{"token":"$token"}}""")),
            "id",
        )
        record(
            user.post(
                "/api/v1/targets/$targetId/access-rules",
                """{"endpointId":"$endpointId","idParameter":{"name":"id","location":"PATH"},"idValue":"1","ownerIdentityId":"$alice",
                    "sensitivity":"HIGH","ownerMarkers":["${'$'}.email"],"access":[{"identityId":"$bob","expected":"DENY"}]}""",
            ),
        )
        record(user.get("/api/v1/targets/$targetId/identities"))
        // неудачный вход тоже не должен светить пароль
        record(ApiClient(port).login("nobody", password))

        val scan = record(user.post("/api/v1/scans", """{"targetId":"$targetId","modules":["IDOR"],"endpointIds":["$endpointId"],"idor":{"identityIds":["$alice","$bob"]}}"""))
        assertThat(scan.statusCode()).isEqualTo(202)
        val scanId = UUID.fromString(user.field(scan, "id"))
        record(user.get("/api/v1/scans/$scanId"))
        record(user.get("/api/v1/findings?scanId=$scanId"))

        // публикация в Kafka и выдача секретов владельцу lease: тело этого ответа содержит секреты по определению
        relay.publishBatch()
        val job = jobs.findByScanId(scanId).single()
        assertThat(job.status).isEqualTo(JobStatus.QUEUED)
        val internal = InternalApiClient(port)
        assertThat(internal.post("/internal/v1/jobs/${job.id}/claim", """{"attempt":1,"workerId":"w-1"}""", InternalApiClient.IDOR).statusCode()).isEqualTo(200)
        val issued = internal.get("/internal/v1/jobs/${job.id}/identities?attempt=1", InternalApiClient.IDOR)
        assertThat(issued.statusCode()).isEqualTo(200)
        assertThat(issued.body()).contains(password).contains(token)
        // посторонний запрос секретов отклоняется и тоже не оставляет следов
        internal.get("/internal/v1/jobs/${job.id}/identities?attempt=1", InternalApiClient.IDOR, "w-other")

        val auditDump = audits.findAll().joinToString("\n") { "${it.action} ${it.details}" }
        val outboxDump = outbox.findAll().joinToString("\n") { "${it.payload} ${it.headers}" }
        val kafka = kafkaDump()
        assertThat(kafka).contains(job.id.toString())

        for ((name, text) in mapOf("responses" to responses.toString(), "logs" to output.all, "audit" to auditDump, "outbox" to outboxDump, "kafka" to kafka)) {
            assertThat(text).`as`("secret password in $name").doesNotContain(password)
            assertThat(text).`as`("secret token in $name").doesNotContain(token)
        }
        assertThat(Instant.now()).isNotNull()
        assertThat(Json.write(mapOf("ok" to true))).isNotBlank()
    }
}

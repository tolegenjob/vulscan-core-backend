package io.vulscan.core

import io.micrometer.core.instrument.MeterRegistry
import io.vulscan.core.domain.OutboxStatus
import io.vulscan.core.domain.UserRole
import io.vulscan.core.persistence.OutboxEventEntity
import io.vulscan.core.persistence.OutboxEventRepository
import io.vulscan.core.persistence.UserEntity
import io.vulscan.core.persistence.UserRepository
import io.vulscan.core.scheduling.RetentionCleaner
import io.vulscan.core.support.ApiClient
import io.vulscan.core.support.PostgresTestBase
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.web.server.LocalServerPort
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.security.crypto.password.PasswordEncoder
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.time.Instant
import java.util.UUID

class OperationsIT : PostgresTestBase() {
    @LocalServerPort private var port: Int = 0
    @Autowired lateinit var registry: MeterRegistry
    @Autowired lateinit var cleaner: RetentionCleaner
    @Autowired lateinit var jdbc: JdbcTemplate
    @Autowired lateinit var outbox: OutboxEventRepository
    @Autowired lateinit var users: UserRepository
    @Autowired lateinit var encoder: PasswordEncoder

    @Test
    fun `readiness reports database and kafka`() {
        val response = HttpClient.newHttpClient().send(
            HttpRequest.newBuilder(URI("http://localhost:$port/actuator/health/readiness")).GET().build(), HttpResponse.BodyHandlers.ofString(),
        )
        assertThat(response.statusCode()).isEqualTo(200)
        assertThat(response.body()).contains("\"status\":\"UP\"")
    }

    @Test
    fun `scan creation is counted and the outbox gauge is registered`() {
        val before = registry.counter("scanner.scans.created").count()
        val name = "u-" + UUID.randomUUID().toString().take(8)
        users.save(UserEntity(username = name, passwordHash = encoder.encode("pw-$name")!!, role = UserRole.USER))
        val admin = "a-" + UUID.randomUUID().toString().take(8)
        users.save(UserEntity(username = admin, passwordHash = encoder.encode("pw-$admin")!!, role = UserRole.ADMIN))
        val user = ApiClient(port).also { it.login(name, "pw-$name") }
        val host = "app-${UUID.randomUUID().toString().take(6)}.test"
        val targetId = user.field(user.post("/api/v1/targets", """{"name":"lab","baseUrl":"http://$host:8080"}"""), "id")
        ApiClient(port).also { it.login(admin, "pw-$admin") }.post("/api/v1/targets/$targetId/approve")
        val endpointId = user.field(user.post("/api/v1/targets/$targetId/endpoints", """{"method":"GET","url":"http://$host:8080/s","parameters":[{"name":"q","location":"QUERY"}],"idempotent":true}"""), "id")
        assertThat(user.post("/api/v1/scans", """{"targetId":"$targetId","modules":["XSS"],"endpointIds":["$endpointId"]}""").statusCode()).isEqualTo(202)

        assertThat(registry.counter("scanner.scans.created").count()).isEqualTo(before + 1)
        assertThat(registry.get("scanner.outbox.pending").gauge().value()).isGreaterThanOrEqualTo(1.0)
    }

    @Test
    fun `retention removes only old service records`() {
        val oldId = UUID.randomUUID()
        val freshId = UUID.randomUUID()
        jdbc.update("INSERT INTO processed_messages (message_id, consumer, processed_at) VALUES (?, 'x', now() - interval '10 days')", oldId)
        jdbc.update("INSERT INTO processed_messages (message_id, consumer, processed_at) VALUES (?, 'x', now())", freshId)
        val oldEvent = outbox.saveAndFlush(
            OutboxEventEntity(aggregateId = UUID.randomUUID(), topic = "t", messageKey = "k", status = OutboxStatus.SENT, sentAt = Instant.now().minusSeconds(10 * 86400)),
        )
        val pending = outbox.saveAndFlush(OutboxEventEntity(aggregateId = UUID.randomUUID(), topic = "t", messageKey = "k"))

        assertThat(cleaner.clean()).isGreaterThanOrEqualTo(2)
        assertThat(jdbc.queryForObject("SELECT count(*) FROM processed_messages WHERE message_id = ?", Long::class.java, oldId)).isZero()
        assertThat(jdbc.queryForObject("SELECT count(*) FROM processed_messages WHERE message_id = ?", Long::class.java, freshId)).isEqualTo(1L)
        assertThat(outbox.findById(oldEvent.id)).isEmpty()
        assertThat(outbox.findById(pending.id)).isPresent()
    }
}

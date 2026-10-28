package io.vulscan.core.application

import io.vulscan.core.domain.UserRole
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

class TargetAccessIT : PostgresTestBase() {
    @LocalServerPort private var port: Int = 0
    @Autowired lateinit var users: UserRepository
    @Autowired lateinit var encoder: PasswordEncoder

    private fun newUser(role: UserRole = UserRole.USER): Pair<String, String> {
        val name = "u-" + UUID.randomUUID().toString().take(8)
        users.save(UserEntity(username = name, passwordHash = encoder.encode("pw-$name")!!, role = role))
        return name to "pw-$name"
    }

    private fun client(user: Pair<String, String>) = ApiClient(port).also { assertThat(it.login(user.first, user.second).statusCode()).isEqualTo(200) }

    private fun createTarget(c: ApiClient, host: String = "app-${UUID.randomUUID().toString().take(6)}.test"): String {
        val response = c.post("/api/v1/targets", """{"name":"lab","baseUrl":"http://$host:8080"}""")
        assertThat(response.statusCode()).isEqualTo(201)
        return c.field(response, "id")
    }

    @Test
    fun `other users cannot see a target but admin can`() {
        val a = client(newUser())
        val b = client(newUser())
        val admin = client(newUser(UserRole.ADMIN))
        val id = createTarget(a)

        assertThat(a.get("/api/v1/targets/$id").statusCode()).isEqualTo(200)
        val foreign = b.get("/api/v1/targets/$id")
        assertThat(foreign.statusCode()).isEqualTo(404)
        assertThat(foreign.body()).contains("NOT_FOUND")
        assertThat(admin.get("/api/v1/targets/$id").statusCode()).isEqualTo(200)
        assertThat(b.get("/api/v1/targets").body()).doesNotContain(id)
        assertThat(b.post("/api/v1/targets/$id/verify").statusCode()).isEqualTo(404)
        assertThat(b.delete("/api/v1/targets/$id").statusCode()).isEqualTo(404)
    }

    @Test
    fun `new target is pending and shows verification instructions`() {
        val a = client(newUser())
        val response = a.post("/api/v1/targets", """{"name":"lab","baseUrl":"http://pending.test:8080"}""")
        assertThat(response.statusCode()).isEqualTo(201)
        assertThat(response.body()).contains("PENDING_VERIFICATION").contains("/.well-known/vulnscan-").contains("\"method\":\"FILE\"")
    }

    @Test
    fun `dangerous target is rejected with scope violation`() {
        val a = client(newUser())
        listOf("http://127.0.0.1:8080", "http://private.test:8080", "http://169.254.169.254").forEach { url ->
            val r = a.post("/api/v1/targets", """{"name":"x","baseUrl":"$url"}""")
            assertThat(r.statusCode()).`as`(url).isEqualTo(422)
            assertThat(r.body()).contains("SCOPE_VIOLATION")
        }
    }

    @Test
    fun `duplicate target url is a conflict`() {
        val a = client(newUser())
        createTarget(a, "dup.test")
        assertThat(a.post("/api/v1/targets", """{"name":"again","baseUrl":"http://dup.test:8080"}""").statusCode()).isEqualTo(409)
    }

    @Test
    fun `only admin can approve`() {
        val owner = client(newUser())
        val admin = client(newUser(UserRole.ADMIN))
        val id = createTarget(owner)
        assertThat(owner.post("/api/v1/targets/$id/approve").statusCode()).isEqualTo(403)
        val approved = admin.post("/api/v1/targets/$id/approve")
        assertThat(approved.statusCode()).isEqualTo(200)
        assertThat(approved.body()).contains("\"status\":\"VERIFIED\"").doesNotContain("expectedContent")
    }

    @Test
    fun `verify fails when the file is absent`() {
        val a = client(newUser())
        val id = createTarget(a)
        val r = a.post("/api/v1/targets/$id/verify")
        assertThat(r.statusCode()).isEqualTo(409)
        assertThat(r.body()).contains("VERIFICATION_FAILED")
    }

    @Test
    fun `target without scans is deleted`() {
        val a = client(newUser())
        val id = createTarget(a)
        assertThat(a.delete("/api/v1/targets/$id").statusCode()).isEqualTo(204)
        assertThat(a.get("/api/v1/targets/$id").statusCode()).isEqualTo(404)
    }

    @Test
    fun `validation errors list fields`() {
        val a = client(newUser())
        val r = a.post("/api/v1/targets", """{"name":"","baseUrl":""}""")
        assertThat(r.statusCode()).isEqualTo(400)
        assertThat(r.body()).contains("VALIDATION_FAILED").contains("fieldErrors")
    }
}

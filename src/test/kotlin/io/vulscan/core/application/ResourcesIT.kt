package io.vulscan.core.application

import io.vulscan.core.domain.UserRole
import io.vulscan.core.persistence.UserEntity
import io.vulscan.core.persistence.UserRepository
import io.vulscan.core.support.ApiClient
import io.vulscan.core.support.PostgresTestBase
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtendWith
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.system.CapturedOutput
import org.springframework.boot.test.system.OutputCaptureExtension
import org.springframework.boot.test.web.server.LocalServerPort
import org.springframework.security.crypto.password.PasswordEncoder
import java.util.UUID

@ExtendWith(OutputCaptureExtension::class)
class ResourcesIT : PostgresTestBase() {
    @LocalServerPort private var port: Int = 0
    @Autowired lateinit var users: UserRepository
    @Autowired lateinit var encoder: PasswordEncoder

    private fun client(role: UserRole = UserRole.USER): ApiClient {
        val name = "u-" + UUID.randomUUID().toString().take(8)
        users.save(UserEntity(username = name, passwordHash = encoder.encode("pw-$name")!!, role = role))
        return ApiClient(port).also { assertThat(it.login(name, "pw-$name").statusCode()).isEqualTo(200) }
    }

    private fun target(c: ApiClient): Pair<String, String> {
        val host = "app-${UUID.randomUUID().toString().take(6)}.test"
        val r = c.post("/api/v1/targets", """{"name":"lab","baseUrl":"http://$host:8080"}""")
        assertThat(r.statusCode()).isEqualTo(201)
        return c.field(r, "id") to host
    }

    @Test
    fun `endpoints respect target scope and uniqueness`() {
        val c = client()
        val (id, host) = target(c)
        val ok = c.post("/api/v1/targets/$id/endpoints", """{"method":"GET","url":"http://$host:8080/search?x=1","parameters":[{"name":"q","location":"QUERY"}],"idempotent":true}""")
        assertThat(ok.statusCode()).isEqualTo(201)
        assertThat(c.post("/api/v1/targets/$id/endpoints", """{"method":"GET","url":"http://$host:8080/search?x=1"}""").statusCode()).isEqualTo(409)
        val foreign = c.post("/api/v1/targets/$id/endpoints", """{"method":"GET","url":"http://evil.test:8080/x"}""")
        assertThat(foreign.statusCode()).isEqualTo(422)
        assertThat(foreign.body()).contains("SCOPE_VIOLATION")
        assertThat(c.get("/api/v1/targets/$id/endpoints").body()).contains("/search")
    }

    @Test
    fun `other users cannot touch endpoints of a foreign target`() {
        val owner = client()
        val other = client()
        val (id, host) = target(owner)
        assertThat(other.get("/api/v1/targets/$id/endpoints").statusCode()).isEqualTo(404)
        assertThat(other.post("/api/v1/targets/$id/endpoints", """{"method":"GET","url":"http://$host:8080/x"}""").statusCode()).isEqualTo(404)
    }

    @Test
    fun `openapi import creates endpoints and reports skipped ones`() {
        val c = client()
        val (id, host) = target(c)
        val doc = """{"openapi":"3.0.3","paths":{"/a":{"get":{}},"/b/{id}":{"get":{"parameters":[{"name":"id","in":"path"}]},"put":{}}}}"""
        val r = c.post("/api/v1/targets/$id/endpoints/import-openapi", """{"serverUrl":"http://$host:8080","document":$doc}""")
        assertThat(r.statusCode()).isEqualTo(200)
        assertThat(r.body()).contains("\"created\":2").contains("UNSUPPORTED_METHOD")
        val again = c.post("/api/v1/targets/$id/endpoints/import-openapi", """{"serverUrl":"http://$host:8080","document":$doc}""")
        assertThat(again.body()).contains("\"created\":0").contains("DUPLICATE")
        val outside = c.post("/api/v1/targets/$id/endpoints/import-openapi", """{"serverUrl":"http://evil.test:8080","document":$doc}""")
        assertThat(outside.body()).contains("\"created\":0").contains("OUT_OF_SCOPE")
    }

    @Test
    fun `identity secret never appears in responses or logs`(output: CapturedOutput) {
        val c = client()
        val (id, host) = target(c)
        val secret = "Sup3r-S3cret-Pass-" + UUID.randomUUID()
        val body = """{"label":"alice","role":"USER","authType":"FORM_LOGIN",
            "authConfig":{"loginUrl":"http://$host:8080/login","usernameField":"u","passwordField":"p"},
            "secret":{"username":"alice","password":"$secret"}}"""
        val created = c.post("/api/v1/targets/$id/identities", body)
        assertThat(created.statusCode()).isEqualTo(201)
        assertThat(created.body()).contains("\"hasSecret\":true").doesNotContain(secret)
        assertThat(c.get("/api/v1/targets/$id/identities").body()).doesNotContain(secret).doesNotContain("\"password\"")
        assertThat(c.post("/api/v1/targets/$id/identities", body).statusCode()).isEqualTo(409)
        assertThat(output.all).doesNotContain(secret)

        val admin = client(UserRole.ADMIN)
        assertThat(admin.get("/api/v1/audit-events?size=100").body()).doesNotContain(secret).contains("IDENTITY_CREATED")
    }

    @Test
    fun `identity validation and scope`() {
        val c = client()
        val (id, host) = target(c)
        val missing = c.post("/api/v1/targets/$id/identities", """{"label":"x","role":"USER","authType":"BEARER_STATIC","secret":{}}""")
        assertThat(missing.statusCode()).isEqualTo(400)
        val outside = c.post(
            "/api/v1/targets/$id/identities",
            """{"label":"y","role":"USER","authType":"FORM_LOGIN","authConfig":{"loginUrl":"http://evil.test/login","usernameField":"u","passwordField":"p"},"secret":{"username":"a","password":"b"}}""",
        )
        assertThat(outside.statusCode()).isEqualTo(422)
        assertThat(host).isNotBlank()
    }

    @Test
    fun `test login requires a verified target`() {
        val c = client()
        val (id, host) = target(c)
        val created = c.post(
            "/api/v1/targets/$id/identities",
            """{"label":"t","role":"USER","authType":"BEARER_STATIC","secret":{"token":"abc"}}""",
        )
        val identityId = c.field(created, "id")
        assertThat(c.post("/api/v1/targets/$id/identities/$identityId/test-login").statusCode()).isEqualTo(409)
        assertThat(host).isNotBlank()
    }

    @Test
    fun `access rules are validated against the target`() {
        val c = client()
        val (id, host) = target(c)
        val endpoint = c.field(c.post("/api/v1/targets/$id/endpoints", """{"method":"GET","url":"http://$host:8080/orders/1","idempotent":true}"""), "id")
        val alice = c.field(c.post("/api/v1/targets/$id/identities", """{"label":"alice","role":"USER","authType":"BEARER_STATIC","secret":{"token":"a"}}"""), "id")
        val bob = c.field(c.post("/api/v1/targets/$id/identities", """{"label":"bob","role":"USER","authType":"BEARER_STATIC","secret":{"token":"b"}}"""), "id")
        val rule = """{"endpointId":"$endpoint","idParameter":{"name":"id","location":"PATH"},"idValue":"1","ownerIdentityId":"$alice",
            "sensitivity":"HIGH","ownerMarkers":["${'$'}.email"],"access":[{"identityId":"$bob","expected":"DENY"}]}"""
        val created = c.post("/api/v1/targets/$id/access-rules", rule)
        assertThat(created.statusCode()).isEqualTo(201)
        assertThat(c.get("/api/v1/targets/$id/access-rules").body()).contains("DENY")

        val badOwner = rule.replace(alice, UUID.randomUUID().toString())
        assertThat(c.post("/api/v1/targets/$id/access-rules", badOwner).statusCode()).isEqualTo(400)
        val badMarker = rule.replace("${'$'}.email", "email")
        assertThat(c.post("/api/v1/targets/$id/access-rules", badMarker).statusCode()).isEqualTo(400)

        val ruleId = c.field(created, "id")
        assertThat(c.delete("/api/v1/targets/$id/access-rules/$ruleId").statusCode()).isEqualTo(204)
    }

    @Test
    fun `policies are listed and audit is admin only`() {
        val c = client()
        assertThat(c.get("/api/v1/policies").body()).contains("LIGHT").contains("NORMAL")
        assertThat(c.get("/api/v1/audit-events").statusCode()).isEqualTo(403)
        assertThat(client(UserRole.ADMIN).get("/api/v1/audit-events").statusCode()).isEqualTo(200)
    }
}

package io.vulscan.core.api

import io.vulscan.core.domain.TriageStatus
import io.vulscan.core.domain.UserRole
import io.vulscan.core.persistence.AuditEventRepository
import io.vulscan.core.persistence.FindingEntity
import io.vulscan.core.persistence.PersistenceTestBase
import io.vulscan.core.persistence.UserEntity
import io.vulscan.core.support.ApiClient
import io.vulscan.kit.contracts.Json
import io.vulscan.kit.contracts.ModuleType
import io.vulscan.kit.contracts.Severity
import io.vulscan.kit.contracts.Verdict
import io.vulscan.kit.contracts.VulnType
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.web.server.LocalServerPort
import org.springframework.security.crypto.password.PasswordEncoder
import java.util.UUID

class FindingApiIT : PersistenceTestBase() {
    @LocalServerPort private var port: Int = 0
    @Autowired lateinit var encoder: PasswordEncoder
    @Autowired lateinit var audits: AuditEventRepository

    private class Owner(val chain: Chain, val client: ApiClient)

    private fun owner(): Owner {
        val chain = newChain()
        val user = users.findById(chain.userId).orElseThrow()
        user.passwordHash = encoder.encode("pw-${user.username}")!!
        users.saveAndFlush(user)
        val client = ApiClient(port)
        assertThat(client.login(user.username, "pw-${user.username}").statusCode()).isEqualTo(200)
        return Owner(chain, client)
    }

    private fun admin(): ApiClient {
        val name = "adm-" + UUID.randomUUID().toString().take(8)
        users.saveAndFlush(UserEntity(username = name, passwordHash = encoder.encode("pw-$name")!!, role = UserRole.ADMIN))
        return ApiClient(port).also { assertThat(it.login(name, "pw-$name").statusCode()).isEqualTo(200) }
    }

    private fun add(
        c: Chain,
        severity: Severity = Severity.HIGH,
        module: ModuleType = ModuleType.XSS,
        vuln: VulnType = VulnType.XSS_REFLECTED,
        verdict: Verdict = Verdict.CONFIRMED,
        confidence: Int = 80,
        title: String = "title",
        url: String = "http://lab/x",
        endpointId: UUID? = null,
        triage: TriageStatus = TriageStatus.OPEN,
    ): FindingEntity = findings.saveAndFlush(
        newFinding(c).also {
            it.severity = severity; it.moduleType = module; it.vulnType = vuln; it.verdict = verdict
            it.confidence = confidence.toShort(); it.title = title; it.url = url; it.endpointId = endpointId; it.triageStatus = triage
        },
    )

    private fun ids(client: ApiClient, query: String): List<String> {
        val response = client.get("/api/v1/findings?$query")
        assertThat(response.statusCode()).`as`(response.body()).isEqualTo(200)
        return Json.mapper.readTree(response.body()).get("items").toList().map { it.get("id").asString() }
    }

    @Test
    fun `every filter narrows the list`() {
        val o = owner()
        val endpoint = UUID.randomUUID()
        val a = add(o.chain, Severity.CRITICAL, ModuleType.SQLI, VulnType.SQLI_ERROR_BASED, Verdict.CONFIRMED, 95, "SQL error in login", "http://lab/login", endpoint)
        val b = add(o.chain, Severity.LOW, ModuleType.XSS, VulnType.XSS_STORED, Verdict.SUSPECTED, 40, "Stored script", "http://lab/comments", null, TriageStatus.FALSE_POSITIVE)
        val c = add(o.chain, Severity.HIGH, ModuleType.IDOR, VulnType.IDOR_HORIZONTAL, Verdict.LIKELY, 70, "Foreign order readable", "http://lab/orders/1")
        val scan = o.chain.scanId
        assertThat(ids(o.client, "scanId=$scan")).containsExactlyInAnyOrder(a.id.toString(), b.id.toString(), c.id.toString())
        assertThat(ids(o.client, "scanId=${UUID.randomUUID()}")).isEmpty()
        assertThat(ids(o.client, "targetId=${o.chain.targetId}")).hasSize(3)
        assertThat(ids(o.client, "moduleType=SQLI")).containsExactly(a.id.toString())
        assertThat(ids(o.client, "vulnType=XSS_STORED")).containsExactly(b.id.toString())
        assertThat(ids(o.client, "severity=HIGH")).containsExactly(c.id.toString())
        assertThat(ids(o.client, "verdict=SUSPECTED")).containsExactly(b.id.toString())
        assertThat(ids(o.client, "minConfidence=70")).containsExactlyInAnyOrder(a.id.toString(), c.id.toString())
        assertThat(ids(o.client, "triageStatus=FALSE_POSITIVE")).containsExactly(b.id.toString())
        assertThat(ids(o.client, "endpoint=$endpoint")).containsExactly(a.id.toString())
        assertThat(ids(o.client, "q=ORDER")).containsExactly(c.id.toString())
        assertThat(ids(o.client, "q=lab/login")).containsExactly(a.id.toString())
        assertThat(ids(o.client, "q=100%25")).isEmpty()
    }

    @Test
    fun `page size above the limit is rejected`() {
        val o = owner()
        val r = o.client.get("/api/v1/findings?size=1000")
        assertThat(r.statusCode()).isEqualTo(400)
        assertThat(r.body()).contains("PAGE_SIZE_TOO_LARGE")
        assertThat(o.client.get("/api/v1/findings?size=100").statusCode()).isEqualTo(200)
        assertThat(o.client.get("/api/v1/findings?sort=evidence,asc").statusCode()).isEqualTo(400)
        assertThat(o.client.get("/api/v1/findings?minConfidence=100").statusCode()).isEqualTo(400)
    }

    @Test
    fun `severity sorts by rank and pagination works`() {
        val o = owner()
        val bySeverity = Severity.entries.shuffled().associateWith { add(o.chain, it).id.toString() }
        val desc = ids(o.client, "scanId=${o.chain.scanId}&sort=severity,desc")
        assertThat(desc).containsExactly(
            bySeverity[Severity.CRITICAL], bySeverity[Severity.HIGH], bySeverity[Severity.MEDIUM], bySeverity[Severity.LOW], bySeverity[Severity.INFO],
        )
        assertThat(ids(o.client, "scanId=${o.chain.scanId}&sort=severity,asc").first()).isEqualTo(bySeverity[Severity.INFO])
        val page2 = Json.mapper.readTree(o.client.get("/api/v1/findings?scanId=${o.chain.scanId}&sort=severity,desc&size=2&page=1").body())
        assertThat(page2.get("total").asInt()).isEqualTo(5)
        assertThat(page2.get("items").toList().map { it.get("id").asString() }).containsExactly(bySeverity[Severity.MEDIUM], bySeverity[Severity.LOW])
    }

    @Test
    fun `list items carry no evidence or details but the detail view does`() {
        val o = owner()
        val f = add(o.chain)
        val list = o.client.get("/api/v1/findings?scanId=${o.chain.scanId}").body()
        assertThat(list).doesNotContain("evidence").doesNotContain("\"details\"")
        val detail = o.client.get("/api/v1/findings/${f.id}")
        assertThat(detail.statusCode()).isEqualTo(200)
        assertThat(detail.body()).contains("\"evidence\"").contains("\"details\"")
    }

    @Test
    fun `another user sees nothing and an admin sees everything`() {
        val a = owner()
        val b = owner()
        val f = add(a.chain, title = "secret-title-" + UUID.randomUUID())
        assertThat(ids(b.client, "scanId=${a.chain.scanId}")).isEmpty()
        assertThat(ids(b.client, "q=secret-title")).isEmpty()
        assertThat(b.client.get("/api/v1/findings/${f.id}").statusCode()).isEqualTo(404)
        assertThat(b.client.patch("/api/v1/findings/${f.id}", """{"triageStatus":"FIXED"}""").statusCode()).isEqualTo(404)
        assertThat(ids(admin(), "scanId=${a.chain.scanId}")).containsExactly(f.id.toString())
    }

    @Test
    fun `triage changes only the triage status and is audited`() {
        val o = owner()
        val f = add(o.chain)
        val r = o.client.patch("/api/v1/findings/${f.id}", """{"triageStatus":"FALSE_POSITIVE","severity":"INFO","title":"hacked"}""")
        assertThat(r.statusCode()).isEqualTo(200)
        val after = findings.findById(f.id).orElseThrow()
        assertThat(after.triageStatus).isEqualTo(TriageStatus.FALSE_POSITIVE)
        assertThat(after.severity).isEqualTo(Severity.HIGH)
        assertThat(after.title).isEqualTo("title")
        assertThat(audits.findAll().count { it.action == "FINDING_TRIAGED" && it.subjectId == f.id }).isEqualTo(1)
        assertThat(o.client.patch("/api/v1/findings/${f.id}", """{"triageStatus":"BOGUS"}""").statusCode()).isEqualTo(400)
        assertThat(o.client.patch("/api/v1/findings/${f.id}", """{}""").statusCode()).isEqualTo(400)
        // возврат в OPEN допустим
        assertThat(o.client.patch("/api/v1/findings/${f.id}", """{"triageStatus":"OPEN"}""").statusCode()).isEqualTo(200)
    }
}

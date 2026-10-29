package io.vulscan.core.application

import io.vulscan.core.persistence.PersistenceTestBase
import io.vulscan.core.support.ApiClient
import io.vulscan.kit.contracts.Json
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.web.server.LocalServerPort
import org.springframework.security.crypto.password.PasswordEncoder

class DashboardQueryIT : PersistenceTestBase() {
    @LocalServerPort private var port: Int = 0
    @Autowired lateinit var encoder: PasswordEncoder

    @Test
    fun `summary over 5000 findings matches manual counts and is fast`() {
        val chain = newChain()
        val user = users.findById(chain.userId).orElseThrow()
        user.passwordHash = encoder.encode("pw-${user.username}")!!
        users.saveAndFlush(user)
        jdbc.update(
            """
            INSERT INTO findings (job_id, scan_id, target_id, module_type, vuln_type, verdict, severity, confidence, fingerprint,
                                  method, url, title, summary, recommendation, cwe, details, evidence, triage_status)
            SELECT ?::uuid, ?::uuid, ?::uuid,
                   (ARRAY['XSS','SQLI','IDOR'])[1 + g % 3], 'XSS_REFLECTED',
                   (ARRAY['SUSPECTED','LIKELY','CONFIRMED'])[1 + g % 3],
                   (ARRAY['INFO','LOW','MEDIUM','HIGH','CRITICAL'])[1 + g % 5], 50,
                   md5(g::text) || md5((g * 7)::text), 'GET', 'http://lab/' || g, 't', 's', 'r', 'CWE-79', '{}'::jsonb, '{}'::jsonb,
                   CASE WHEN g % 5 = 0 THEN 'FIXED' ELSE 'OPEN' END
            FROM generate_series(1, 5000) g
            """.trimIndent(),
            chain.jobId.toString(), chain.scanId.toString(), chain.targetId.toString(),
        )
        val client = ApiClient(port)
        assertThat(client.login(user.username, "pw-${user.username}").statusCode()).isEqualTo(200)

        client.get("/api/v1/dashboard/summary") // прогрев
        val started = System.nanoTime()
        val response = client.get("/api/v1/dashboard/summary")
        val elapsedMs = (System.nanoTime() - started) / 1_000_000
        assertThat(response.statusCode()).isEqualTo(200)
        println("DASHBOARD_SUMMARY_MS=$elapsedMs")
        assertThat(elapsedMs).isLessThan(1000)

        val json = Json.mapper.readTree(response.body())
        fun manual(column: String) = jdbc.queryForList(
            "SELECT $column AS k, count(*) AS c FROM findings WHERE scan_id = ?::uuid AND triage_status = 'OPEN' GROUP BY $column", chain.scanId.toString(),
        ).associate { it["k"] as String to (it["c"] as Number).toLong() }

        val bySeverity = manual("severity")
        listOf("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL").forEach {
            assertThat(json.get("openFindingsBySeverity").get(it).asLong()).`as`(it).isEqualTo(bySeverity[it] ?: 0L)
        }
        val byModule = manual("module_type")
        listOf("XSS", "SQLI", "IDOR").forEach { assertThat(json.get("openFindingsByModule").get(it).asLong()).isEqualTo(byModule[it] ?: 0L) }
        val byVerdict = manual("verdict")
        listOf("SUSPECTED", "LIKELY", "CONFIRMED").forEach { assertThat(json.get("openFindingsByVerdict").get(it).asLong()).isEqualTo(byVerdict[it] ?: 0L) }
        assertThat(json.get("openFindingsBySeverity").map { it.asLong() }.sum()).isEqualTo(4000L)
        assertThat(json.get("recentScans")).hasSize(1)
        assertThat(json.get("activeScans").asLong()).isEqualTo(1L)
    }
}

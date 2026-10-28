package io.vulscan.core.persistence

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

/** Контекст стартует с ddl-auto=validate, значит схема после миграций совпадает с сущностями. */
class MigrationIT : PersistenceTestBase() {

    @Test
    fun `all tables exist`() {
        val tables = jdbc.queryForList("SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'", String::class.java)
        assertThat(tables).contains(
            "users", "targets", "target_endpoints", "scan_policies", "test_identities", "resource_access_rules",
            "scans", "scan_jobs", "findings", "outbox_events", "processed_messages", "audit_events",
            "spring_session", "spring_session_attributes",
        )
    }

    @Test
    fun `seed policies are present`() {
        val light = policies.findByName("LIGHT")!!
        val normal = policies.findByName("NORMAL")!!
        assertThat(light.limits.maxRequests).isEqualTo(200)
        assertThat(light.limits.requestsPerSecond).isEqualTo(2)
        assertThat(normal.limits.maxRequests).isEqualTo(600)
        assertThat(normal.limits.maxConcurrency).isEqualTo(2)
    }

    @Test
    fun `json columns round trip`() {
        val chain = newChain()
        val target = targets.findById(chain.targetId).orElseThrow()
        assertThat(target.allowedHosts).hasSize(1)
        assertThat(target.allowedHosts[0].ports).containsExactly(8080)
    }
}

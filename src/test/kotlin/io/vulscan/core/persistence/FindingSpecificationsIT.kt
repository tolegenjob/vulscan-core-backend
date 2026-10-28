package io.vulscan.core.persistence

import io.vulscan.core.domain.TriageStatus
import io.vulscan.kit.contracts.ModuleType
import io.vulscan.kit.contracts.Severity
import io.vulscan.kit.contracts.Verdict
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import org.springframework.data.domain.PageRequest
import java.util.UUID

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class FindingSpecificationsIT : PersistenceTestBase() {

    private lateinit var chain: Chain
    private val severities = Severity.entries.filter { it != Severity.CRITICAL }
    private val verdicts = Verdict.entries
    private val modules = ModuleType.entries
    private val triage = TriageStatus.entries

    @BeforeAll
    fun seed() {
        chain = newChain()
        val rows = (0 until 1000).map { i ->
            newFinding(chain, "%064x".format(i)).apply {
                severity = severities[i % severities.size]
                verdict = verdicts[i % verdicts.size]
                moduleType = modules[i % modules.size]
                triageStatus = triage[i % triage.size]
                parameterName = "p${i % 5}"
            }
        }
        findings.saveAll(rows)
        findings.flush()
    }

    private fun expected(predicate: (Int) -> Boolean) = (0 until 1000).count(predicate)

    @Test
    fun `severity filter`() {
        val spec = FindingSpecifications.filter(scanId = chain.scanId, severity = Severity.HIGH)
        assertThat(findings.count(spec)).isEqualTo(expected { severities[it % severities.size] == Severity.HIGH }.toLong())
    }

    @Test
    fun `combined filters`() {
        val spec = FindingSpecifications.filter(
            scanId = chain.scanId, verdict = Verdict.LIKELY, moduleType = ModuleType.SQLI, triageStatus = TriageStatus.OPEN, parameterName = "p3",
        )
        val count = expected {
            verdicts[it % verdicts.size] == Verdict.LIKELY && modules[it % modules.size] == ModuleType.SQLI &&
                triage[it % triage.size] == TriageStatus.OPEN && it % 5 == 3
        }
        assertThat(findings.count(spec)).isEqualTo(count.toLong())
    }

    @Test
    fun `no filters returns all scan findings`() {
        assertThat(findings.count(FindingSpecifications.filter(scanId = chain.scanId))).isEqualTo(1000)
    }

    @Test
    fun `page size is respected`() {
        val page = findings.findAll(FindingSpecifications.filter(scanId = chain.scanId), PageRequest.of(0, 25))
        assertThat(page.content).hasSize(25)
        assertThat(page.totalElements).isEqualTo(1000)
    }

    @Test
    fun `other scans are not included`() {
        assertThat(findings.count(FindingSpecifications.filter(scanId = UUID.randomUUID()))).isZero()
    }
}

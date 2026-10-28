package io.vulscan.core.persistence

import io.vulscan.core.domain.ScanStatus
import io.vulscan.kit.contracts.ModuleType
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.junit.jupiter.api.Test
import org.springframework.dao.DataIntegrityViolationException
import java.time.Instant

class ConstraintsIT : PersistenceTestBase() {

    @Test
    fun `duplicate module per scan is rejected`() {
        val chain = newChain(ModuleType.XSS)
        assertThatThrownBy {
            jobs.saveAndFlush(ScanJobEntity(scanId = chain.scanId, moduleType = ModuleType.XSS, deadlineAt = Instant.now()))
        }.isInstanceOf(DataIntegrityViolationException::class.java)
    }

    @Test
    fun `duplicate fingerprint per job is rejected`() {
        val chain = newChain()
        val fingerprint = "a".repeat(64)
        findings.saveAndFlush(newFinding(chain, fingerprint))
        assertThatThrownBy { findings.saveAndFlush(newFinding(chain, fingerprint)) }
            .isInstanceOf(DataIntegrityViolationException::class.java)
    }

    @Test
    fun `same fingerprint in another job is allowed`() {
        val first = newChain()
        val second = newChain()
        val fingerprint = "b".repeat(64)
        findings.saveAndFlush(newFinding(first, fingerprint))
        findings.saveAndFlush(newFinding(second, fingerprint))
    }

    @Test
    fun `confidence outside 1 to 99 is rejected`() {
        val chain = newChain()
        listOf<Short>(0, 100).forEach { value ->
            assertThatThrownBy { findings.saveAndFlush(newFinding(chain).apply { confidence = value }) }
                .isInstanceOf(DataIntegrityViolationException::class.java)
        }
    }

    @Test
    fun `malformed fingerprint is rejected`() {
        val chain = newChain()
        assertThatThrownBy { findings.saveAndFlush(newFinding(chain, "XYZ")) }.isInstanceOf(DataIntegrityViolationException::class.java)
    }

    @Test
    fun `unknown scan status is rejected by the database`() {
        val chain = newChain()
        assertThatThrownBy { jdbc.update("UPDATE scans SET status = 'BOGUS' WHERE id = ?", chain.scanId) }
            .isInstanceOf(DataIntegrityViolationException::class.java)
    }

    @Test
    fun `duplicate target url per owner is rejected`() {
        val chain = newChain()
        val existing = targets.findById(chain.targetId).orElseThrow()
        assertThatThrownBy {
            targets.saveAndFlush(TargetEntity(ownerId = existing.ownerId, name = "dup", baseUrl = existing.baseUrl, verificationToken = "t"))
        }.isInstanceOf(DataIntegrityViolationException::class.java)
    }

    @Test
    fun `user with scan history cannot be deleted`() {
        val chain = newChain()
        assertThatThrownBy { jdbc.update("DELETE FROM users WHERE id = ?", chain.userId) }
            .isInstanceOf(DataIntegrityViolationException::class.java)
    }

    @Test
    fun `deleting a scan cascades to jobs and findings`() {
        val chain = newChain()
        findings.saveAndFlush(newFinding(chain))
        jdbc.update("DELETE FROM scans WHERE id = ?", chain.scanId)
        assertThat(jobs.findByScanId(chain.scanId)).isEmpty()
        assertThat(findings.findAll().filter { it.scanId == chain.scanId }).isEmpty()
    }

    @Test
    fun `scan status enum persists`() {
        val chain = newChain()
        val scan = scans.findById(chain.scanId).orElseThrow()
        scan.status = ScanStatus.RUNNING
        scans.saveAndFlush(scan)
        assertThat(scans.findById(chain.scanId).orElseThrow().status).isEqualTo(ScanStatus.RUNNING)
    }
}

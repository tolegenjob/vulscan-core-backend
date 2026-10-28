package io.vulscan.core.persistence

import io.vulscan.core.domain.UserRole
import io.vulscan.core.support.PostgresTestBase
import io.vulscan.kit.contracts.AllowedHost
import io.vulscan.kit.contracts.ModuleType
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.jdbc.core.JdbcTemplate
import java.time.Instant
import java.util.UUID

abstract class PersistenceTestBase : PostgresTestBase() {
    @Autowired lateinit var users: UserRepository
    @Autowired lateinit var targets: TargetRepository
    @Autowired lateinit var policies: ScanPolicyRepository
    @Autowired lateinit var scans: ScanRepository
    @Autowired lateinit var jobs: ScanJobRepository
    @Autowired lateinit var findings: FindingRepository
    @Autowired lateinit var jdbc: JdbcTemplate

    data class Chain(val userId: UUID, val targetId: UUID, val policyId: UUID, val scanId: UUID, val jobId: UUID)

    /** Создаёт цепочку user → target → scan → job с уникальными данными. */
    fun newChain(module: ModuleType = ModuleType.XSS): Chain {
        val suffix = UUID.randomUUID().toString().take(8)
        val user = users.saveAndFlush(UserEntity(username = "user-$suffix", passwordHash = "x", role = UserRole.USER))
        val target = targets.saveAndFlush(
            TargetEntity(
                ownerId = user.id, name = "t-$suffix", baseUrl = "http://lab-$suffix:8080",
                allowedHosts = listOf(AllowedHost("lab-$suffix", listOf(8080))), verificationToken = "tok",
            ),
        )
        val policy = policies.findByName("NORMAL")!!
        val scan = scans.saveAndFlush(ScanEntity(targetId = target.id, policyId = policy.id, startedBy = user.id))
        val job = jobs.saveAndFlush(ScanJobEntity(scanId = scan.id, moduleType = module, deadlineAt = Instant.now().plusSeconds(600)))
        return Chain(user.id, target.id, policy.id, scan.id, job.id)
    }

    fun newFinding(chain: Chain, fingerprint: String = UUID.randomUUID().toString().replace("-", "").repeat(2)): FindingEntity =
        FindingEntity(
            jobId = chain.jobId, scanId = chain.scanId, targetId = chain.targetId, fingerprint = fingerprint,
            url = "http://lab/x", title = "t", summary = "s", recommendation = "r", cwe = "CWE-79",
            details = mapOf("type" to "XSS_REFLECTED"), evidence = mapOf("request" to mapOf("method" to "GET")),
        )
}

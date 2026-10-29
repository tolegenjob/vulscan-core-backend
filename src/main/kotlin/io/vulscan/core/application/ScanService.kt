package io.vulscan.core.application

import io.vulscan.core.config.ScannerProperties
import io.vulscan.core.domain.IllegalStateTransitionException
import io.vulscan.core.domain.JobStateMachine
import io.vulscan.core.domain.JobStatus
import io.vulscan.core.domain.NotFoundException
import io.vulscan.core.domain.PayloadTooLargeException
import io.vulscan.core.domain.ScanStatus
import io.vulscan.core.domain.ScanStatusAggregator
import io.vulscan.core.domain.TooManyActiveScansException
import io.vulscan.core.domain.ValidationFailedException
import io.vulscan.core.messaging.OutboxEventFactory
import io.vulscan.core.persistence.OutboxEventRepository
import io.vulscan.core.persistence.ResourceAccessRuleRepository
import io.vulscan.core.persistence.ScanEntity
import io.vulscan.core.persistence.ScanJobEntity
import io.vulscan.core.persistence.ScanJobRepository
import io.vulscan.core.persistence.ScanPolicyRepository
import io.vulscan.core.persistence.ScanRepository
import io.vulscan.core.persistence.TargetEndpointRepository
import io.vulscan.core.persistence.TestIdentityRepository
import io.vulscan.core.security.CurrentUser
import io.vulscan.core.security.OwnershipPolicy
import io.vulscan.kit.contracts.Json
import io.vulscan.kit.contracts.ModuleType
import io.vulscan.kit.contracts.ScanJobPayloadValidator
import org.springframework.data.domain.Page
import org.springframework.data.domain.PageRequest
import org.springframework.data.domain.Sort
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional
import java.time.Instant
import java.util.UUID

data class ScanView(val scan: ScanEntity, val jobs: List<ScanJobEntity>)

@Service
class ScanService(
    private val scans: ScanRepository,
    private val jobs: ScanJobRepository,
    private val outbox: OutboxEventRepository,
    private val policies: ScanPolicyRepository,
    private val endpoints: TargetEndpointRepository,
    private val identities: TestIdentityRepository,
    private val rules: ResourceAccessRuleRepository,
    private val targetService: TargetService,
    private val scopePolicy: ScopePolicyService,
    private val audit: AuditService,
    private val properties: ScannerProperties,
    private val jdbc: JdbcTemplate,
) {
    private val activeStatuses = listOf(ScanStatus.PENDING, ScanStatus.RUNNING, ScanStatus.CANCELLING)

    @Transactional
    fun create(user: CurrentUser, command: ScanCommand): ScanView {
        validateCommand(command)
        val target = targetService.requireVerified(user, command.targetId)
        // Адрес мог измениться после верификации: повторная проверка DNS и IpPolicy
        scopePolicy.validateTarget(target.baseUrl)

        val selected = endpoints.findByIdInAndTargetId(command.endpointIds.distinct(), target.id)
        if (selected.size != command.endpointIds.distinct().size) throw NotFoundException("Endpoint not found")

        val policy = (command.policyId?.let { policies.findById(it).orElse(null) } ?: policies.findByName("NORMAL"))
            ?: throw ValidationFailedException("Scan policy not found")

        val targetIdentities = identities.findByTargetId(target.id)
        if (ModuleType.IDOR in command.modules) validateIdor(command, targetIdentities.map { it.id })

        checkActiveLimits(user)

        val correlationId = UUID.randomUUID()
        val scan = scans.save(
            ScanEntity(
                targetId = target.id, policyId = policy.id, startedBy = user.id, correlationId = correlationId,
                config = Json.mapper.convertValue(command, Map::class.java).let { raw ->
                    @Suppress("UNCHECKED_CAST")
                    raw as Map<String, Any?>
                },
            ),
        )
        val deadline = Instant.now().plusSeconds((policy.limits.maxDurationSec + properties.jobs.queueTimeoutSec).toLong())
        val createdJobs = command.modules.distinct().map { module ->
            val job = jobs.save(ScanJobEntity(scanId = scan.id, moduleType = module, deadlineAt = deadline))
            val payload = ScanJobFactory.build(
                job.id, scan.id, module, job.attempt, deadline, policy.id, target, selected, policy.limits,
                command, targetIdentities, rules.findByTargetId(target.id),
            )
            val violations = ScanJobPayloadValidator.validate(payload)
            if (violations.isNotEmpty()) throw ValidationFailedException("Job is invalid: " + violations.joinToString { it.code.name })
            if (OutboxEventFactory.serializedSize(payload, correlationId) > MAX_PAYLOAD_BYTES) {
                throw PayloadTooLargeException("Scan job for $module is too large; select fewer endpoints")
            }
            outbox.save(OutboxEventFactory.jobMessage(payload, correlationId))
            job
        }
        audit.record("SCAN_CREATED", user.id, "SCAN", scan.id, mapOf("modules" to command.modules.map { it.name }, "endpoints" to selected.size))
        return ScanView(scan, createdJobs)
    }

    @Transactional(readOnly = true)
    fun get(user: CurrentUser, id: UUID): ScanView {
        val scan = scans.findById(id).orElseThrow { NotFoundException("Scan not found") }
        OwnershipPolicy.requireAccess(user, scan.startedBy)
        return ScanView(scan, jobs.findByScanId(id))
    }

    @Transactional(readOnly = true)
    fun list(user: CurrentUser, page: Int, size: Int): Page<ScanEntity> {
        val pageable = PageRequest.of(page.coerceAtLeast(0), size.coerceIn(1, 100), Sort.by(Sort.Direction.DESC, "createdAt"))
        return if (user.isAdmin) scans.findAll(pageable) else scans.findByStartedBy(user.id, pageable)
    }

    /** Запрашивает отмену: ещё не запущенные задания отменяются сразу, запущенные — по heartbeat. */
    @Transactional
    fun cancel(user: CurrentUser, id: UUID): ScanView {
        val scan = scans.lockById(id) ?: throw NotFoundException("Scan not found")
        OwnershipPolicy.requireAccess(user, scan.startedBy)
        val current = jobs.findByScanId(id)
        if (current.all { JobStateMachine.isTerminal(it.status) }) throw IllegalStateTransitionException("Scan is already finished")
        scan.cancelRequested = true
        current.filter { it.status == JobStatus.PENDING || it.status == JobStatus.QUEUED }.forEach { job ->
            JobStateMachine.transition(job.status, JobStatus.CANCELLED)
            job.status = JobStatus.CANCELLED
            job.finishedAt = Instant.now()
            jobs.save(job)
        }
        scan.status = ScanStatusAggregator.aggregate(current.map { it.status }, true)
        if (scan.status == ScanStatus.CANCELLED) scan.finishedAt = Instant.now()
        scans.save(scan)
        audit.record("SCAN_CANCEL_REQUESTED", user.id, "SCAN", scan.id)
        return ScanView(scan, current)
    }

    /** Создаёт новый скан с теми же параметрами; повторный запуск существующего скана не предусмотрен. */
    @Transactional
    fun rerun(user: CurrentUser, id: UUID): ScanView {
        val source = get(user, id)
        if (source.scan.status.isActive) throw IllegalStateTransitionException("Scan is still active")
        val command = Json.mapper.convertValue(source.scan.config, ScanCommand::class.java)
        return create(user, command)
    }

    private fun validateCommand(command: ScanCommand) {
        if (command.modules.isEmpty()) throw ValidationFailedException("modules must not be empty")
        if (command.modules.size != command.modules.distinct().size) throw ValidationFailedException("modules must not contain duplicates")
        if (command.endpointIds.isEmpty()) throw ValidationFailedException("endpointIds must not be empty")
        if (command.endpointIds.size > properties.jobs.maxEndpointsPerScan) {
            throw ValidationFailedException("At most ${properties.jobs.maxEndpointsPerScan} endpoints per scan")
        }
    }

    private fun validateIdor(command: ScanCommand, knownIdentities: List<UUID>) {
        val idor = command.idor ?: throw ValidationFailedException("idor options are required for the IDOR module")
        if (idor.identityIds.distinct().size < 2) throw ValidationFailedException("IDOR needs at least two identities")
        if (!knownIdentities.containsAll(idor.identityIds)) throw ValidationFailedException("Unknown identity")
    }

    /** Проверка лимитов под advisory-блокировкой: параллельные запросы не могут одновременно пройти проверку. */
    private fun checkActiveLimits(user: CurrentUser) {
        jdbc.execute("SELECT pg_advisory_xact_lock(hashtext('active-scans'))")
        if (scans.countByStartedByAndStatusIn(user.id, activeStatuses) >= properties.limits.maxActiveScansPerUser) {
            throw TooManyActiveScansException("Too many active scans for this user")
        }
        if (scans.countByStatusIn(activeStatuses) >= properties.limits.maxActiveScansGlobal) {
            throw TooManyActiveScansException("Too many active scans on the server")
        }
    }

    private companion object {
        const val MAX_PAYLOAD_BYTES = 900 * 1024
    }
}

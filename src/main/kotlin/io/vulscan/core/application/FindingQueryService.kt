package io.vulscan.core.application

import io.vulscan.core.domain.ErrorCodes
import io.vulscan.core.domain.NotFoundException
import io.vulscan.core.domain.TriageStatus
import io.vulscan.core.domain.ValidationFailedException
import io.vulscan.core.persistence.FindingEntity
import io.vulscan.core.persistence.FindingFilter
import io.vulscan.core.persistence.FindingListRow
import io.vulscan.core.persistence.FindingQueryRepository
import io.vulscan.core.persistence.FindingRepository
import io.vulscan.core.persistence.ScanRepository
import io.vulscan.core.security.CurrentUser
import io.vulscan.core.security.OwnershipPolicy
import org.springframework.data.domain.Page
import org.springframework.data.domain.PageRequest
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional
import java.util.UUID

@Service
class FindingQueryService(
    private val query: FindingQueryRepository,
    private val findings: FindingRepository,
    private val scans: ScanRepository,
    private val audit: AuditService,
) {

    /** @param sort `поле,направление`; поле из белого списка, по умолчанию `createdAt,desc`. */
    @Transactional(readOnly = true)
    fun list(user: CurrentUser, filter: FindingFilter, sort: String?, page: Int, size: Int): Page<FindingListRow> {
        if (size > MAX_PAGE_SIZE) throw ValidationFailedException("size must not exceed $MAX_PAGE_SIZE", ErrorCodes.PAGE_SIZE_TOO_LARGE)
        if (size < 1 || page < 0) throw ValidationFailedException("page must be >= 0 and size >= 1")
        if (filter.minConfidence != null && filter.minConfidence !in 1..99) throw ValidationFailedException("minConfidence must be 1..99")
        if ((filter.query?.length ?: 0) > 100) throw ValidationFailedException("q must not exceed 100 characters")
        val parts = (sort ?: "createdAt,desc").split(",")
        val field = parts[0].trim()
        if (field !in SORT_FIELDS) throw ValidationFailedException("Unsupported sort field: $field")
        val direction = parts.getOrNull(1)?.trim()?.lowercase() ?: "desc"
        if (direction != "asc" && direction != "desc") throw ValidationFailedException("Sort direction must be asc or desc")
        val scoped = filter.copy(ownerId = if (user.isAdmin) null else user.id)
        return query.search(scoped, PageRequest.of(page, size), field, direction == "asc")
    }

    @Transactional(readOnly = true)
    fun get(user: CurrentUser, id: UUID): FindingEntity = load(user, id)

    @Transactional
    fun triage(user: CurrentUser, id: UUID, status: TriageStatus): FindingEntity {
        val finding = load(user, id)
        val previous = finding.triageStatus
        if (previous != status) {
            finding.triageStatus = status
            findings.save(finding)
            audit.record("FINDING_TRIAGED", user.id, "FINDING", id, mapOf("from" to previous.name, "to" to status.name))
        }
        return finding
    }

    private fun load(user: CurrentUser, id: UUID): FindingEntity {
        val finding = findings.findById(id).orElseThrow { NotFoundException("Finding not found") }
        val scan = scans.findById(finding.scanId).orElseThrow { NotFoundException("Finding not found") }
        OwnershipPolicy.requireAccess(user, scan.startedBy)
        return finding
    }

    companion object {
        const val MAX_PAGE_SIZE = 100
        val SORT_FIELDS = setOf("createdAt", "severity", "confidence", "url")
    }
}

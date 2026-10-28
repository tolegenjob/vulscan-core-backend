package io.vulscan.core.application

import io.vulscan.core.domain.ForbiddenException
import io.vulscan.core.persistence.AuditEventEntity
import io.vulscan.core.persistence.AuditEventRepository
import io.vulscan.core.persistence.ScanPolicyEntity
import io.vulscan.core.persistence.ScanPolicyRepository
import io.vulscan.core.security.CurrentUser
import org.springframework.data.domain.Page
import org.springframework.data.domain.PageRequest
import org.springframework.data.domain.Sort
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional

@Service
class PolicyService(private val policies: ScanPolicyRepository) {
    @Transactional(readOnly = true)
    fun list(): List<ScanPolicyEntity> = policies.findAllByOrderByNameAsc()
}

@Service
class AuditQueryService(private val events: AuditEventRepository) {
    @Transactional(readOnly = true)
    fun list(user: CurrentUser, page: Int, size: Int): Page<AuditEventEntity> {
        if (!user.isAdmin) throw ForbiddenException()
        return events.findAll(PageRequest.of(page.coerceAtLeast(0), size.coerceIn(1, 100), Sort.by(Sort.Direction.DESC, "createdAt")))
    }
}

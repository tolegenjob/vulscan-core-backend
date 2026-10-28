package io.vulscan.core.application

import io.vulscan.core.domain.NotFoundException
import io.vulscan.core.domain.ValidationFailedException
import io.vulscan.core.persistence.ResourceAccessRuleEntity
import io.vulscan.core.persistence.ResourceAccessRuleRepository
import io.vulscan.core.persistence.TargetEndpointRepository
import io.vulscan.core.persistence.TestIdentityRepository
import io.vulscan.core.security.CurrentUser
import io.vulscan.kit.contracts.AccessRuleRef
import io.vulscan.kit.contracts.ParameterId
import io.vulscan.kit.contracts.Sensitivity
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional
import java.util.UUID

@Service
class AccessRuleService(
    private val rules: ResourceAccessRuleRepository,
    private val endpoints: TargetEndpointRepository,
    private val identities: TestIdentityRepository,
    private val targetService: TargetService,
    private val audit: AuditService,
) {
    @Transactional(readOnly = true)
    fun list(user: CurrentUser, targetId: UUID): List<ResourceAccessRuleEntity> {
        targetService.get(user, targetId)
        return rules.findByTargetId(targetId)
    }

    @Transactional
    fun create(
        user: CurrentUser,
        targetId: UUID,
        endpointId: UUID,
        idParameter: ParameterId,
        idValue: String,
        ownerIdentityId: UUID,
        sensitivity: Sensitivity,
        ownerMarkers: List<String>,
        access: List<AccessRuleRef>,
    ): ResourceAccessRuleEntity {
        targetService.get(user, targetId)
        endpoints.findByIdAndTargetId(endpointId, targetId) ?: throw ValidationFailedException("endpointId does not belong to the target")
        val known = identities.findByTargetId(targetId).map { it.id }.toSet()
        if (ownerIdentityId !in known) throw ValidationFailedException("ownerIdentityId does not belong to the target")
        val unknown = access.map { it.identityId }.filter { it !in known }
        if (unknown.isNotEmpty()) throw ValidationFailedException("access refers to identities outside the target")
        if (ownerMarkers.size > 20 || ownerMarkers.any { !it.startsWith("$") }) {
            throw ValidationFailedException("ownerMarkers must be at most 20 JSONPath expressions starting with $")
        }
        val saved = rules.save(
            ResourceAccessRuleEntity(
                targetId = targetId, endpointId = endpointId, idParameter = idParameter, idValue = idValue,
                ownerIdentityId = ownerIdentityId, sensitivity = sensitivity, ownerMarkers = ownerMarkers, access = access,
            ),
        )
        audit.record("ACCESS_RULE_CREATED", user.id, "ACCESS_RULE", saved.id)
        return saved
    }

    @Transactional
    fun delete(user: CurrentUser, targetId: UUID, ruleId: UUID) {
        targetService.get(user, targetId)
        val rule = rules.findByIdAndTargetId(ruleId, targetId) ?: throw NotFoundException("Access rule not found")
        rules.delete(rule)
        audit.record("ACCESS_RULE_DELETED", user.id, "ACCESS_RULE", ruleId)
    }
}

package io.vulscan.core.persistence

import org.springframework.data.domain.Page
import org.springframework.data.domain.Pageable
import org.springframework.data.jpa.repository.JpaRepository
import org.springframework.data.jpa.repository.JpaSpecificationExecutor
import java.util.UUID

interface UserRepository : JpaRepository<UserEntity, UUID> {
    fun findByUsername(username: String): UserEntity?
}

interface TargetRepository : JpaRepository<TargetEntity, UUID> {
    fun findByOwnerId(ownerId: UUID): List<TargetEntity>

    fun findByOwnerId(ownerId: UUID, pageable: Pageable): Page<TargetEntity>

    fun existsByOwnerIdAndBaseUrl(ownerId: UUID, baseUrl: String): Boolean
}

interface TargetEndpointRepository : JpaRepository<TargetEndpointEntity, UUID> {
    fun findByTargetId(targetId: UUID): List<TargetEndpointEntity>

    fun existsByTargetIdAndMethodAndUrl(targetId: UUID, method: io.vulscan.kit.contracts.HttpMethod, url: String): Boolean

    fun findByIdAndTargetId(id: UUID, targetId: UUID): TargetEndpointEntity?
}

interface ScanPolicyRepository : JpaRepository<ScanPolicyEntity, UUID> {
    fun findAllByOrderByNameAsc(): List<ScanPolicyEntity>

    fun findByName(name: String): ScanPolicyEntity?
}

interface TestIdentityRepository : JpaRepository<TestIdentityEntity, UUID> {
    fun findByTargetId(targetId: UUID): List<TestIdentityEntity>

    fun existsByTargetIdAndLabel(targetId: UUID, label: String): Boolean

    fun findByIdAndTargetId(id: UUID, targetId: UUID): TestIdentityEntity?
}

interface ResourceAccessRuleRepository : JpaRepository<ResourceAccessRuleEntity, UUID> {
    fun findByTargetId(targetId: UUID): List<ResourceAccessRuleEntity>

    fun findByIdAndTargetId(id: UUID, targetId: UUID): ResourceAccessRuleEntity?
}

interface ScanRepository : JpaRepository<ScanEntity, UUID> {
    fun existsByTargetId(targetId: UUID): Boolean
}

interface ScanJobRepository : JpaRepository<ScanJobEntity, UUID> {
    fun findByScanId(scanId: UUID): List<ScanJobEntity>
}

interface FindingRepository : JpaRepository<FindingEntity, UUID>, JpaSpecificationExecutor<FindingEntity>

interface OutboxEventRepository : JpaRepository<OutboxEventEntity, UUID>

interface ProcessedMessageRepository : JpaRepository<ProcessedMessageEntity, UUID>

interface AuditEventRepository : JpaRepository<AuditEventEntity, UUID>

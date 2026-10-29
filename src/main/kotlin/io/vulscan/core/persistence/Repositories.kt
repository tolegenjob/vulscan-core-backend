package io.vulscan.core.persistence

import org.springframework.data.domain.Page
import org.springframework.data.domain.Pageable
import org.springframework.data.jpa.repository.JpaRepository
import jakarta.persistence.LockModeType
import org.springframework.data.jpa.repository.Lock
import org.springframework.data.jpa.repository.Modifying
import org.springframework.data.jpa.repository.Query
import org.springframework.data.repository.query.Param
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

    fun findByIdInAndTargetId(ids: Collection<UUID>, targetId: UUID): List<TargetEndpointEntity>
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

    fun countByStartedByAndStatusIn(startedBy: UUID, statuses: Collection<io.vulscan.core.domain.ScanStatus>): Long

    fun countByStatusIn(statuses: Collection<io.vulscan.core.domain.ScanStatus>): Long

    fun findByStartedBy(startedBy: UUID, pageable: Pageable): Page<ScanEntity>

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select s from ScanEntity s where s.id = :id")
    fun lockById(@Param("id") id: UUID): ScanEntity?
}

interface ScanJobRepository : JpaRepository<ScanJobEntity, UUID> {
    fun findByScanId(scanId: UUID): List<ScanJobEntity>

    /** Атомарный захват: успешен только для QUEUED-задания с совпадающей попыткой. */
    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query(
        value = "UPDATE scan_jobs SET status = 'RUNNING', worker_id = :workerId, lease_expires_at = :leaseUntil, " +
            "started_at = COALESCE(started_at, now()) WHERE id = :id AND status = 'QUEUED' AND attempt = :attempt",
        nativeQuery = true,
    )
    fun claim(
        @Param("id") id: UUID,
        @Param("attempt") attempt: Int,
        @Param("workerId") workerId: String,
        @Param("leaseUntil") leaseUntil: java.time.Instant,
    ): Int

    /** Продление lease: успешно только для RUNNING-задания этого worker и этой попытки. */
    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query(
        value = "UPDATE scan_jobs SET lease_expires_at = :leaseUntil, requests_sent = :requestsSent, endpoints_done = :endpointsDone " +
            "WHERE id = :id AND status = 'RUNNING' AND worker_id = :workerId AND attempt = :attempt",
        nativeQuery = true,
    )
    fun extendLease(
        @Param("id") id: UUID,
        @Param("attempt") attempt: Int,
        @Param("workerId") workerId: String,
        @Param("leaseUntil") leaseUntil: java.time.Instant,
        @Param("requestsSent") requestsSent: Int,
        @Param("endpointsDone") endpointsDone: Int,
    ): Int

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select j from ScanJobEntity j where j.id = :id")
    fun lockById(@Param("id") id: UUID): ScanJobEntity?
}

interface FindingRepository : JpaRepository<FindingEntity, UUID>, JpaSpecificationExecutor<FindingEntity>

interface OutboxEventRepository : JpaRepository<OutboxEventEntity, UUID> {
    @Query(
        value = "SELECT * FROM outbox_events WHERE status = 'PENDING' AND next_attempt_at <= now() ORDER BY created_at LIMIT :limit FOR UPDATE SKIP LOCKED",
        nativeQuery = true,
    )
    fun lockPending(@Param("limit") limit: Int): List<OutboxEventEntity>
}

interface ProcessedMessageRepository : JpaRepository<ProcessedMessageEntity, UUID>

interface AuditEventRepository : JpaRepository<AuditEventEntity, UUID> {
    fun countByActionAndSubjectId(action: String, subjectId: UUID): Long
}

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

    /** Скалярный запрос: не загружает сущность в контекст, чтобы последующая блокировка прочитала свежее состояние. */
    @Query("select j.scanId from ScanJobEntity j where j.id = :id")
    fun findScanId(@Param("id") id: UUID): UUID?

    /** Кандидаты для watchdog: без блокировок, состояние перепроверяется под блокировкой. */
    @Query("select j.id from ScanJobEntity j where j.status = io.vulscan.core.domain.JobStatus.RUNNING and j.leaseExpiresAt < :now order by j.leaseExpiresAt")
    fun findLostLease(@Param("now") now: java.time.Instant, pageable: Pageable): List<UUID>

    @Query("select j.id from ScanJobEntity j where j.status = io.vulscan.core.domain.JobStatus.QUEUED and j.queuedAt < :threshold order by j.queuedAt")
    fun findStaleQueued(@Param("threshold") threshold: java.time.Instant, pageable: Pageable): List<UUID>

    @Query("select j.id from ScanJobEntity j where j.status = io.vulscan.core.domain.JobStatus.RUNNING and j.deadlineAt < :now order by j.deadlineAt")
    fun findPastDeadline(@Param("now") now: java.time.Instant, pageable: Pageable): List<UUID>
}

interface FindingRepository : JpaRepository<FindingEntity, UUID>, JpaSpecificationExecutor<FindingEntity> {
    fun countByJobId(jobId: UUID): Long

    @Query("select f.severity, count(f) from FindingEntity f where f.scanId = :scanId group by f.severity")
    fun countBySeverity(@Param("scanId") scanId: UUID): List<Array<Any>>

    /** Идемпотентная вставка: повтор того же (job_id, fingerprint) ничего не меняет. Возвращает число вставленных строк. */
    @Modifying(flushAutomatically = true)
    @Query(
        value = "INSERT INTO findings (id, job_id, scan_id, target_id, module_type, vuln_type, verdict, severity, confidence, fingerprint, " +
            "endpoint_id, method, url, parameter_name, parameter_location, title, summary, recommendation, cwe, details, evidence) " +
            "VALUES (:id, :jobId, :scanId, :targetId, :moduleType, :vulnType, :verdict, :severity, :confidence, :fingerprint, " +
            ":endpointId, :method, :url, :parameterName, :parameterLocation, :title, :summary, :recommendation, :cwe, " +
            "CAST(:details AS jsonb), CAST(:evidence AS jsonb)) ON CONFLICT (job_id, fingerprint) DO NOTHING",
        nativeQuery = true,
    )
    fun insertIgnore(
        @Param("id") id: UUID,
        @Param("jobId") jobId: UUID,
        @Param("scanId") scanId: UUID,
        @Param("targetId") targetId: UUID,
        @Param("moduleType") moduleType: String,
        @Param("vulnType") vulnType: String,
        @Param("verdict") verdict: String,
        @Param("severity") severity: String,
        @Param("confidence") confidence: Int,
        @Param("fingerprint") fingerprint: String,
        @Param("endpointId") endpointId: UUID?,
        @Param("method") method: String,
        @Param("url") url: String,
        @Param("parameterName") parameterName: String?,
        @Param("parameterLocation") parameterLocation: String?,
        @Param("title") title: String,
        @Param("summary") summary: String,
        @Param("recommendation") recommendation: String,
        @Param("cwe") cwe: String,
        @Param("details") details: String,
        @Param("evidence") evidence: String,
    ): Int
}

interface OutboxEventRepository : JpaRepository<OutboxEventEntity, UUID> {
    fun findFirstByAggregateIdOrderByCreatedAtDesc(aggregateId: UUID): OutboxEventEntity?

    /** Помечает неопубликованные сообщения задания отправленными, чтобы отменённое задание не попало в Kafka. */
    @Modifying(clearAutomatically = false, flushAutomatically = true)
    @Query(
        value = "UPDATE outbox_events SET status = 'SENT', sent_at = now(), headers = headers || jsonb_build_object('cancelled', 'true') " +
            "WHERE aggregate_id = :jobId AND status = 'PENDING'",
        nativeQuery = true,
    )
    fun cancelPending(@Param("jobId") jobId: UUID): Int

    @Query(
        value = "SELECT * FROM outbox_events WHERE status = 'PENDING' AND next_attempt_at <= now() ORDER BY created_at LIMIT :limit FOR UPDATE SKIP LOCKED",
        nativeQuery = true,
    )
    fun lockPending(@Param("limit") limit: Int): List<OutboxEventEntity>
}

interface ProcessedMessageRepository : JpaRepository<ProcessedMessageEntity, UUID> {
    /** Возвращает 1, если сообщение обрабатывается впервые, и 0 для дубликата. */
    @Modifying(flushAutomatically = true)
    @Query(
        value = "INSERT INTO processed_messages (message_id, consumer) VALUES (:id, :consumer) ON CONFLICT (message_id) DO NOTHING",
        nativeQuery = true,
    )
    fun markProcessed(@Param("id") id: UUID, @Param("consumer") consumer: String): Int
}

interface AuditEventRepository : JpaRepository<AuditEventEntity, UUID> {
    fun countByActionAndSubjectId(action: String, subjectId: UUID): Long
}

package io.vulscan.core.persistence

import io.vulscan.core.domain.JobStatus
import io.vulscan.core.domain.OutboxStatus
import io.vulscan.core.domain.ResultIntegrity
import io.vulscan.core.domain.ScanStatus
import io.vulscan.core.domain.TargetStatus
import io.vulscan.core.domain.TriageStatus
import io.vulscan.core.domain.UserRole
import io.vulscan.kit.contracts.AllowedHost
import io.vulscan.kit.contracts.AuthType
import io.vulscan.kit.contracts.HttpMethod
import io.vulscan.kit.contracts.JobStats
import io.vulscan.kit.contracts.ModuleType
import io.vulscan.kit.contracts.ParameterId
import io.vulscan.kit.contracts.ParameterRef
import io.vulscan.kit.contracts.ScanLimits
import io.vulscan.kit.contracts.Sensitivity
import io.vulscan.kit.contracts.Severity
import io.vulscan.kit.contracts.Verdict
import io.vulscan.kit.contracts.VulnType
import jakarta.persistence.Column
import jakarta.persistence.Entity
import jakarta.persistence.EnumType
import jakarta.persistence.Enumerated
import jakarta.persistence.Id
import jakarta.persistence.Table
import org.hibernate.annotations.JdbcTypeCode
import org.hibernate.type.SqlTypes
import java.time.Instant
import java.util.UUID

// Связи между сущностями хранятся как UUID без @ManyToOne: целостность обеспечивают внешние ключи БД,
// а запросы пишутся явно. Это исключает ленивую загрузку и N+1 в сервисах.

@Entity
@Table(name = "users")
class UserEntity(
    @Id var id: UUID = UUID.randomUUID(),
    var username: String = "",
    var passwordHash: String = "",
    @Enumerated(EnumType.STRING) var role: UserRole = UserRole.USER,
    var enabled: Boolean = true,
    var createdAt: Instant = Instant.now(),
)

@Entity
@Table(name = "targets")
class TargetEntity(
    @Id var id: UUID = UUID.randomUUID(),
    var ownerId: UUID = UUID.randomUUID(),
    var name: String = "",
    var baseUrl: String = "",
    @JdbcTypeCode(SqlTypes.JSON) var allowedHosts: List<AllowedHost> = emptyList(),
    @Enumerated(EnumType.STRING) var status: TargetStatus = TargetStatus.PENDING_VERIFICATION,
    var verificationToken: String = "",
    var verifiedAt: Instant? = null,
    var createdAt: Instant = Instant.now(),
)

@Entity
@Table(name = "target_endpoints")
class TargetEndpointEntity(
    @Id var id: UUID = UUID.randomUUID(),
    var targetId: UUID = UUID.randomUUID(),
    @Enumerated(EnumType.STRING) var method: HttpMethod = HttpMethod.GET,
    var url: String = "",
    @JdbcTypeCode(SqlTypes.JSON) var parameters: List<ParameterRef> = emptyList(),
    var idempotent: Boolean = false,
    var label: String? = null,
    var createdAt: Instant = Instant.now(),
)

@Entity
@Table(name = "scan_policies")
class ScanPolicyEntity(
    @Id var id: UUID = UUID.randomUUID(),
    var name: String = "",
    @JdbcTypeCode(SqlTypes.JSON) var limits: ScanLimits = ScanLimits(1, 1, 1, 1, 1, 1),
    var createdAt: Instant = Instant.now(),
)

@Entity
@Table(name = "test_identities")
class TestIdentityEntity(
    @Id var id: UUID = UUID.randomUUID(),
    var targetId: UUID = UUID.randomUUID(),
    var label: String = "",
    var role: String = "",
    @Enumerated(EnumType.STRING) var authType: AuthType = AuthType.BEARER_STATIC,
    @JdbcTypeCode(SqlTypes.JSON) var authConfig: Map<String, String> = emptyMap(),
    @Column(name = "secret_encrypted") var secretEncrypted: ByteArray = ByteArray(0),
    var keyVersion: Int = 1,
    var createdAt: Instant = Instant.now(),
)

@Entity
@Table(name = "resource_access_rules")
class ResourceAccessRuleEntity(
    @Id var id: UUID = UUID.randomUUID(),
    var targetId: UUID = UUID.randomUUID(),
    var endpointId: UUID = UUID.randomUUID(),
    @JdbcTypeCode(SqlTypes.JSON) var idParameter: ParameterId = ParameterId("id", io.vulscan.kit.contracts.ParamLocation.PATH),
    var idValue: String = "",
    var ownerIdentityId: UUID = UUID.randomUUID(),
    @Enumerated(EnumType.STRING) var sensitivity: Sensitivity = Sensitivity.LOW,
    @JdbcTypeCode(SqlTypes.JSON) var ownerMarkers: List<String> = emptyList(),
    @JdbcTypeCode(SqlTypes.JSON) var access: Map<String, Any?> = emptyMap(),
)

@Entity
@Table(name = "scans")
class ScanEntity(
    @Id var id: UUID = UUID.randomUUID(),
    var targetId: UUID = UUID.randomUUID(),
    var policyId: UUID = UUID.randomUUID(),
    var startedBy: UUID = UUID.randomUUID(),
    @Enumerated(EnumType.STRING) var status: ScanStatus = ScanStatus.PENDING,
    var cancelRequested: Boolean = false,
    var correlationId: UUID = UUID.randomUUID(),
    @JdbcTypeCode(SqlTypes.JSON) var config: Map<String, Any?> = emptyMap(),
    var createdAt: Instant = Instant.now(),
    var finishedAt: Instant? = null,
)

@Entity
@Table(name = "scan_jobs")
class ScanJobEntity(
    @Id var id: UUID = UUID.randomUUID(),
    var scanId: UUID = UUID.randomUUID(),
    @Enumerated(EnumType.STRING) var moduleType: ModuleType = ModuleType.XSS,
    @Enumerated(EnumType.STRING) var status: JobStatus = JobStatus.PENDING,
    var attempt: Int = 1,
    var workerId: String? = null,
    var leaseExpiresAt: Instant? = null,
    var deadlineAt: Instant = Instant.now(),
    var queuedAt: Instant? = null,
    var startedAt: Instant? = null,
    var finishedAt: Instant? = null,
    var requestsSent: Int = 0,
    var endpointsDone: Int = 0,
    var errorCode: String? = null,
    var errorMessage: String? = null,
    @Enumerated(EnumType.STRING) var resultIntegrity: ResultIntegrity = ResultIntegrity.OK,
    @JdbcTypeCode(SqlTypes.JSON) var stats: JobStats? = null,
)

@Entity
@Table(name = "findings")
class FindingEntity(
    @Id var id: UUID = UUID.randomUUID(),
    var jobId: UUID = UUID.randomUUID(),
    var scanId: UUID = UUID.randomUUID(),
    var targetId: UUID = UUID.randomUUID(),
    @Enumerated(EnumType.STRING) var moduleType: ModuleType = ModuleType.XSS,
    @Enumerated(EnumType.STRING) var vulnType: VulnType = VulnType.XSS_REFLECTED,
    @Enumerated(EnumType.STRING) var verdict: Verdict = Verdict.SUSPECTED,
    @Enumerated(EnumType.STRING) var severity: Severity = Severity.LOW,
    var confidence: Short = 50,
    var fingerprint: String = "",
    var endpointId: UUID? = null,
    var method: String = "GET",
    var url: String = "",
    var parameterName: String? = null,
    var parameterLocation: String? = null,
    var title: String = "",
    var summary: String = "",
    var recommendation: String = "",
    var cwe: String = "",
    @JdbcTypeCode(SqlTypes.JSON) var details: Map<String, Any?> = emptyMap(),
    @JdbcTypeCode(SqlTypes.JSON) var evidence: Map<String, Any?> = emptyMap(),
    @Enumerated(EnumType.STRING) var triageStatus: TriageStatus = TriageStatus.OPEN,
    var createdAt: Instant = Instant.now(),
)

@Entity
@Table(name = "outbox_events")
class OutboxEventEntity(
    @Id var id: UUID = UUID.randomUUID(),
    var aggregateId: UUID = UUID.randomUUID(),
    var topic: String = "",
    var messageKey: String = "",
    @JdbcTypeCode(SqlTypes.JSON) var payload: Map<String, Any?> = emptyMap(),
    @JdbcTypeCode(SqlTypes.JSON) var headers: Map<String, String> = emptyMap(),
    @Enumerated(EnumType.STRING) var status: OutboxStatus = OutboxStatus.PENDING,
    var attempts: Int = 0,
    var nextAttemptAt: Instant = Instant.now(),
    var createdAt: Instant = Instant.now(),
    var sentAt: Instant? = null,
)

@Entity
@Table(name = "processed_messages")
class ProcessedMessageEntity(
    @Id var messageId: UUID = UUID.randomUUID(),
    var consumer: String = "",
    var processedAt: Instant = Instant.now(),
)

@Entity
@Table(name = "audit_events")
class AuditEventEntity(
    @Id var id: UUID = UUID.randomUUID(),
    var actorId: UUID? = null,
    var action: String = "",
    var subjectType: String? = null,
    var subjectId: UUID? = null,
    @JdbcTypeCode(SqlTypes.JSON) var details: Map<String, Any?>? = null,
    var createdAt: Instant = Instant.now(),
)

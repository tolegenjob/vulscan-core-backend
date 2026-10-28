package io.vulscan.core.application

import io.vulscan.core.domain.ConflictException
import io.vulscan.core.domain.ErrorCodes
import io.vulscan.core.domain.NotFoundException
import io.vulscan.core.domain.ScopeViolationException
import io.vulscan.core.domain.TargetStatus
import io.vulscan.core.domain.ValidationFailedException
import io.vulscan.core.persistence.TestIdentityEntity
import io.vulscan.core.persistence.TestIdentityRepository
import io.vulscan.core.security.CurrentUser
import io.vulscan.core.security.SecretCipher
import io.vulscan.kit.contracts.AuthType
import io.vulscan.kit.contracts.Json
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional
import java.util.UUID

@Service
class IdentityService(
    private val identities: TestIdentityRepository,
    private val targetService: TargetService,
    private val cipher: SecretCipher,
    private val loginTester: IdentityLoginTester,
    private val audit: AuditService,
) {
    @Transactional(readOnly = true)
    fun list(user: CurrentUser, targetId: UUID): List<TestIdentityEntity> {
        targetService.get(user, targetId)
        return identities.findByTargetId(targetId)
    }

    @Transactional
    fun create(
        user: CurrentUser,
        targetId: UUID,
        label: String,
        role: String,
        authType: AuthType,
        authConfig: Map<String, String>,
        secret: Map<String, String>,
    ): TestIdentityEntity {
        val target = targetService.get(user, targetId)
        validateAuth(authType, authConfig, secret)
        authConfig["loginUrl"]?.let {
            TargetScope.normalize(target.allowedHosts, target.baseUrl, it) ?: throw ScopeViolationException("OUT_OF_SCOPE: login URL is outside the target")
        }
        if (identities.existsByTargetIdAndLabel(targetId, label)) throw ConflictException("Identity with this label already exists")
        val encrypted = cipher.encrypt(Json.write(secret).toByteArray(Charsets.UTF_8))
        val saved = identities.save(
            TestIdentityEntity(
                targetId = targetId, label = label, role = role, authType = authType, authConfig = authConfig,
                secretEncrypted = encrypted.bytes, keyVersion = encrypted.keyVersion,
            ),
        )
        // В аудит не попадают ни секрет, ни конфигурация
        audit.record("IDENTITY_CREATED", user.id, "IDENTITY", saved.id, mapOf("label" to label, "authType" to authType.name))
        return saved
    }

    @Transactional
    fun delete(user: CurrentUser, targetId: UUID, identityId: UUID) {
        targetService.get(user, targetId)
        val identity = identities.findByIdAndTargetId(identityId, targetId) ?: throw NotFoundException("Identity not found")
        identities.delete(identity)
        audit.record("IDENTITY_DELETED", user.id, "IDENTITY", identityId)
    }

    @Transactional(readOnly = true)
    fun testLogin(user: CurrentUser, targetId: UUID, identityId: UUID): LoginTestResult {
        val target = targetService.get(user, targetId)
        if (target.status != TargetStatus.VERIFIED) throw ConflictException("Target is not verified", ErrorCodes.CONFLICT)
        val identity = identities.findByIdAndTargetId(identityId, targetId) ?: throw NotFoundException("Identity not found")
        return loginTester.test(target, identity)
    }

    private fun validateAuth(type: AuthType, config: Map<String, String>, secret: Map<String, String>) {
        val (configKeys, secretKeys) = when (type) {
            AuthType.FORM_LOGIN, AuthType.JSON_LOGIN -> listOf("loginUrl", "usernameField", "passwordField") to listOf("username", "password")
            AuthType.BEARER_STATIC -> emptyList<String>() to listOf("token")
            AuthType.COOKIE_STATIC -> emptyList<String>() to listOf("cookie")
            AuthType.HEADER_STATIC -> listOf("headerName") to listOf("value")
        }
        val missingConfig = configKeys.filter { config[it].isNullOrBlank() }
        val missingSecret = secretKeys.filter { secret[it].isNullOrBlank() }
        if (missingConfig.isNotEmpty()) throw ValidationFailedException("authConfig is missing: ${missingConfig.joinToString()}")
        if (missingSecret.isNotEmpty()) throw ValidationFailedException("secret is missing: ${missingSecret.joinToString()}")
    }
}

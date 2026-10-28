package io.vulscan.core.application

import io.vulscan.core.domain.ConflictException
import io.vulscan.core.domain.ForbiddenException
import io.vulscan.core.domain.NotFoundException
import io.vulscan.core.domain.TargetStatus
import io.vulscan.core.persistence.ScanRepository
import io.vulscan.core.persistence.TargetEntity
import io.vulscan.core.persistence.TargetRepository
import io.vulscan.core.security.CurrentUser
import io.vulscan.core.security.OwnershipPolicy
import org.springframework.data.domain.Page
import org.springframework.data.domain.PageRequest
import org.springframework.data.domain.Sort
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional
import java.security.SecureRandom
import java.time.Instant
import java.util.Base64
import java.util.UUID

@Service
class TargetService(
    private val targets: TargetRepository,
    private val scans: ScanRepository,
    private val scopePolicy: ScopePolicyService,
    private val verification: TargetVerificationService,
    private val audit: AuditService,
) {
    private val random = SecureRandom()

    @Transactional(readOnly = true)
    fun list(user: CurrentUser, page: Int, size: Int): Page<TargetEntity> {
        val pageable = PageRequest.of(page.coerceAtLeast(0), size.coerceIn(1, 100), Sort.by(Sort.Direction.DESC, "createdAt"))
        return if (user.isAdmin) targets.findAll(pageable) else targets.findByOwnerId(user.id, pageable)
    }

    /** Возвращает цель, если она принадлежит пользователю (или пользователь — ADMIN); иначе NOT_FOUND. */
    @Transactional(readOnly = true)
    fun get(user: CurrentUser, id: UUID): TargetEntity {
        val target = targets.findById(id).orElseThrow { NotFoundException("Target not found") }
        OwnershipPolicy.requireAccess(user, target.ownerId)
        return target
    }

    /** Цель доступна пользователю и подтверждена; иначе 404 или 409 TARGET_NOT_VERIFIED. */
    @Transactional(readOnly = true)
    fun requireVerified(user: CurrentUser, id: UUID): TargetEntity {
        val target = get(user, id)
        if (target.status != TargetStatus.VERIFIED) throw ConflictException("Target is not verified", io.vulscan.core.domain.ErrorCodes.TARGET_NOT_VERIFIED)
        return target
    }

    @Transactional
    fun create(user: CurrentUser, name: String, baseUrl: String): TargetEntity {
        val validated = scopePolicy.validateTarget(baseUrl)
        if (targets.existsByOwnerIdAndBaseUrl(user.id, validated.baseUrl)) throw ConflictException("Target with this URL already exists")
        val token = ByteArray(32).also(random::nextBytes).let { Base64.getUrlEncoder().withoutPadding().encodeToString(it) }
        val target = targets.save(
            TargetEntity(
                ownerId = user.id, name = name.trim(), baseUrl = validated.baseUrl,
                allowedHosts = validated.allowedHosts, status = TargetStatus.PENDING_VERIFICATION, verificationToken = token,
            ),
        )
        audit.record("TARGET_CREATED", user.id, "TARGET", target.id, mapOf("baseUrl" to target.baseUrl))
        return target
    }

    @Transactional
    fun verify(user: CurrentUser, id: UUID): TargetEntity {
        val target = get(user, id)
        if (target.status == TargetStatus.DISABLED) throw ConflictException("Target is disabled")
        if (target.status == TargetStatus.VERIFIED) return target
        verification.check(target)
        target.status = TargetStatus.VERIFIED
        target.verifiedAt = Instant.now()
        audit.record("TARGET_VERIFIED", user.id, "TARGET", target.id)
        return targets.save(target)
    }

    @Transactional
    fun approve(user: CurrentUser, id: UUID): TargetEntity {
        if (!user.isAdmin) throw ForbiddenException()
        val target = targets.findById(id).orElseThrow { NotFoundException("Target not found") }
        if (target.status == TargetStatus.DISABLED) throw ConflictException("Target is disabled")
        target.status = TargetStatus.VERIFIED
        target.verifiedAt = Instant.now()
        audit.record("TARGET_APPROVED", user.id, "TARGET", target.id)
        return targets.save(target)
    }

    /** Цель со сканами только отключается (история сохраняется); без сканов удаляется. */
    @Transactional
    fun delete(user: CurrentUser, id: UUID) {
        val target = get(user, id)
        if (scans.existsByTargetId(target.id)) {
            target.status = TargetStatus.DISABLED
            targets.save(target)
        } else {
            targets.delete(target)
        }
        audit.record("TARGET_DELETED", user.id, "TARGET", target.id)
    }
}

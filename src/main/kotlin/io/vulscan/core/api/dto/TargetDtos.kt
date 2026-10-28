package io.vulscan.core.api.dto

import io.vulscan.core.domain.TargetStatus
import io.vulscan.kit.contracts.AllowedHost
import jakarta.validation.constraints.NotBlank
import jakarta.validation.constraints.Size
import java.time.Instant
import java.util.UUID

data class CreateTargetRequest(
    @field:NotBlank @field:Size(max = 100) val name: String?,
    @field:NotBlank @field:Size(max = 300) val baseUrl: String?,
)

data class VerificationInfo(val method: String, val path: String, val expectedContent: String)

data class TargetResponse(
    val id: UUID,
    val ownerId: UUID,
    val name: String,
    val baseUrl: String,
    val status: TargetStatus,
    val allowedHosts: List<AllowedHost>,
    val verification: VerificationInfo?,
    val verifiedAt: Instant?,
    val createdAt: Instant,
)

data class PageResponse<T>(val items: List<T>, val page: Int, val size: Int, val total: Long)

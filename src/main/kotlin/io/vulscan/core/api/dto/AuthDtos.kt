package io.vulscan.core.api.dto

import io.vulscan.core.domain.UserRole
import jakarta.validation.constraints.NotBlank
import jakarta.validation.constraints.Size
import java.util.UUID

data class LoginRequest(
    @field:NotBlank @field:Size(max = 100) val username: String?,
    @field:NotBlank @field:Size(max = 200) val password: String?,
)

data class MeResponse(val id: UUID, val username: String, val role: UserRole, val csrfToken: String? = null)

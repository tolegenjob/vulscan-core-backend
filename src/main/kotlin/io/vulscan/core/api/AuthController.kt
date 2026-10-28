package io.vulscan.core.api

import io.vulscan.core.api.dto.LoginRequest
import io.vulscan.core.api.dto.MeResponse
import io.vulscan.core.application.AuditActions
import io.vulscan.core.application.AuditService
import io.vulscan.core.domain.InvalidCredentialsException
import io.vulscan.core.domain.RateLimitedException
import io.vulscan.core.security.AppUserDetails
import io.vulscan.core.security.SlidingWindowLimiter
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import jakarta.validation.Valid
import org.springframework.http.HttpStatus
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.AuthenticationException
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.web.context.SecurityContextRepository
import org.springframework.security.web.csrf.CsrfTokenRepository
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.ResponseStatus
import org.springframework.web.bind.annotation.RestController
import org.springframework.security.core.annotation.AuthenticationPrincipal

@RestController
@RequestMapping("/api/v1/auth")
class AuthController(
    private val authenticationManager: AuthenticationManager,
    private val contextRepository: SecurityContextRepository,
    private val csrfRepository: CsrfTokenRepository,
    private val audit: AuditService,
) {
    private val loginLimiter = SlidingWindowLimiter(max = 5, windowMs = 60_000)

    @PostMapping("/login")
    fun login(@Valid @RequestBody body: LoginRequest, request: HttpServletRequest, response: HttpServletResponse): MeResponse {
        val username = body.username!!.trim()
        val retryAfter = loginLimiter.tryAcquire("${request.remoteAddr}|${username.lowercase()}")
        if (retryAfter > 0) throw RateLimitedException(retryAfter)

        val authentication = try {
            authenticationManager.authenticate(UsernamePasswordAuthenticationToken.unauthenticated(username, body.password!!))
        } catch (e: AuthenticationException) {
            audit.record(AuditActions.LOGIN_FAILURE, details = mapOf("username" to username.take(100)))
            throw InvalidCredentialsException()
        }

        // Защита от фиксации сессии: идентификатор меняется, если сессия уже была
        if (request.getSession(false) != null) request.changeSessionId() else request.getSession(true)
        val context = SecurityContextHolder.createEmptyContext()
        context.authentication = authentication
        SecurityContextHolder.setContext(context)
        contextRepository.saveContext(context, request, response)

        val csrf = csrfRepository.generateToken(request)
        csrfRepository.saveToken(csrf, request, response)

        val user = authentication.principal as AppUserDetails
        audit.record(AuditActions.LOGIN_SUCCESS, actorId = user.id, subjectType = "USER", subjectId = user.id)
        return MeResponse(user.id, user.username, user.role, csrf.token)
    }

    @PostMapping("/logout")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    fun logout(@AuthenticationPrincipal user: AppUserDetails, request: HttpServletRequest) {
        audit.record(AuditActions.LOGOUT, actorId = user.id, subjectType = "USER", subjectId = user.id)
        request.getSession(false)?.invalidate()
        SecurityContextHolder.clearContext()
    }

    @GetMapping("/me")
    fun me(@AuthenticationPrincipal user: AppUserDetails): MeResponse = MeResponse(user.id, user.username, user.role)
}

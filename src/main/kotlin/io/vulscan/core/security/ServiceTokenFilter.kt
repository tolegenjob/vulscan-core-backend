package io.vulscan.core.security

import io.vulscan.core.config.ScannerProperties
import io.vulscan.kit.contracts.ModuleType
import jakarta.servlet.FilterChain
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.web.filter.OncePerRequestFilter
import java.security.MessageDigest

/**
 * Аутентификация модулей на /internal/v1/** по сервисному токену (Authorization: Bearer ...).
 * Токен однозначно определяет moduleType; X-Worker-Id обязателен.
 */
class ServiceTokenFilter(properties: ScannerProperties) : OncePerRequestFilter() {
    private val tokens: List<Pair<ModuleType, ByteArray>> = listOf(
        ModuleType.XSS to properties.serviceTokens.xss,
        ModuleType.SQLI to properties.serviceTokens.sqli,
        ModuleType.IDOR to properties.serviceTokens.idor,
    ).filter { it.second.isNotBlank() }.map { it.first to it.second.toByteArray(Charsets.UTF_8) }

    override fun doFilterInternal(request: HttpServletRequest, response: HttpServletResponse, chain: FilterChain) {
        val presented = request.getHeader("Authorization")
            ?.takeIf { it.startsWith("Bearer ") }?.removePrefix("Bearer ")?.toByteArray(Charsets.UTF_8)
        val workerId = request.getHeader("X-Worker-Id")?.takeIf { it.isNotBlank() && it.length <= 100 }
        if (presented != null && workerId != null) {
            // Перебираются все токены без раннего выхода, чтобы время ответа не зависело от совпадения
            var matched: ModuleType? = null
            for ((module, token) in tokens) {
                if (MessageDigest.isEqual(token, presented)) matched = module
            }
            if (matched != null) {
                val authentication = UsernamePasswordAuthenticationToken.authenticated(
                    ModuleWorker(matched, workerId), null, listOf(SimpleGrantedAuthority("ROLE_WORKER_${matched.name}")),
                )
                SecurityContextHolder.getContext().authentication = authentication
            }
        }
        chain.doFilter(request, response)
    }
}

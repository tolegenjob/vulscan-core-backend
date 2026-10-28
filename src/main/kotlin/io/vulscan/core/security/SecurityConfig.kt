package io.vulscan.core.security

import io.vulscan.core.config.ScannerProperties
import io.vulscan.core.domain.ErrorCodes
import io.vulscan.core.observability.CorrelationFilter
import io.vulscan.kit.contracts.ApiError
import io.vulscan.kit.contracts.Json
import jakarta.servlet.http.HttpServletResponse
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.annotation.Order
import org.springframework.http.MediaType
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.ProviderManager
import org.springframework.security.authentication.dao.DaoAuthenticationProvider
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.http.SessionCreationPolicy
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.crypto.factory.PasswordEncoderFactories
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter
import org.springframework.security.web.context.HttpSessionSecurityContextRepository
import org.springframework.security.web.context.SecurityContextRepository
import org.springframework.security.web.csrf.CookieCsrfTokenRepository
import org.springframework.security.web.csrf.CsrfTokenRepository
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler
import java.time.Instant

@Configuration
class SecurityConfig {

    @Bean
    fun passwordEncoder(): PasswordEncoder = PasswordEncoderFactories.createDelegatingPasswordEncoder()

    @Bean
    fun csrfTokenRepository(): CsrfTokenRepository = CookieCsrfTokenRepository.withHttpOnlyFalse()

    @Bean
    fun securityContextRepository(): SecurityContextRepository = HttpSessionSecurityContextRepository()

    @Bean
    fun authenticationManager(users: UserDetailsService, encoder: PasswordEncoder): AuthenticationManager {
        val provider = DaoAuthenticationProvider(users)
        provider.setPasswordEncoder(encoder)
        return ProviderManager(provider)
    }

    /** Внутренний API модулей: без сессий и CSRF, только сервисный токен. */
    @Bean
    @Order(1)
    fun internalChain(http: HttpSecurity, properties: ScannerProperties): SecurityFilterChain {
        http.securityMatcher("/internal/v1/**")
            .csrf { it.disable() }
            .sessionManagement { it.sessionCreationPolicy(SessionCreationPolicy.STATELESS) }
            .addFilterBefore(ServiceTokenFilter(properties), UsernamePasswordAuthenticationFilter::class.java)
            .authorizeHttpRequests { it.anyRequest().authenticated() }
            .exceptionHandling {
                it.authenticationEntryPoint { _, response, _ -> writeError(response, 401, ErrorCodes.UNAUTHENTICATED, "Authentication required") }
                it.accessDeniedHandler { _, response, _ -> writeError(response, 403, ErrorCodes.FORBIDDEN, "Access denied") }
            }
        return http.build()
    }

    /** Пользовательский API: сессия + CSRF через cookie XSRF-TOKEN / заголовок X-XSRF-TOKEN. */
    @Bean
    @Order(2)
    fun apiChain(http: HttpSecurity, csrfRepository: CsrfTokenRepository, contextRepository: SecurityContextRepository): SecurityFilterChain {
        http.securityMatcher("/api/**")
            .csrf {
                it.csrfTokenRepository(csrfRepository)
                it.csrfTokenRequestHandler(CsrfTokenRequestAttributeHandler())
                it.ignoringRequestMatchers("/api/v1/auth/login")
            }
            .securityContext { it.securityContextRepository(contextRepository) }
            .sessionManagement { it.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED) }
            .authorizeHttpRequests {
                it.requestMatchers("/api/v1/auth/login").permitAll()
                it.anyRequest().authenticated()
            }
            .exceptionHandling {
                it.authenticationEntryPoint { _, response, _ -> writeError(response, 401, ErrorCodes.UNAUTHENTICATED, "Authentication required") }
                it.accessDeniedHandler { _, response, _ -> writeError(response, 403, ErrorCodes.FORBIDDEN, "Access denied") }
            }
        return http.build()
    }

    @Bean
    @Order(3)
    fun defaultChain(http: HttpSecurity): SecurityFilterChain {
        http.csrf { it.disable() }
            .authorizeHttpRequests {
                it.requestMatchers("/actuator/health", "/actuator/health/**").permitAll()
                it.anyRequest().denyAll()
            }
            .exceptionHandling {
                it.authenticationEntryPoint { _, response, _ -> writeError(response, 401, ErrorCodes.UNAUTHENTICATED, "Authentication required") }
                it.accessDeniedHandler { _, response, _ -> writeError(response, 403, ErrorCodes.FORBIDDEN, "Access denied") }
            }
        return http.build()
    }

    private fun writeError(response: HttpServletResponse, status: Int, code: String, message: String) {
        response.status = status
        response.contentType = MediaType.APPLICATION_JSON_VALUE
        response.characterEncoding = "UTF-8"
        val body = ApiError(Instant.now(), status, code, message, CorrelationFilter.current())
        response.writer.write(Json.write(body))
    }
}

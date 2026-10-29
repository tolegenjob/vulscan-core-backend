package io.vulscan.core.security

import io.vulscan.core.domain.ErrorCodes
import io.vulscan.core.observability.CorrelationFilter
import io.vulscan.kit.contracts.ApiError
import io.vulscan.kit.contracts.Json
import jakarta.servlet.FilterChain
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.core.Ordered
import org.springframework.core.annotation.Order
import org.springframework.http.MediaType
import org.springframework.stereotype.Component
import org.springframework.web.filter.OncePerRequestFilter
import java.time.Instant

/** Отклоняет запросы с заявленным размером тела выше лимита (1 МБ; для import-openapi 2 МБ) до чтения тела. */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE + 5)
class RequestSizeFilter : OncePerRequestFilter() {

    override fun doFilterInternal(request: HttpServletRequest, response: HttpServletResponse, chain: FilterChain) {
        val limit = if (request.requestURI.endsWith("/import-openapi")) IMPORT_LIMIT else DEFAULT_LIMIT
        if (request.contentLengthLong > limit) {
            response.status = 413
            response.contentType = MediaType.APPLICATION_JSON_VALUE
            response.characterEncoding = "UTF-8"
            response.writer.write(Json.write(ApiError(Instant.now(), 413, ErrorCodes.PAYLOAD_TOO_LARGE, "Request body is too large", CorrelationFilter.current())))
            return
        }
        chain.doFilter(request, response)
    }

    companion object {
        const val DEFAULT_LIMIT = 1L * 1024 * 1024
        const val IMPORT_LIMIT = 2L * 1024 * 1024
    }
}

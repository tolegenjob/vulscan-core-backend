package io.vulscan.core.observability

import jakarta.servlet.FilterChain
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.slf4j.MDC
import org.springframework.core.Ordered
import org.springframework.core.annotation.Order
import org.springframework.stereotype.Component
import org.springframework.web.filter.OncePerRequestFilter
import java.util.UUID

/** Читает или создаёт X-Correlation-Id, кладёт его в MDC и в ответ. Невалидное значение заменяется новым. */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
class CorrelationFilter : OncePerRequestFilter() {

    override fun doFilterInternal(request: HttpServletRequest, response: HttpServletResponse, chain: FilterChain) {
        val id = parse(request.getHeader(HEADER)) ?: UUID.randomUUID()
        MDC.put(MDC_KEY, id.toString())
        response.setHeader(HEADER, id.toString())
        try {
            chain.doFilter(request, response)
        } finally {
            MDC.remove(MDC_KEY)
        }
    }

    private fun parse(value: String?): UUID? =
        value?.let { runCatching { UUID.fromString(it) }.getOrNull() }

    companion object {
        const val HEADER = "X-Correlation-Id"
        const val MDC_KEY = "correlationId"

        fun current(): UUID? = MDC.get(MDC_KEY)?.let { runCatching { UUID.fromString(it) }.getOrNull() }
    }
}

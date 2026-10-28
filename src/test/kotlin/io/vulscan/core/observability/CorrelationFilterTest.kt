package io.vulscan.core.observability

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.springframework.mock.web.MockFilterChain
import org.springframework.mock.web.MockHttpServletRequest
import org.springframework.mock.web.MockHttpServletResponse
import java.util.UUID

class CorrelationFilterTest {
    private val filter = CorrelationFilter()

    private fun call(header: String?): MockHttpServletResponse {
        val request = MockHttpServletRequest("GET", "/x")
        if (header != null) request.addHeader(CorrelationFilter.HEADER, header)
        val response = MockHttpServletResponse()
        filter.doFilter(request, response, MockFilterChain())
        return response
    }

    @Test
    fun `valid header is accepted`() {
        val id = UUID.randomUUID().toString()
        assertThat(call(id).getHeader(CorrelationFilter.HEADER)).isEqualTo(id)
    }

    @Test
    fun `missing header is generated`() {
        val value = call(null).getHeader(CorrelationFilter.HEADER)
        assertThat(UUID.fromString(value)).isNotNull()
    }

    @Test
    fun `invalid header is replaced`() {
        val value = call("not-a-uuid\nX-Evil: 1").getHeader(CorrelationFilter.HEADER)
        assertThat(value).isNotEqualTo("not-a-uuid")
        assertThat(UUID.fromString(value)).isNotNull()
    }

    @Test
    fun `mdc is cleared after the request`() {
        call(UUID.randomUUID().toString())
        assertThat(CorrelationFilter.current()).isNull()
    }
}

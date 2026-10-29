package io.vulscan.core.security

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.springframework.mock.web.MockFilterChain
import org.springframework.mock.web.MockHttpServletRequest
import org.springframework.mock.web.MockHttpServletResponse

class RequestSizeFilterTest {
    private val filter = RequestSizeFilter()

    private fun run(uri: String, bytes: Int): Pair<MockHttpServletResponse, MockFilterChain> {
        val request = MockHttpServletRequest("POST", uri).apply { setContent(ByteArray(bytes)) }
        val response = MockHttpServletResponse()
        val chain = MockFilterChain()
        filter.doFilter(request, response, chain)
        return response to chain
    }

    @Test
    fun `body above one megabyte is rejected before processing`() {
        val (response, chain) = run("/api/v1/targets", 1024 * 1024 + 1)
        assertThat(response.status).isEqualTo(413)
        assertThat(response.contentAsString).contains("PAYLOAD_TOO_LARGE")
        assertThat(chain.request).isNull()
    }

    @Test
    fun `body at the limit passes`() {
        val (response, chain) = run("/api/v1/targets", 1024 * 1024)
        assertThat(response.status).isEqualTo(200)
        assertThat(chain.request).isNotNull()
    }

    @Test
    fun `openapi import allows two megabytes`() {
        val (response, chain) = run("/api/v1/targets/abc/endpoints/import-openapi", 1_500_000)
        assertThat(response.status).isEqualTo(200)
        assertThat(chain.request).isNotNull()
        assertThat(run("/api/v1/targets/abc/endpoints/import-openapi", 2 * 1024 * 1024 + 1).first.status).isEqualTo(413)
    }
}

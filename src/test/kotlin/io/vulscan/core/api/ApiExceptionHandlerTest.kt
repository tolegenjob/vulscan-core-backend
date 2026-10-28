package io.vulscan.core.api

import io.vulscan.core.domain.ConflictException
import io.vulscan.core.domain.IllegalStateTransitionException
import io.vulscan.core.domain.NotFoundException
import io.vulscan.core.domain.ScopeViolationException
import io.vulscan.core.domain.TooManyActiveScansException
import io.vulscan.core.observability.CorrelationFilter
import jakarta.validation.Valid
import jakarta.validation.constraints.NotBlank
import jakarta.validation.constraints.Size
import org.junit.jupiter.api.Test
import org.springframework.http.MediaType
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.content
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.status
import org.springframework.test.web.servlet.setup.MockMvcBuilders
import org.springframework.test.web.servlet.setup.StandaloneMockMvcBuilder
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RestController

class ApiExceptionHandlerTest {

    data class Body(@field:NotBlank val name: String?, @field:Size(max = 3) val code: String?)

    @RestController
    class ThrowingController {
        @GetMapping("/t/not-found") fun notFound(): String = throw NotFoundException("Scan not found")

        @GetMapping("/t/conflict") fun conflict(): String = throw ConflictException("Duplicate")

        @GetMapping("/t/scope") fun scope(): String = throw ScopeViolationException("Out of scope")

        @GetMapping("/t/transition") fun transition(): String = throw IllegalStateTransitionException("Bad transition")

        @GetMapping("/t/limit") fun limit(): String = throw TooManyActiveScansException()

        @GetMapping("/t/boom") fun boom(): String = throw IllegalStateException("secret internal detail")

        @PostMapping("/t/body") fun body(@Valid @RequestBody body: Body): String = "ok"
    }

    private val mvc: MockMvc = MockMvcBuilders.standaloneSetup(ThrowingController())
        .setControllerAdvice(ApiExceptionHandler())
        .addFilters<StandaloneMockMvcBuilder>(CorrelationFilter())
        .build()

    @Test
    fun `domain exceptions map to status and code`() {
        mvc.perform(get("/t/not-found")).andExpect(status().isNotFound).andExpect(jsonPath("$.code").value("NOT_FOUND"))
        mvc.perform(get("/t/conflict")).andExpect(status().isConflict).andExpect(jsonPath("$.code").value("CONFLICT"))
        mvc.perform(get("/t/scope")).andExpect(status().isUnprocessableEntity).andExpect(jsonPath("$.code").value("SCOPE_VIOLATION"))
        mvc.perform(get("/t/transition")).andExpect(status().isConflict).andExpect(jsonPath("$.code").value("ILLEGAL_STATE_TRANSITION"))
        mvc.perform(get("/t/limit")).andExpect(status().isTooManyRequests).andExpect(jsonPath("$.code").value("TOO_MANY_ACTIVE_SCANS"))
    }

    @Test
    fun `unexpected exception hides details`() {
        mvc.perform(get("/t/boom"))
            .andExpect(status().isInternalServerError)
            .andExpect(jsonPath("$.code").value("INTERNAL_ERROR"))
            .andExpect(jsonPath("$.message").value("Internal server error"))
            .andExpect(content().string(org.hamcrest.Matchers.not(org.hamcrest.Matchers.containsString("secret internal detail"))))
            .andExpect(content().string(org.hamcrest.Matchers.not(org.hamcrest.Matchers.containsString("at io.vulscan"))))
    }

    @Test
    fun `bean validation errors list fields`() {
        mvc.perform(post("/t/body").contentType(MediaType.APPLICATION_JSON).content("""{"name":"","code":"toolong"}"""))
            .andExpect(status().isBadRequest)
            .andExpect(jsonPath("$.code").value("VALIDATION_FAILED"))
            .andExpect(jsonPath("$.fieldErrors.length()").value(2))
    }

    @Test
    fun `malformed json is a bad request`() {
        mvc.perform(post("/t/body").contentType(MediaType.APPLICATION_JSON).content("{not json"))
            .andExpect(status().isBadRequest)
            .andExpect(jsonPath("$.code").value("MALFORMED_REQUEST"))
    }

    @Test
    fun `error body carries the correlation id`() {
        val id = "0f8fad5b-d9cb-469f-a165-70867728950e"
        mvc.perform(get("/t/not-found").header("X-Correlation-Id", id))
            .andExpect(jsonPath("$.correlationId").value(id))
    }
}

package io.vulscan.core.api

import io.vulscan.core.domain.ConflictException
import io.vulscan.core.domain.DomainException
import io.vulscan.core.domain.ErrorCodes
import io.vulscan.core.domain.ForbiddenException
import io.vulscan.core.domain.IllegalStateTransitionException
import io.vulscan.core.domain.InvalidCredentialsException
import io.vulscan.core.domain.RateLimitedException
import io.vulscan.core.domain.NotFoundException
import io.vulscan.core.domain.ScopeViolationException
import io.vulscan.core.domain.TooManyActiveScansException
import io.vulscan.core.observability.CorrelationFilter
import io.vulscan.kit.contracts.ApiError
import io.vulscan.kit.contracts.FieldError
import jakarta.validation.ConstraintViolationException
import org.slf4j.LoggerFactory
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.http.converter.HttpMessageNotReadableException
import org.springframework.web.bind.MethodArgumentNotValidException
import org.springframework.web.bind.annotation.ExceptionHandler
import org.springframework.web.bind.annotation.RestControllerAdvice
import java.time.Instant

/** Единый формат ошибок. Тело никогда не содержит стек-трейсов и внутренних деталей. */
@RestControllerAdvice
class ApiExceptionHandler {
    private val log = LoggerFactory.getLogger(ApiExceptionHandler::class.java)

    @ExceptionHandler(DomainException::class)
    fun domain(e: DomainException): ResponseEntity<ApiError> {
        val response = respond(statusFor(e), e.code, e.message ?: e.code)
        if (e is RateLimitedException) {
            return ResponseEntity.status(response.statusCode).header("Retry-After", e.retryAfterSec.toString()).body(response.body)
        }
        return response
    }

    @ExceptionHandler(MethodArgumentNotValidException::class)
    fun invalidBody(e: MethodArgumentNotValidException): ResponseEntity<ApiError> {
        val errors = e.bindingResult.fieldErrors.map { FieldError(it.field, it.code ?: "invalid", it.defaultMessage ?: "Invalid value") }
        return respond(HttpStatus.BAD_REQUEST, ErrorCodes.VALIDATION_FAILED, "Request validation failed", errors)
    }

    @ExceptionHandler(ConstraintViolationException::class)
    fun constraint(e: ConstraintViolationException): ResponseEntity<ApiError> {
        val errors = e.constraintViolations.map {
            FieldError(it.propertyPath.toString().substringAfterLast('.'), "invalid", it.message)
        }
        return respond(HttpStatus.BAD_REQUEST, ErrorCodes.VALIDATION_FAILED, "Request validation failed", errors)
    }

    @ExceptionHandler(HttpMessageNotReadableException::class)
    fun unreadable(e: HttpMessageNotReadableException): ResponseEntity<ApiError> =
        respond(HttpStatus.BAD_REQUEST, ErrorCodes.MALFORMED_REQUEST, "Malformed request body")

    @ExceptionHandler(Exception::class)
    fun unexpected(e: Exception): ResponseEntity<ApiError> {
        log.error("Unhandled exception", e)
        return respond(HttpStatus.INTERNAL_SERVER_ERROR, ErrorCodes.INTERNAL_ERROR, "Internal server error")
    }

    private fun statusFor(e: DomainException): HttpStatus = when (e) {
        is NotFoundException -> HttpStatus.NOT_FOUND
        is ConflictException -> HttpStatus.CONFLICT
        is IllegalStateTransitionException -> HttpStatus.CONFLICT
        is ScopeViolationException -> HttpStatus.UNPROCESSABLE_ENTITY
        is TooManyActiveScansException -> HttpStatus.TOO_MANY_REQUESTS
        is RateLimitedException -> HttpStatus.TOO_MANY_REQUESTS
        is ForbiddenException -> HttpStatus.FORBIDDEN
        is InvalidCredentialsException -> HttpStatus.UNAUTHORIZED
    }

    private fun respond(status: HttpStatus, code: String, message: String, fieldErrors: List<FieldError> = emptyList()) =
        ResponseEntity.status(status).body(
            ApiError(Instant.now(), status.value(), code, message, CorrelationFilter.current(), fieldErrors),
        )
}

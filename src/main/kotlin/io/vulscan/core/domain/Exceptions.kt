package io.vulscan.core.domain

/** Коды ошибок API. Значение попадает в поле `code` ответа. */
object ErrorCodes {
    const val NOT_FOUND = "NOT_FOUND"
    const val CONFLICT = "CONFLICT"
    const val SCOPE_VIOLATION = "SCOPE_VIOLATION"
    const val ILLEGAL_STATE_TRANSITION = "ILLEGAL_STATE_TRANSITION"
    const val TOO_MANY_ACTIVE_SCANS = "TOO_MANY_ACTIVE_SCANS"
    const val VALIDATION_FAILED = "VALIDATION_FAILED"
    const val MALFORMED_REQUEST = "MALFORMED_REQUEST"
    const val FORBIDDEN = "FORBIDDEN"
    const val INTERNAL_ERROR = "INTERNAL_ERROR"
    const val UNAUTHENTICATED = "UNAUTHENTICATED"
    const val BAD_CREDENTIALS = "BAD_CREDENTIALS"
    const val RATE_LIMITED = "RATE_LIMITED"
}

/** Ожидаемая бизнес-ошибка. Сообщение показывается клиенту, поэтому не должно содержать секретов. */
sealed class DomainException(val code: String, message: String) : RuntimeException(message)

class NotFoundException(message: String = "Resource not found") : DomainException(ErrorCodes.NOT_FOUND, message)

class ConflictException(message: String, code: String = ErrorCodes.CONFLICT) : DomainException(code, message)

class ScopeViolationException(message: String) : DomainException(ErrorCodes.SCOPE_VIOLATION, message)

class IllegalStateTransitionException(message: String) : DomainException(ErrorCodes.ILLEGAL_STATE_TRANSITION, message)

class TooManyActiveScansException(message: String = "Too many active scans") :
    DomainException(ErrorCodes.TOO_MANY_ACTIVE_SCANS, message)

class InvalidCredentialsException : DomainException(ErrorCodes.BAD_CREDENTIALS, "Invalid username or password")

class RateLimitedException(val retryAfterSec: Long) : DomainException(ErrorCodes.RATE_LIMITED, "Too many requests")

package io.vulscan.core.domain

enum class UserRole { USER, ADMIN }

enum class TargetStatus { PENDING_VERIFICATION, VERIFIED, DISABLED }

enum class ScanStatus {
    PENDING, RUNNING, COMPLETED, PARTIALLY_COMPLETED, FAILED, CANCELLING, CANCELLED;

    val isActive: Boolean get() = this == PENDING || this == RUNNING || this == CANCELLING
}

enum class JobStatus { PENDING, QUEUED, RUNNING, COMPLETED, FAILED, CANCELLED }

enum class TriageStatus { OPEN, FALSE_POSITIVE, FIXED }

enum class OutboxStatus { PENDING, SENT }

enum class ResultIntegrity { OK, INCOMPLETE }

package io.vulscan.core.application

import io.vulscan.core.persistence.AuditEventEntity
import io.vulscan.core.persistence.AuditEventRepository
import org.springframework.stereotype.Service
import java.util.UUID

@Service
class AuditService(private val repository: AuditEventRepository) {

    /** Записывает событие аудита. В [details] нельзя передавать секреты. */
    fun record(
        action: String,
        actorId: UUID? = null,
        subjectType: String? = null,
        subjectId: UUID? = null,
        details: Map<String, Any?>? = null,
    ) {
        repository.save(AuditEventEntity(actorId = actorId, action = action, subjectType = subjectType, subjectId = subjectId, details = details))
    }
}

object AuditActions {
    const val LOGIN_SUCCESS = "LOGIN_SUCCESS"
    const val LOGIN_FAILURE = "LOGIN_FAILURE"
    const val LOGOUT = "LOGOUT"
}

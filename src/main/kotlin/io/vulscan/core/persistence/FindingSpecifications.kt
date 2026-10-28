package io.vulscan.core.persistence

import io.vulscan.core.domain.TriageStatus
import io.vulscan.kit.contracts.ModuleType
import io.vulscan.kit.contracts.Severity
import io.vulscan.kit.contracts.Verdict
import org.springframework.data.jpa.domain.Specification
import java.util.UUID

/** Фильтры списка находок; незаданный фильтр не ограничивает выборку. */
object FindingSpecifications {

    fun filter(
        scanId: UUID? = null,
        targetId: UUID? = null,
        severity: Severity? = null,
        verdict: Verdict? = null,
        moduleType: ModuleType? = null,
        triageStatus: TriageStatus? = null,
        parameterName: String? = null,
    ): Specification<FindingEntity> {
        val parts = mutableListOf<Specification<FindingEntity>>()
        scanId?.let { parts += equal("scanId", it) }
        targetId?.let { parts += equal("targetId", it) }
        severity?.let { parts += equal("severity", it) }
        verdict?.let { parts += equal("verdict", it) }
        moduleType?.let { parts += equal("moduleType", it) }
        triageStatus?.let { parts += equal("triageStatus", it) }
        parameterName?.let { parts += equal("parameterName", it) }
        return Specification.allOf(parts)
    }

    private fun equal(field: String, value: Any): Specification<FindingEntity> =
        Specification { root, _, cb -> cb.equal(root.get<Any>(field), value) }
}

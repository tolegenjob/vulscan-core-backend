package io.vulscan.core.persistence

import io.vulscan.core.domain.TriageStatus
import io.vulscan.kit.contracts.ModuleType
import io.vulscan.kit.contracts.Severity
import io.vulscan.kit.contracts.Verdict
import io.vulscan.kit.contracts.VulnType
import jakarta.persistence.EntityManager
import jakarta.persistence.PersistenceContext
import jakarta.persistence.Tuple
import jakarta.persistence.criteria.CriteriaBuilder
import jakarta.persistence.criteria.CriteriaQuery
import jakarta.persistence.criteria.Expression
import jakarta.persistence.criteria.Predicate
import jakarta.persistence.criteria.Root
import org.springframework.data.domain.Page
import org.springframework.data.domain.PageImpl
import org.springframework.data.domain.Pageable
import org.springframework.stereotype.Repository
import java.time.Instant
import java.util.UUID

data class FindingFilter(
    val scanId: UUID? = null,
    val targetId: UUID? = null,
    val moduleType: ModuleType? = null,
    val vulnType: VulnType? = null,
    val severity: Severity? = null,
    val verdict: Verdict? = null,
    val minConfidence: Int? = null,
    val triageStatus: TriageStatus? = null,
    val endpointId: UUID? = null,
    val query: String? = null,
    /** Если задан, видны только находки сканов этого пользователя. */
    val ownerId: UUID? = null,
)

/** Строка списка: тяжёлые поля `details` и `evidence` не читаются. */
data class FindingListRow(
    val id: UUID,
    val scanId: UUID,
    val targetId: UUID,
    val moduleType: ModuleType,
    val vulnType: VulnType,
    val verdict: Verdict,
    val severity: Severity,
    val confidence: Int,
    val method: String,
    val url: String,
    val parameterName: String?,
    val endpointId: UUID?,
    val title: String,
    val triageStatus: TriageStatus,
    val createdAt: Instant,
)

@Repository
class FindingQueryRepository(@PersistenceContext private val em: EntityManager) {

    fun search(filter: FindingFilter, pageable: Pageable, sortField: String, ascending: Boolean): Page<FindingListRow> {
        val cb = em.criteriaBuilder
        val query = cb.createTupleQuery()
        val root = query.from(FindingEntity::class.java)
        query.multiselect(
            root.get<UUID>("id").alias("id"), root.get<UUID>("scanId").alias("scanId"), root.get<UUID>("targetId").alias("targetId"),
            root.get<ModuleType>("moduleType").alias("moduleType"), root.get<VulnType>("vulnType").alias("vulnType"),
            root.get<Verdict>("verdict").alias("verdict"), root.get<Severity>("severity").alias("severity"),
            root.get<Short>("confidence").alias("confidence"), root.get<String>("method").alias("method"), root.get<String>("url").alias("url"),
            root.get<String>("parameterName").alias("parameterName"), root.get<UUID>("endpointId").alias("endpointId"),
            root.get<String>("title").alias("title"), root.get<TriageStatus>("triageStatus").alias("triageStatus"),
            root.get<Instant>("createdAt").alias("createdAt"),
        )
        query.where(*predicates(cb, query, root, filter).toTypedArray())
        val key = sortExpression(cb, root, sortField)
        query.orderBy(if (ascending) cb.asc(key) else cb.desc(key), cb.asc(root.get<UUID>("id")))

        val rows = em.createQuery(query).setFirstResult(pageable.offset.toInt()).setMaxResults(pageable.pageSize).resultList.map(::toRow)

        val countQuery = cb.createQuery(Long::class.java)
        val countRoot = countQuery.from(FindingEntity::class.java)
        countQuery.select(cb.count(countRoot)).where(*predicates(cb, countQuery, countRoot, filter).toTypedArray())
        return PageImpl(rows, pageable, em.createQuery(countQuery).singleResult)
    }

    /** Severity сортируется по рангу, а не по строке. */
    private fun sortExpression(cb: CriteriaBuilder, root: Root<FindingEntity>, field: String): Expression<*> = when (field) {
        "severity" -> cb.selectCase<Int>()
            .`when`(cb.equal(root.get<Severity>("severity"), Severity.CRITICAL), 4)
            .`when`(cb.equal(root.get<Severity>("severity"), Severity.HIGH), 3)
            .`when`(cb.equal(root.get<Severity>("severity"), Severity.MEDIUM), 2)
            .`when`(cb.equal(root.get<Severity>("severity"), Severity.LOW), 1)
            .otherwise(0)
        "confidence" -> root.get<Short>("confidence")
        "url" -> root.get<String>("url")
        else -> root.get<Instant>("createdAt")
    }

    private fun predicates(cb: CriteriaBuilder, query: CriteriaQuery<*>, root: Root<FindingEntity>, f: FindingFilter): List<Predicate> {
        val list = mutableListOf<Predicate>()
        f.scanId?.let { list += cb.equal(root.get<UUID>("scanId"), it) }
        f.targetId?.let { list += cb.equal(root.get<UUID>("targetId"), it) }
        f.moduleType?.let { list += cb.equal(root.get<ModuleType>("moduleType"), it) }
        f.vulnType?.let { list += cb.equal(root.get<VulnType>("vulnType"), it) }
        f.severity?.let { list += cb.equal(root.get<Severity>("severity"), it) }
        f.verdict?.let { list += cb.equal(root.get<Verdict>("verdict"), it) }
        f.minConfidence?.let { list += cb.greaterThanOrEqualTo(root.get<Short>("confidence"), it.toShort()) }
        f.triageStatus?.let { list += cb.equal(root.get<TriageStatus>("triageStatus"), it) }
        f.endpointId?.let { list += cb.equal(root.get<UUID>("endpointId"), it) }
        f.query?.takeIf { it.isNotBlank() }?.let { text ->
            val pattern = "%" + text.lowercase().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
            list += cb.or(
                cb.like(cb.lower(root.get("title")), pattern, '\\'),
                cb.like(cb.lower(root.get("url")), pattern, '\\'),
                cb.like(cb.lower(root.get("parameterName")), pattern, '\\'),
            )
        }
        f.ownerId?.let { owner ->
            val sub = query.subquery(UUID::class.java)
            val scan = sub.from(ScanEntity::class.java)
            sub.select(scan.get("id")).where(cb.equal(scan.get<UUID>("startedBy"), owner))
            list += root.get<UUID>("scanId").`in`(sub)
        }
        return list
    }

    private fun toRow(t: Tuple) = FindingListRow(
        id = t.get("id", UUID::class.java), scanId = t.get("scanId", UUID::class.java), targetId = t.get("targetId", UUID::class.java),
        moduleType = t.get("moduleType", ModuleType::class.java), vulnType = t.get("vulnType", VulnType::class.java),
        verdict = t.get("verdict", Verdict::class.java), severity = t.get("severity", Severity::class.java),
        confidence = t.get("confidence", Number::class.java).toInt(), method = t.get("method", String::class.java),
        url = t.get("url", String::class.java), parameterName = t.get("parameterName", String::class.java),
        endpointId = t.get("endpointId", UUID::class.java), title = t.get("title", String::class.java),
        triageStatus = t.get("triageStatus", TriageStatus::class.java), createdAt = t.get("createdAt", Instant::class.java),
    )
}

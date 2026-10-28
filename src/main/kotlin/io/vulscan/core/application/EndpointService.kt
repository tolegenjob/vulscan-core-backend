package io.vulscan.core.application

import io.vulscan.core.config.ScannerProperties
import io.vulscan.core.domain.ConflictException
import io.vulscan.core.domain.NotFoundException
import io.vulscan.core.domain.ScopeViolationException
import io.vulscan.core.persistence.TargetEndpointEntity
import io.vulscan.core.persistence.TargetEndpointRepository
import io.vulscan.core.security.CurrentUser
import io.vulscan.kit.contracts.HttpMethod
import io.vulscan.kit.contracts.ParameterRef
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional
import java.util.UUID

data class ImportResult(val created: Int, val skipped: List<SkippedOperation>)

@Service
class EndpointService(
    private val endpoints: TargetEndpointRepository,
    private val targetService: TargetService,
    private val audit: AuditService,
    private val properties: ScannerProperties,
) {
    @Transactional(readOnly = true)
    fun list(user: CurrentUser, targetId: UUID): List<TargetEndpointEntity> {
        targetService.get(user, targetId)
        return endpoints.findByTargetId(targetId)
    }

    @Transactional
    fun create(
        user: CurrentUser,
        targetId: UUID,
        method: HttpMethod,
        url: String,
        parameters: List<ParameterRef>,
        idempotent: Boolean,
        label: String?,
    ): TargetEndpointEntity {
        val target = targetService.get(user, targetId)
        val normalized = inScope(target.allowedHosts, target.baseUrl, url) ?: throw ScopeViolationException("OUT_OF_SCOPE: URL is outside the target")
        if (endpoints.existsByTargetIdAndMethodAndUrl(targetId, method, normalized)) throw ConflictException("Endpoint already exists")
        val saved = endpoints.save(
            TargetEndpointEntity(targetId = targetId, method = method, url = normalized, parameters = parameters, idempotent = idempotent, label = label),
        )
        audit.record("ENDPOINT_CREATED", user.id, "ENDPOINT", saved.id)
        return saved
    }

    @Transactional
    fun importOpenApi(user: CurrentUser, targetId: UUID, document: Map<String, Any?>, serverUrl: String): ImportResult {
        val target = targetService.get(user, targetId)
        val parsed = OpenApiImporter.parse(document, serverUrl, properties.jobs.maxEndpointsPerScan)
        val skipped = parsed.skipped.toMutableList()
        var created = 0
        for (candidate in parsed.endpoints) {
            val concrete = inScope(target.allowedHosts, target.baseUrl, OpenApiImporter.concreteUrl(candidate.urlTemplate))
            if (concrete == null) {
                skipped += SkippedOperation(candidate.urlTemplate, candidate.method.name, "OUT_OF_SCOPE")
                continue
            }
            // Шаблон пути хранится как есть: модули подставляют значения PATH-параметров сами
            if (endpoints.existsByTargetIdAndMethodAndUrl(targetId, candidate.method, candidate.urlTemplate)) {
                skipped += SkippedOperation(candidate.urlTemplate, candidate.method.name, "DUPLICATE")
                continue
            }
            endpoints.save(
                TargetEndpointEntity(
                    targetId = targetId, method = candidate.method, url = candidate.urlTemplate,
                    parameters = candidate.parameters, idempotent = candidate.idempotent,
                ),
            )
            created++
        }
        audit.record("ENDPOINTS_IMPORTED", user.id, "TARGET", targetId, mapOf("created" to created, "skipped" to skipped.size))
        return ImportResult(created, skipped)
    }

    @Transactional
    fun delete(user: CurrentUser, targetId: UUID, endpointId: UUID) {
        targetService.get(user, targetId)
        val endpoint = endpoints.findByIdAndTargetId(endpointId, targetId) ?: throw NotFoundException("Endpoint not found")
        endpoints.delete(endpoint)
        audit.record("ENDPOINT_DELETED", user.id, "ENDPOINT", endpointId)
    }

    private fun inScope(allowedHosts: List<io.vulscan.kit.contracts.AllowedHost>, baseUrl: String, url: String): String? =
        TargetScope.normalize(allowedHosts, baseUrl, url)
}

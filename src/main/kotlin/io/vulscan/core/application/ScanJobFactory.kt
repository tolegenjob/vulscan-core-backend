package io.vulscan.core.application

import io.vulscan.core.domain.ValidationFailedException
import io.vulscan.core.persistence.ResourceAccessRuleEntity
import io.vulscan.core.persistence.TargetEndpointEntity
import io.vulscan.core.persistence.TargetEntity
import io.vulscan.core.persistence.TestIdentityEntity
import io.vulscan.kit.contracts.AccessRuleRef
import io.vulscan.kit.contracts.EndpointRef
import io.vulscan.kit.contracts.HttpMethod
import io.vulscan.kit.contracts.IdentityRef
import io.vulscan.kit.contracts.IdorOptions
import io.vulscan.kit.contracts.ModuleOptions
import io.vulscan.kit.contracts.ModuleType
import io.vulscan.kit.contracts.ResourceRef
import io.vulscan.kit.contracts.ScanJobPayload
import io.vulscan.kit.contracts.ScanLimits
import io.vulscan.kit.contracts.ScopeRules
import io.vulscan.kit.contracts.SessionCheck
import io.vulscan.kit.contracts.SqliOptions
import io.vulscan.kit.contracts.TargetRef
import io.vulscan.kit.contracts.XssOptions
import java.time.Instant
import java.util.UUID

/** Параметры запроса на сканирование в терминах приложения (сохраняются в scans.config). */
data class ScanCommand(
    val targetId: UUID,
    val policyId: UUID? = null,
    val modules: List<ModuleType>,
    val endpointIds: List<UUID>,
    val xss: XssOptions? = null,
    val sqli: SqliOptions? = null,
    val idor: IdorCommand? = null,
    val excludePrefixes: List<String> = emptyList(),
)

data class IdorCommand(val identityIds: List<UUID>, val sessionCheck: SessionCheck? = null)

/** Собирает сообщение SCAN_JOB. Секреты идентичностей в него не попадают: только идентификаторы и метки. */
object ScanJobFactory {

    fun build(
        jobId: UUID,
        scanId: UUID,
        module: ModuleType,
        attempt: Int,
        deadlineAt: Instant,
        policyId: UUID,
        target: TargetEntity,
        endpoints: List<TargetEndpointEntity>,
        limits: ScanLimits,
        command: ScanCommand,
        identities: List<TestIdentityEntity>,
        rules: List<ResourceAccessRuleEntity>,
    ): ScanJobPayload {
        val scoped = when (module) {
            ModuleType.IDOR -> endpoints.filter { it.method == HttpMethod.GET || it.method == HttpMethod.HEAD }
            else -> endpoints
        }
        val options = when (module) {
            ModuleType.XSS -> ModuleOptions(xss = command.xss ?: XssOptions())
            ModuleType.SQLI -> ModuleOptions(sqli = command.sqli ?: SqliOptions())
            ModuleType.IDOR -> ModuleOptions(idor = idorOptions(command, scoped, identities, rules))
        }
        return ScanJobPayload(
            jobId = jobId,
            scanId = scanId,
            moduleType = module,
            attempt = attempt,
            deadlineAt = deadlineAt,
            policyId = policyId,
            target = TargetRef(target.id, target.baseUrl, target.allowedHosts),
            scope = ScopeRules(listOf(target.baseUrl + "/"), command.excludePrefixes),
            limits = limits,
            endpoints = scoped.map { EndpointRef(it.id, it.method, it.url, it.idempotent, it.parameters) },
            moduleOptions = options,
        )
    }

    private fun idorOptions(
        command: ScanCommand,
        endpoints: List<TargetEndpointEntity>,
        identities: List<TestIdentityEntity>,
        rules: List<ResourceAccessRuleEntity>,
    ): IdorOptions {
        val idor = command.idor ?: throw ValidationFailedException("idor options are required for the IDOR module")
        val selected = identities.filter { it.id in idor.identityIds }
        val selectedIds = selected.map { it.id }.toSet()
        val endpointIds = endpoints.map { it.id }.toSet()
        val resources = rules
            .filter { it.endpointId in endpointIds && it.ownerIdentityId in selectedIds }
            .map { rule ->
                ResourceRef(
                    resourceId = rule.id, endpointId = rule.endpointId, idParameter = rule.idParameter, idValue = rule.idValue,
                    ownerIdentityId = rule.ownerIdentityId, sensitivity = rule.sensitivity, ownerMarkers = rule.ownerMarkers,
                    access = rule.access.filter { it.identityId in selectedIds }.map { AccessRuleRef(it.identityId, it.expected) },
                )
            }
        if (resources.isEmpty()) throw ValidationFailedException("No access rules match the selected endpoints and identities")
        return IdorOptions(
            identities = selected.map { IdentityRef(it.id, it.label, it.role) },
            resources = resources,
            sessionCheck = idor.sessionCheck,
        )
    }
}

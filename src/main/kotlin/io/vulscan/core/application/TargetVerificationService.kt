package io.vulscan.core.application

import io.vulscan.core.config.ScannerProperties
import io.vulscan.core.domain.ConflictException
import io.vulscan.core.domain.ErrorCodes
import io.vulscan.core.persistence.TargetEntity
import io.vulscan.kit.contracts.HttpMethod
import io.vulscan.kit.net.Cidr
import io.vulscan.kit.net.HostResolver
import io.vulscan.kit.net.HttpLimits
import io.vulscan.kit.net.IpPolicy
import io.vulscan.kit.net.ProbeRequest
import io.vulscan.kit.net.SafeHttpClient
import io.vulscan.kit.net.ScopeMatcher
import org.springframework.stereotype.Service

/** Подтверждает владение целью: токен должен лежать в `/.well-known/vulnscan-<token>.txt`. */
@Service
class TargetVerificationService(
    properties: ScannerProperties,
    private val resolver: HostResolver,
) {
    private val policy = IpPolicy(properties.scope.allowedPrivateCidrs.map(Cidr::parse))

    fun verificationPath(token: String) = "/.well-known/vulnscan-$token.txt"

    /** @throws ConflictException с кодом VERIFICATION_FAILED, если файл недоступен или содержимое не совпало. */
    fun check(target: TargetEntity) {
        val path = verificationPath(target.verificationToken)
        val client = SafeHttpClient(
            scope = ScopeMatcher(target.allowedHosts, listOf(target.baseUrl + "/")),
            policy = policy,
            limits = HttpLimits(timeoutMs = 5000, maxResponseBytes = 4096),
            resolver = resolver,
        )
        val ok = try {
            val response = client.execute(ProbeRequest(HttpMethod.GET, target.baseUrl + path))
            response.status == 200 && !response.truncated && response.bodyText().trim() == target.verificationToken
        } catch (e: Exception) {
            false
        }
        if (!ok) throw ConflictException("Verification file was not found or has unexpected content", ErrorCodes.VERIFICATION_FAILED)
    }
}

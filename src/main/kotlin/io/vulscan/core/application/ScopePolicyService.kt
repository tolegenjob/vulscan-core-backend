package io.vulscan.core.application

import io.vulscan.core.config.ScannerProperties
import io.vulscan.core.domain.ScopeViolationException
import io.vulscan.kit.contracts.AllowedHost
import io.vulscan.kit.net.Cidr
import io.vulscan.kit.net.HostResolver
import io.vulscan.kit.net.IpPolicy
import io.vulscan.kit.net.SafeDns
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import org.springframework.stereotype.Service
import java.net.UnknownHostException
import io.vulscan.kit.net.ScopeViolationException as NetScopeViolation

data class ValidatedTarget(val baseUrl: String, val allowedHosts: List<AllowedHost>)

/** Проверка адреса цели до сохранения: защита от SSRF и сканирования внутренней сети. */
@Service
class ScopePolicyService(
    private val properties: ScannerProperties,
    resolver: HostResolver,
) {
    private val dns = SafeDns(IpPolicy(properties.scope.allowedPrivateCidrs.map(Cidr::parse)), resolver)

    fun validateTarget(rawBaseUrl: String): ValidatedTarget {
        val url = rawBaseUrl.trim().toHttpUrlOrNull() ?: reject("BAD_URL", "Target URL cannot be parsed or has an unsupported scheme")
        if (url.username.isNotEmpty() || url.password.isNotEmpty()) reject("USERINFO_NOT_ALLOWED", "Credentials in the URL are not allowed")
        if (url.query != null || url.fragment != null || url.encodedPath != "/") reject("BAD_URL", "Target URL must be a bare origin (scheme, host, port)")
        if (url.host.endsWith(".")) reject("BAD_HOST", "Host must not end with a dot")
        if (url.port !in properties.scope.allowedPorts) reject("PORT_NOT_ALLOWED", "Port ${url.port} is not allowed")
        try {
            dns.lookup(url.host)
        } catch (e: NetScopeViolation) {
            reject(e.reason.name, "Target host is not allowed (${e.reason.name})")
        } catch (e: UnknownHostException) {
            reject("HOST_NOT_RESOLVED", "Target host cannot be resolved")
        }
        val defaultPort = if (url.scheme == "https") 443 else 80
        val origin = "${url.scheme}://${url.host.let { if (it.contains(':')) "[$it]" else it }}" + if (url.port == defaultPort) "" else ":${url.port}"
        return ValidatedTarget(origin, listOf(AllowedHost(url.host, listOf(url.port))))
    }

    private fun reject(subcode: String, message: String): Nothing = throw ScopeViolationException("$subcode: $message")
}

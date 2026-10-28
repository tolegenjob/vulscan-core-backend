package io.vulscan.core.application

import io.vulscan.core.config.ScannerProperties
import io.vulscan.core.persistence.TargetEntity
import io.vulscan.core.persistence.TestIdentityEntity
import io.vulscan.core.security.EncryptedSecret
import io.vulscan.core.security.SecretCipher
import io.vulscan.kit.contracts.AuthType
import io.vulscan.kit.contracts.HttpMethod
import io.vulscan.kit.contracts.Json
import io.vulscan.kit.net.Cidr
import io.vulscan.kit.net.HostResolver
import io.vulscan.kit.net.HttpLimits
import io.vulscan.kit.net.IpPolicy
import io.vulscan.kit.net.ProbeRequest
import io.vulscan.kit.net.SafeHttpClient
import io.vulscan.kit.net.ScopeMatcher
import org.springframework.stereotype.Service
import java.net.URLEncoder

data class LoginTestResult(val ok: Boolean, val detail: String)

/** Пробный вход тестовой идентичности. В результат не попадают тело ответа и секреты. */
@Service
class IdentityLoginTester(
    properties: ScannerProperties,
    private val resolver: HostResolver,
    private val cipher: SecretCipher,
) {
    private val policy = IpPolicy(properties.scope.allowedPrivateCidrs.map(Cidr::parse))

    @Suppress("UNCHECKED_CAST")
    fun test(target: TargetEntity, identity: TestIdentityEntity): LoginTestResult {
        if (identity.authType != AuthType.FORM_LOGIN && identity.authType != AuthType.JSON_LOGIN) {
            return LoginTestResult(true, "Static credentials are not verified by a login request")
        }
        val secret = Json.mapper.readValue(cipher.decrypt(EncryptedSecret(identity.keyVersion, identity.secretEncrypted)), Map::class.java) as Map<String, String>
        val config = identity.authConfig
        val loginUrl = TargetScope.normalize(target.allowedHosts, target.baseUrl, config.getValue("loginUrl"))
            ?: return LoginTestResult(false, "Login URL is outside the target scope")
        val userField = config.getValue("usernameField")
        val passField = config.getValue("passwordField")
        val request = if (identity.authType == AuthType.FORM_LOGIN) {
            val body = listOf(userField to secret.getValue("username"), passField to secret.getValue("password"))
                .joinToString("&") { (k, v) -> URLEncoder.encode(k, Charsets.UTF_8) + "=" + URLEncoder.encode(v, Charsets.UTF_8) }
            ProbeRequest(HttpMethod.POST, loginUrl, body = body.toByteArray(), contentType = "application/x-www-form-urlencoded")
        } else {
            val body = Json.write(mapOf(userField to secret.getValue("username"), passField to secret.getValue("password")))
            ProbeRequest(HttpMethod.POST, loginUrl, body = body.toByteArray(), contentType = "application/json")
        }
        val client = SafeHttpClient(
            scope = ScopeMatcher(target.allowedHosts, listOf("${target.baseUrl}/")),
            policy = policy,
            limits = HttpLimits(timeoutMs = 5000, maxResponseBytes = 64 * 1024),
            resolver = resolver,
        )
        return try {
            val response = client.execute(request)
            val ok = if (identity.authType == AuthType.FORM_LOGIN) {
                response.status in 200..399 && response.headers.containsKey("set-cookie")
            } else {
                response.status in 200..299
            }
            LoginTestResult(ok, "HTTP ${response.status}" + if (ok) ", login accepted" else ", login was not accepted")
        } catch (e: Exception) {
            LoginTestResult(false, "Login request failed (${e.javaClass.simpleName})")
        }
    }
}

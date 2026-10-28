package io.vulscan.core.application

import io.vulscan.core.config.ScannerProperties
import io.vulscan.core.domain.ScopeViolationException
import io.vulscan.kit.net.HostResolver
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.CsvSource
import java.net.InetAddress
import java.net.UnknownHostException

class ScopePolicyServiceTest {

    private val resolver = HostResolver { host ->
        when (host) {
            "localhost" -> listOf(InetAddress.getByName("127.0.0.1"))
            "mixed.test" -> listOf(InetAddress.getByName("93.184.216.34"), InetAddress.getByName("10.0.0.5"))
            "lab-app" -> listOf(InetAddress.getByName("172.28.0.5"))
            "public.test" -> listOf(InetAddress.getByName("93.184.216.34"))
            else -> throw UnknownHostException(host)
        }
    }

    private fun properties(cidrs: List<String> = emptyList()) = ScannerProperties(
        scope = ScannerProperties.Scope(cidrs, listOf(80, 443, 8080, 8443)),
        limits = ScannerProperties.Limits(2, 4),
        jobs = ScannerProperties.Jobs(2, 600, 45, 200),
        outbox = ScannerProperties.Outbox(500, 50),
        secret = ScannerProperties.Secret("", 1),
        serviceTokens = ScannerProperties.ServiceTokens("", "", ""),
        bootstrapAdmin = ScannerProperties.BootstrapAdmin("", ""),
    )

    private val service = ScopePolicyService(properties(), resolver)

    @ParameterizedTest
    @CsvSource(
        "http://localhost,PRIVATE_ADDRESS",
        "http://127.0.0.1,PRIVATE_ADDRESS",
        "http://[::1],PRIVATE_ADDRESS",
        "http://169.254.169.254,PRIVATE_ADDRESS",
        "http://2130706433,BAD_HOST",
        "http://user:pw@public.test,USERINFO_NOT_ALLOWED",
        "ftp://public.test,BAD_URL",
        "http://public.test:22,PORT_NOT_ALLOWED",
        "http://mixed.test,PRIVATE_ADDRESS",
        "http://public.test/path,BAD_URL",
        "http://public.test?x=1,BAD_URL",
        "http://nonexistent.test,HOST_NOT_RESOLVED",
        "not a url,BAD_URL",
    )
    fun `dangerous or malformed targets are rejected`(url: String, subcode: String) {
        assertThatThrownBy { service.validateTarget(url) }
            .isInstanceOf(ScopeViolationException::class.java)
            .hasMessageStartingWith(subcode)
    }

    @Test
    fun `public host is accepted and normalized`() {
        val result = service.validateTarget("HTTP://Public.Test:8080")
        assertThat(result.baseUrl).isEqualTo("http://public.test:8080")
        assertThat(result.allowedHosts.single().host).isEqualTo("public.test")
        assertThat(result.allowedHosts.single().ports).containsExactly(8080)
    }

    @Test
    fun `default port is omitted`() {
        assertThat(service.validateTarget("https://public.test:443").baseUrl).isEqualTo("https://public.test")
    }

    @Test
    fun `private address is accepted when allowlisted`() {
        val lab = ScopePolicyService(properties(listOf("172.16.0.0/12")), resolver)
        assertThat(lab.validateTarget("http://lab-app:8080").baseUrl).isEqualTo("http://lab-app:8080")
        assertThatThrownBy { service.validateTarget("http://lab-app:8080") }.isInstanceOf(ScopeViolationException::class.java)
    }

    @Test
    fun `cloud metadata address cannot be allowlisted`() {
        val lax = ScopePolicyService(properties(listOf("169.254.0.0/16", "0.0.0.0/0")), resolver)
        assertThatThrownBy { lax.validateTarget("http://169.254.169.254") }.hasMessageStartingWith("PRIVATE_ADDRESS")
    }
}

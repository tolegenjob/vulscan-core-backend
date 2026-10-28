package io.vulscan.core.support

import io.vulscan.kit.net.HostResolver
import org.springframework.boot.test.context.TestConfiguration
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Primary
import java.net.InetAddress
import java.net.UnknownHostException

/** Детерминированный DNS для тестов: `*.test` — публичный адрес, `private.test` — внутренний. */
@TestConfiguration(proxyBeanMethods = false)
class TestHostResolverConfig {
    @Bean
    @Primary
    fun testHostResolver(): HostResolver = HostResolver { host ->
        when {
            host == "private.test" -> listOf(InetAddress.getByName("10.0.0.5"))
            host.endsWith(".test") -> listOf(InetAddress.getByName("93.184.216.34"))
            else -> throw UnknownHostException(host)
        }
    }
}

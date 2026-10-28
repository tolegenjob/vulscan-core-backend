package io.vulscan.core.config

import io.vulscan.kit.net.HostResolver
import io.vulscan.kit.net.SystemHostResolver
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration

@Configuration(proxyBeanMethods = false)
class NetworkConfig {
    /** DNS-резолвер для проверки целей; в тестах подменяется. */
    @Bean
    fun hostResolver(): HostResolver = SystemHostResolver
}

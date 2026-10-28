package io.vulscan.core.persistence

import io.vulscan.kit.contracts.Json
import org.hibernate.cfg.AvailableSettings
import org.hibernate.type.descriptor.WrapperOptions
import org.hibernate.type.descriptor.java.JavaType
import org.hibernate.type.format.FormatMapper
import org.springframework.boot.hibernate.autoconfigure.HibernatePropertiesCustomizer
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration

/** JSON-колонки сериализуются тем же Jackson-маппером, что и контракты (общие настройки дат и enum). */
class KitJsonFormatMapper : FormatMapper {
    override fun <T : Any?> fromString(charSequence: CharSequence, javaType: JavaType<T>, wrapperOptions: WrapperOptions): T {
        val type = Json.mapper.constructType(javaType.javaType)
        return Json.mapper.readValue(charSequence.toString(), type)
    }

    override fun <T : Any?> toString(value: T, javaType: JavaType<T>, wrapperOptions: WrapperOptions): String =
        Json.mapper.writeValueAsString(value)
}

@Configuration(proxyBeanMethods = false)
class JsonFormatMapperConfig {
    @Bean
    fun jsonFormatMapperCustomizer() = HibernatePropertiesCustomizer { props ->
        props[AvailableSettings.JSON_FORMAT_MAPPER] = KitJsonFormatMapper()
    }
}

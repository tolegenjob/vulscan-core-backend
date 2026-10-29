package io.vulscan.core.observability

import ch.qos.logback.classic.pattern.ClassicConverter
import ch.qos.logback.classic.spi.ILoggingEvent
import io.vulscan.kit.redact.Redactor

/** Подставляется в шаблон логов вместо `%m`: маскирует значения секретных полей (пароли, токены, cookie) в тексте сообщения. */
class RedactingMessageConverter : ClassicConverter() {
    override fun convert(event: ILoggingEvent): String = Redactor.body(event.formattedMessage ?: "")
}

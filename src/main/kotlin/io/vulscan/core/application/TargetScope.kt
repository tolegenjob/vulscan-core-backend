package io.vulscan.core.application

import io.vulscan.kit.contracts.AllowedHost
import io.vulscan.kit.net.ScopeDecision
import io.vulscan.kit.net.ScopeMatcher

object TargetScope {
    /** Нормализованный URL, если он принадлежит цели (host, порт и префикс), иначе null. */
    fun normalize(allowedHosts: List<AllowedHost>, baseUrl: String, url: String): String? =
        when (val decision = ScopeMatcher(allowedHosts, listOf("$baseUrl/")).check(url)) {
            is ScopeDecision.Allowed -> decision.url.toString()
            is ScopeDecision.Denied -> null
        }
}

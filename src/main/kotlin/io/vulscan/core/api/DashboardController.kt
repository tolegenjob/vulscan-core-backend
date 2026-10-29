package io.vulscan.core.api

import io.vulscan.core.application.DashboardService
import io.vulscan.core.security.AppUserDetails
import org.springframework.security.core.annotation.AuthenticationPrincipal
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController

@RestController
@RequestMapping("/api/v1/dashboard")
class DashboardController(private val service: DashboardService) {
    @GetMapping("/summary")
    fun summary(@AuthenticationPrincipal user: AppUserDetails) = service.summary(user.toCurrentUser())
}

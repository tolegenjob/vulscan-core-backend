package io.vulscan.core.application

import io.vulscan.core.config.ScannerProperties
import io.vulscan.core.domain.UserRole
import io.vulscan.core.persistence.UserEntity
import io.vulscan.core.persistence.UserRepository
import org.slf4j.LoggerFactory
import org.springframework.boot.ApplicationArguments
import org.springframework.boot.ApplicationRunner
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.stereotype.Component

/** Создаёт первого ADMIN из переменных окружения, только если таблица users пуста. */
@Component
class AdminBootstrap(
    private val users: UserRepository,
    private val properties: ScannerProperties,
    private val encoder: PasswordEncoder,
) : ApplicationRunner {
    private val log = LoggerFactory.getLogger(AdminBootstrap::class.java)

    override fun run(args: ApplicationArguments) {
        val admin = properties.bootstrapAdmin
        if (admin.user.isBlank() || admin.password.isBlank()) return
        if (users.count() > 0) return
        users.save(UserEntity(username = admin.user, passwordHash = encoder.encode(admin.password)!!, role = UserRole.ADMIN))
        log.info("Bootstrap admin '{}' created", admin.user)
    }
}

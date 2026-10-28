package io.vulscan.core.security

import io.vulscan.core.domain.NotFoundException
import io.vulscan.core.domain.UserRole
import io.vulscan.kit.contracts.ModuleType
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.userdetails.UserDetails
import java.util.UUID

/** Пользователь, от имени которого выполняется запрос. */
data class CurrentUser(val id: UUID, val username: String, val role: UserRole) {
    val isAdmin: Boolean get() = role == UserRole.ADMIN
}

class AppUserDetails(
    val id: UUID,
    private val username: String,
    private val passwordHash: String,
    val role: UserRole,
    private val enabled: Boolean,
) : UserDetails {
    override fun getAuthorities(): Collection<GrantedAuthority> = listOf(SimpleGrantedAuthority("ROLE_${role.name}"))
    override fun getPassword(): String = passwordHash
    override fun getUsername(): String = username
    override fun isEnabled(): Boolean = enabled
    fun toCurrentUser() = CurrentUser(id, username, role)

    // Хэш пароля не должен попадать в сессию в открытом виде: сериализуется только идентичность
    override fun toString(): String = "AppUserDetails(id=$id, username=$username, role=$role)"
}

/** Принципал внутреннего API: модуль-воркер, аутентифицированный сервисным токеном. */
data class ModuleWorker(val moduleType: ModuleType, val workerId: String)

/** Единственное место проверки владения объектом. Чужой объект выглядит как несуществующий. */
object OwnershipPolicy {
    fun requireAccess(user: CurrentUser, ownerId: UUID) {
        if (!user.isAdmin && user.id != ownerId) throw NotFoundException()
    }
}

package io.vulscan.core.security

import io.vulscan.core.domain.NotFoundException
import io.vulscan.core.domain.UserRole
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.junit.jupiter.api.Test
import java.util.UUID

class OwnershipPolicyTest {
    private val owner = CurrentUser(UUID.randomUUID(), "o", UserRole.USER)
    private val other = CurrentUser(UUID.randomUUID(), "x", UserRole.USER)
    private val admin = CurrentUser(UUID.randomUUID(), "a", UserRole.ADMIN)

    @Test
    fun `owner and admin have access, others get not found`() {
        OwnershipPolicy.requireAccess(owner, owner.id)
        OwnershipPolicy.requireAccess(admin, owner.id)
        assertThatThrownBy { OwnershipPolicy.requireAccess(other, owner.id) }.isInstanceOf(NotFoundException::class.java)
    }
}

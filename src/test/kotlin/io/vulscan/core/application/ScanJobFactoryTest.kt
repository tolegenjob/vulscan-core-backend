package io.vulscan.core.application

import io.vulscan.core.persistence.ResourceAccessRuleEntity
import io.vulscan.core.persistence.TargetEndpointEntity
import io.vulscan.core.persistence.TargetEntity
import io.vulscan.core.persistence.TestIdentityEntity
import io.vulscan.kit.contracts.AccessRuleRef
import io.vulscan.kit.contracts.AllowedHost
import io.vulscan.kit.contracts.AuthType
import io.vulscan.kit.contracts.ExpectedAccess
import io.vulscan.kit.contracts.HttpMethod
import io.vulscan.kit.contracts.Json
import io.vulscan.kit.contracts.ModuleType
import io.vulscan.kit.contracts.ParamLocation
import io.vulscan.kit.contracts.ParameterId
import io.vulscan.kit.contracts.ScanJobPayloadValidator
import io.vulscan.kit.contracts.ScanLimits
import io.vulscan.kit.contracts.Sensitivity
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import java.time.Instant
import java.util.UUID

class ScanJobFactoryTest {
    private val target = TargetEntity(baseUrl = "http://lab-app:8080", allowedHosts = listOf(AllowedHost("lab-app", listOf(8080))))
    private val getEndpoint = TargetEndpointEntity(targetId = target.id, method = HttpMethod.GET, url = "http://lab-app:8080/orders/{id}", idempotent = true)
    private val postEndpoint = TargetEndpointEntity(targetId = target.id, method = HttpMethod.POST, url = "http://lab-app:8080/orders")
    private val alice = TestIdentityEntity(targetId = target.id, label = "alice", role = "USER", authType = AuthType.BEARER_STATIC, secretEncrypted = "ENCRYPTED-ALICE".toByteArray())
    private val bob = TestIdentityEntity(targetId = target.id, label = "bob", role = "USER", authType = AuthType.BEARER_STATIC, secretEncrypted = "ENCRYPTED-BOB".toByteArray())
    private val rule = ResourceAccessRuleEntity(
        targetId = target.id, endpointId = getEndpoint.id, idParameter = ParameterId("id", ParamLocation.PATH), idValue = "1",
        ownerIdentityId = alice.id, sensitivity = Sensitivity.HIGH, ownerMarkers = listOf("$.email"),
        access = listOf(AccessRuleRef(bob.id, ExpectedAccess.DENY)),
    )
    private val limits = ScanLimits(200, 2, 1, 10000, 1048576, 1800)

    private fun build(module: ModuleType, command: ScanCommand) = ScanJobFactory.build(
        UUID.randomUUID(), UUID.randomUUID(), module, 1, Instant.now().plusSeconds(3600), UUID.randomUUID(), target,
        listOf(getEndpoint, postEndpoint), limits, command, listOf(alice, bob), listOf(rule),
    )

    @Test
    fun `xss job is valid and keeps all endpoints`() {
        val payload = build(ModuleType.XSS, ScanCommand(target.id, modules = listOf(ModuleType.XSS), endpointIds = listOf(getEndpoint.id, postEndpoint.id)))
        assertThat(ScanJobPayloadValidator.validate(payload)).isEmpty()
        assertThat(payload.endpoints).hasSize(2)
        assertThat(payload.scope.includePrefixes).containsExactly("http://lab-app:8080/")
    }

    @Test
    fun `idor job is read only valid and carries no secrets`() {
        val command = ScanCommand(target.id, modules = listOf(ModuleType.IDOR), endpointIds = listOf(getEndpoint.id, postEndpoint.id), idor = IdorCommand(listOf(alice.id, bob.id)))
        val payload = build(ModuleType.IDOR, command)
        assertThat(ScanJobPayloadValidator.validate(payload)).isEmpty()
        assertThat(payload.endpoints.map { it.method }).containsOnly(HttpMethod.GET)
        val json = Json.write(payload)
        assertThat(json).doesNotContain("ENCRYPTED").doesNotContain("secret").doesNotContain("password")
        assertThat(payload.moduleOptions.idor!!.identities.map { it.label }).containsExactlyInAnyOrder("alice", "bob")
        assertThat(payload.moduleOptions.idor!!.resources).hasSize(1)
    }

    @Test
    fun `idor without matching access rules is rejected`() {
        val command = ScanCommand(target.id, modules = listOf(ModuleType.IDOR), endpointIds = listOf(postEndpoint.id), idor = IdorCommand(listOf(alice.id, bob.id)))
        org.assertj.core.api.Assertions.assertThatThrownBy {
            ScanJobFactory.build(UUID.randomUUID(), UUID.randomUUID(), ModuleType.IDOR, 1, Instant.now().plusSeconds(60), UUID.randomUUID(), target, listOf(postEndpoint), limits, command, listOf(alice, bob), listOf(rule))
        }.isInstanceOf(io.vulscan.core.domain.ValidationFailedException::class.java)
    }
}

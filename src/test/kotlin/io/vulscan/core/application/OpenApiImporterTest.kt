package io.vulscan.core.application

import io.vulscan.kit.contracts.HttpMethod
import io.vulscan.kit.contracts.Json
import io.vulscan.kit.contracts.ParamLocation
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class OpenApiImporterTest {

    @Suppress("UNCHECKED_CAST")
    private fun doc(json: String): Map<String, Any?> = Json.mapper.readValue(json, Map::class.java) as Map<String, Any?>

    private val fixture = """
    {
      "openapi": "3.0.3",
      "paths": {
        "/search": {
          "get": {"parameters": [{"name": "q", "in": "query", "schema": {"type": "string", "example": "abc"}}]}
        },
        "/users": {
          "post": {
            "requestBody": {"content": {"application/json": {"schema": {"type": "object", "properties": {"name": {"type": "string", "example": "bob"}, "email": {"type": "string"}}}}}}
          },
          "delete": {}
        },
        "/orders/{id}": {
          "get": {"parameters": [{"${'$'}ref": "#/components/parameters/OrderId"}, {"name": "X-Trace", "in": "header"}, {"name": "sid", "in": "cookie"}]}
        },
        "/items": {
          "post": {"requestBody": {"${'$'}ref": "#/components/requestBodies/Item"}}
        }
      },
      "components": {
        "parameters": {"OrderId": {"name": "id", "in": "path", "required": true}},
        "requestBodies": {"Item": {"content": {"application/json": {"schema": {"${'$'}ref": "#/components/schemas/Item"}}}}},
        "schemas": {"Item": {"properties": {"sku": {"type": "string"}}}}
      }
    }
    """

    @Test
    fun `endpoints parameters and skipped operations are extracted`() {
        val result = OpenApiImporter.parse(doc(fixture), "http://lab-app:8080/")
        val byKey = result.endpoints.associateBy { it.method to it.urlTemplate }

        val search = byKey.getValue(HttpMethod.GET to "http://lab-app:8080/search")
        assertThat(search.idempotent).isTrue()
        assertThat(search.parameters.single().name).isEqualTo("q")
        assertThat(search.parameters.single().location).isEqualTo(ParamLocation.QUERY)
        assertThat(search.parameters.single().sampleValue).isEqualTo("abc")

        val users = byKey.getValue(HttpMethod.POST to "http://lab-app:8080/users")
        assertThat(users.idempotent).isFalse()
        assertThat(users.parameters.map { it.name }).containsExactlyInAnyOrder("name", "email")
        assertThat(users.parameters).allMatch { it.location == ParamLocation.BODY_JSON }

        val order = byKey.getValue(HttpMethod.GET to "http://lab-app:8080/orders/{id}")
        assertThat(order.parameters.map { it.name to it.location })
            .containsExactlyInAnyOrder("id" to ParamLocation.PATH, "X-Trace" to ParamLocation.HEADER)

        val item = byKey.getValue(HttpMethod.POST to "http://lab-app:8080/items")
        assertThat(item.parameters.map { it.name }).containsExactly("sku")

        assertThat(result.skipped).anyMatch { it.method == "DELETE" && it.reason == "UNSUPPORTED_METHOD" }
    }

    @Test
    fun `document without paths is reported`() {
        val result = OpenApiImporter.parse(doc("""{"openapi":"3.0.3"}"""), "http://x")
        assertThat(result.endpoints).isEmpty()
        assertThat(result.skipped.single().reason).isEqualTo("NO_PATHS")
    }

    @Test
    fun `path templates become concrete urls for scope checks`() {
        assertThat(OpenApiImporter.concreteUrl("http://a/orders/{id}/items/{n}")).isEqualTo("http://a/orders/1/items/1")
    }
}

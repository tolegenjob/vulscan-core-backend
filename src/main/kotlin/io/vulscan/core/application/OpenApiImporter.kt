package io.vulscan.core.application

import io.vulscan.kit.contracts.HttpMethod
import io.vulscan.kit.contracts.ParamLocation
import io.vulscan.kit.contracts.ParameterRef

data class ImportedEndpoint(val method: HttpMethod, val urlTemplate: String, val parameters: List<ParameterRef>, val idempotent: Boolean)

data class SkippedOperation(val path: String, val method: String, val reason: String)

data class ImportParseResult(val endpoints: List<ImportedEndpoint>, val skipped: List<SkippedOperation>)

/**
 * Преобразует документ OpenAPI 3 (уже разобранный в Map) в список endpoints.
 * Поддерживаются GET и POST; `$ref` разворачивается не глубже одного уровня.
 */
object OpenApiImporter {
    private val SUPPORTED = mapOf("get" to HttpMethod.GET, "post" to HttpMethod.POST)
    private val PLACEHOLDER = Regex("\\{[^}]+}")

    fun parse(document: Map<String, Any?>, serverUrl: String, maxOperations: Int = 200): ImportParseResult {
        val paths = document["paths"].asMap() ?: return ImportParseResult(emptyList(), listOf(SkippedOperation("", "", "NO_PATHS")))
        val server = serverUrl.trimEnd('/')
        val endpoints = mutableListOf<ImportedEndpoint>()
        val skipped = mutableListOf<SkippedOperation>()

        for ((path, item) in paths) {
            val pathItem = item.asMap() ?: continue
            for ((methodName, operation) in pathItem) {
                if (methodName in setOf("parameters", "summary", "description", "servers") || methodName.startsWith("x-")) continue
                val method = SUPPORTED[methodName.lowercase()]
                if (method == null) {
                    skipped += SkippedOperation(path, methodName.uppercase(), "UNSUPPORTED_METHOD")
                    continue
                }
                if (endpoints.size >= maxOperations) {
                    skipped += SkippedOperation(path, methodName.uppercase(), "TOO_MANY_OPERATIONS")
                    continue
                }
                val op = operation.asMap() ?: continue
                val params = mutableListOf<ParameterRef>()
                (pathItem["parameters"].asList() + op["parameters"].asList()).forEach { raw ->
                    val param = resolve(document, raw.asMap()) ?: return@forEach
                    toParameter(document, param)?.let(params::add)
                }
                params += bodyParameters(document, op)
                endpoints += ImportedEndpoint(method, server + path, params.distinctBy { it.name to it.location }, method == HttpMethod.GET)
            }
        }
        return ImportParseResult(endpoints, skipped)
    }

    /** Подставляет в шаблон пути значения, чтобы URL можно было проверить на принадлежность scope. */
    fun concreteUrl(template: String): String = template.replace(PLACEHOLDER, "1")

    private fun toParameter(document: Map<String, Any?>, param: Map<String, Any?>): ParameterRef? {
        val name = param["name"] as? String ?: return null
        val location = when (param["in"]) {
            "query" -> ParamLocation.QUERY
            "path" -> ParamLocation.PATH
            "header" -> ParamLocation.HEADER
            else -> return null
        }
        val schema = resolve(document, param["schema"].asMap())
        val sample = (param["example"] ?: schema?.get("example") ?: schema?.get("default"))?.toString()
        return ParameterRef(name, location, sample)
    }

    private fun bodyParameters(document: Map<String, Any?>, op: Map<String, Any?>): List<ParameterRef> {
        val body = resolve(document, op["requestBody"].asMap()) ?: return emptyList()
        val json = body["content"].asMap()?.get("application/json").asMap() ?: return emptyList()
        val schema = resolve(document, json["schema"].asMap()) ?: return emptyList()
        val properties = schema["properties"].asMap() ?: return emptyList()
        return properties.map { (name, value) ->
            val sample = value.asMap()?.let { (it["example"] ?: it["default"])?.toString() }
            ParameterRef(name, ParamLocation.BODY_JSON, sample)
        }
    }

    /** Разворачивает `$ref` вида `#/components/...` на один уровень. */
    private fun resolve(document: Map<String, Any?>, node: Map<String, Any?>?): Map<String, Any?>? {
        val ref = node?.get("\$ref") as? String ?: return node
        if (!ref.startsWith("#/")) return null
        var current: Any? = document
        for (part in ref.removePrefix("#/").split('/')) {
            current = current.asMap()?.get(part.replace("~1", "/").replace("~0", "~")) ?: return null
        }
        return current.asMap()
    }

    @Suppress("UNCHECKED_CAST")
    private fun Any?.asMap(): Map<String, Any?>? = this as? Map<String, Any?>

    private fun Any?.asList(): List<Any?> = (this as? List<*>)?.toList() ?: emptyList()
}

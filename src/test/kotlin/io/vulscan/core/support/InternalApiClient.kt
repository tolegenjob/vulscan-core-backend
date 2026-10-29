package io.vulscan.core.support

import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse

/** Клиент внутреннего API для тестов: сервисный токен и идентификатор worker передаются явно. */
class InternalApiClient(private val port: Int) {
    private val http = HttpClient.newHttpClient()

    fun post(path: String, body: String, token: String?, workerId: String? = "w-1"): HttpResponse<String> =
        send(builder(path, token, workerId).header("Content-Type", "application/json").POST(HttpRequest.BodyPublishers.ofString(body)))

    fun get(path: String, token: String?, workerId: String? = "w-1"): HttpResponse<String> = send(builder(path, token, workerId).GET())

    private fun builder(path: String, token: String?, workerId: String?): HttpRequest.Builder {
        val b = HttpRequest.newBuilder(URI("http://localhost:$port$path"))
        token?.let { b.header("Authorization", "Bearer $it") }
        workerId?.let { b.header("X-Worker-Id", it) }
        return b
    }

    private fun send(b: HttpRequest.Builder): HttpResponse<String> = http.send(b.build(), HttpResponse.BodyHandlers.ofString())

    companion object {
        const val XSS = "test-token-xss"
        const val SQLI = "test-token-sqli"
        const val IDOR = "test-token-idor"
    }
}

package io.vulscan.core.support

import java.net.CookieManager
import java.net.CookiePolicy
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse

/** Минимальный клиент для интеграционных тестов: cookie-сессия и CSRF-заголовок. */
class ApiClient(private val port: Int) {
    private val http = HttpClient.newBuilder().cookieHandler(CookieManager(null, CookiePolicy.ACCEPT_ALL)).build()
    var csrf: String? = null

    fun login(username: String, password: String): HttpResponse<String> {
        val response = post("/api/v1/auth/login", """{"username":"$username","password":"$password"}""")
        if (response.statusCode() == 200) {
            csrf = Regex("\"csrfToken\":\"([^\"]+)\"").find(response.body())?.groupValues?.get(1)
        }
        return response
    }

    fun get(path: String): HttpResponse<String> = send(builder(path).GET())

    fun post(path: String, body: String = ""): HttpResponse<String> =
        send(builder(path).header("Content-Type", "application/json").POST(HttpRequest.BodyPublishers.ofString(body)))

    fun patch(path: String, body: String): HttpResponse<String> =
        send(builder(path).header("Content-Type", "application/json").method("PATCH", HttpRequest.BodyPublishers.ofString(body)))

    fun delete(path: String): HttpResponse<String> = send(builder(path).DELETE())

    private fun builder(path: String): HttpRequest.Builder {
        val b = HttpRequest.newBuilder(URI("http://localhost:$port$path"))
        csrf?.let { b.header("X-XSRF-TOKEN", it) }
        return b
    }

    private fun send(b: HttpRequest.Builder): HttpResponse<String> = http.send(b.build(), HttpResponse.BodyHandlers.ofString())

    fun field(response: HttpResponse<String>, name: String): String =
        Regex("\"$name\":\"([^\"]+)\"").find(response.body())?.groupValues?.get(1) ?: error("no $name in ${response.body()}")
}

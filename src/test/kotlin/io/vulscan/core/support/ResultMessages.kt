package io.vulscan.core.support

import io.vulscan.kit.contracts.Envelope
import io.vulscan.kit.contracts.Evidence
import io.vulscan.kit.contracts.FindingPayload
import io.vulscan.kit.contracts.FindingReportedPayload
import io.vulscan.kit.contracts.HttpMethod
import io.vulscan.kit.contracts.HttpRequestEvidence
import io.vulscan.kit.contracts.JobCompletedPayload
import io.vulscan.kit.contracts.JobErrorCode
import io.vulscan.kit.contracts.JobFailedPayload
import io.vulscan.kit.contracts.JobStats
import io.vulscan.kit.contracts.Json
import io.vulscan.kit.contracts.MessageType
import io.vulscan.kit.contracts.ModuleType
import io.vulscan.kit.contracts.ParamLocation
import io.vulscan.kit.contracts.ParameterId
import io.vulscan.kit.contracts.Severity
import io.vulscan.kit.contracts.Verdict
import io.vulscan.kit.contracts.VulnType
import io.vulscan.kit.contracts.XssDetails
import java.util.UUID

/** Сообщения модулей для тестов Core. */
object ResultMessages {
    fun fingerprint(seed: String = UUID.randomUUID().toString()): String = io.vulscan.kit.contracts.Fingerprint.of(seed)

    fun finding(
        jobId: UUID,
        attempt: Int = 1,
        fingerprint: String = fingerprint(),
        messageId: UUID = UUID.randomUUID(),
        confidence: Int = 80,
        module: ModuleType = ModuleType.XSS,
    ): String {
        val finding = FindingPayload(
            moduleType = module, vulnType = VulnType.XSS_REFLECTED, cwe = "CWE-79", method = HttpMethod.GET,
            url = "http://lab/search", parameter = ParameterId("q", ParamLocation.QUERY), verdict = Verdict.CONFIRMED,
            severity = Severity.HIGH, confidence = confidence, fingerprint = fingerprint, title = "Reflected XSS",
            summary = "summary", recommendation = "encode output",
            details = XssDetails(VulnType.XSS_REFLECTED, "HTML_TEXT", listOf("<", ">"), "DOM_STRUCTURE"),
            evidence = Evidence(HttpRequestEvidence(HttpMethod.GET, "http://lab/search?q=x")),
        )
        return Json.write(Envelope(messageId = messageId, type = MessageType.FINDING_REPORTED, correlationId = UUID.randomUUID(), payload = FindingReportedPayload(jobId, attempt, finding)))
    }

    fun completed(jobId: UUID, attempt: Int = 1, findingsCount: Int = 0, messageId: UUID = UUID.randomUUID()): String =
        Json.write(
            Envelope(
                messageId = messageId, type = MessageType.JOB_COMPLETED, correlationId = UUID.randomUUID(),
                payload = JobCompletedPayload(jobId, attempt, JobStats(findingsCount, requestsSent = 10, durationMs = 1000, endpointsTested = 2)),
            ),
        )

    fun failed(jobId: UUID, attempt: Int = 1, retryable: Boolean = false, code: JobErrorCode = JobErrorCode.INTERNAL_ERROR, messageId: UUID = UUID.randomUUID()): String =
        Json.write(
            Envelope(
                messageId = messageId, type = MessageType.JOB_FAILED, correlationId = UUID.randomUUID(),
                payload = JobFailedPayload(jobId, attempt, code, "boom", retryable),
            ),
        )
}

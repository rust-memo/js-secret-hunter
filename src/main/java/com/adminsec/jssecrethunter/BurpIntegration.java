package com.adminsec.jssecrethunter;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import com.adminsec.jssecrethunter.model.Confidence;
import com.adminsec.jssecrethunter.model.Finding;
import com.adminsec.jssecrethunter.model.Severity;

import java.util.List;

final class BurpIntegration {
    private BurpIntegration() {}

    static void publish(MontoyaApi api, HunterRepository repository, Finding finding) {
        api.siteMap().add(auditIssue(finding));
        repository.markPublished(finding);
    }

    static AuditIssue auditIssue(Finding finding) {
        String detail = detail(finding);
        String remediation = "Remove sensitive values from client-accessible content, rotate exposed credentials, "
                + "and move secrets to a server-side secret store. Restrict any affected credential to the minimum required privileges.";
        String background = "Client-accessible JavaScript and text responses can disclose credentials, internal endpoints, and configuration data.";
        HttpRequestResponse message = HttpRequestResponse.httpRequestResponse(finding.request(), finding.response());
        AuditIssueSeverity severity = severity(finding.severity());
        return AuditIssue.auditIssue("JS Secret Hunter: " + finding.ruleName(), detail, remediation,
                finding.assetUrl(), severity, confidence(finding.confidence()), background, remediation,
                severity, List.of(message));
    }

    static String detail(Finding finding) {
        return "<p>JS Secret Hunter identified a reviewed candidate in a text response.</p>"
                + "<ul><li>Rule: <b>" + html(finding.ruleName()) + "</b> (" + html(finding.ruleId()) + ")</li>"
                + "<li>Masked value: <code>" + html(finding.maskedValue()) + "</code></li>"
                + "<li>SHA-256: <code>" + html(finding.valueFingerprint()) + "</code></li>"
                + "<li>Asset: <code>" + html(finding.assetUrl()) + "</code></li>"
                + "<li>Line: " + finding.line() + "</li></ul>"
                + "<p>The value is intentionally redacted. Review the attached response in Burp.</p>";
    }

    static AuditIssueSeverity severity(Severity severity) {
        return switch (severity) {
            case CRITICAL, HIGH -> AuditIssueSeverity.HIGH;
            case MEDIUM -> AuditIssueSeverity.MEDIUM;
            case INFO -> AuditIssueSeverity.INFORMATION;
        };
    }

    static AuditIssueConfidence confidence(Confidence confidence) {
        return confidence == Confidence.HIGH ? AuditIssueConfidence.FIRM : AuditIssueConfidence.TENTATIVE;
    }

    private static String html(String value) {
        if (value == null) return "";
        return value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                .replace("\"", "&quot;").replace("'", "&#39;");
    }
}

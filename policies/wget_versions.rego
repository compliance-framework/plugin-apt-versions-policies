package compliance_framework.apt_versions.apt_versions

risk_templates := [{
	"name": "Outdated wget package detected",
	"title": "Unpatched wget Version Exposure",
	"statement": "Running an outdated wget version increases exposure to publicly known vulnerabilities that may be exploited through content retrieval workflows, administrative automation, or user-initiated downloads, potentially impacting confidentiality, integrity, and availability.",
	"likelihood_hint": "medium",
	"impact_hint": "medium",
	"violation_ids": ["wget_version"],
	"threat_refs": [
		{
			"system": "https://cwe.mitre.org",
			"external_id": "CWE-1104",
			"title": "Use of Unmaintained Third Party Components",
			"url": "https://cwe.mitre.org/data/definitions/1104.html"
		}
	],
	"remediation": {
		"title": "Patch wget and enforce package currency",
		"description": "Upgrade wget to a vendor-supported, security-patched release and maintain documented patch governance, with approved compensating controls when immediate upgrade is not feasible.",
		"tasks": [
			{"title": "Validate installed wget version and distribution support status"},
			{"title": "Upgrade wget to 1.20.3 or later, or to a distribution-equivalent security-patched release"},
			{"title": "Confirm package origin and trust chain for the applied update"},
			{"title": "Re-test dependent retrieval jobs and automation after upgrade"},
			{"title": "If upgrade must be deferred, document exception approval and compensating controls"},
			{"title": "Retain version and change evidence for SOC 2 and ISO/IEC 27001/27002 auditability"},
		],
	},
}]


violation[{
	"id": "wget_version",
    "remarks": sprintf("WGET version is currently |%s|", [input.wget])
}] if {
    semver.compare(input.wget, "1.20.3") == -1
}

title := "Wget version is safe"
description := sprintf("Wget versions should be 1.20.3 or higher to avoid vulnerabilities. Current version |%s|", [input.wget])

labels := {
    "package_name": "wget"
}
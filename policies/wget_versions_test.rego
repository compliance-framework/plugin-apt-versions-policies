package compliance_framework.apt_versions.apt_versions_test

import data.compliance_framework.apt_versions.apt_versions

# data.wget_version is loaded from policies/data.json, which Regal doesn't read, so the
# `with data.wget_version` lines below ignore Regal's unresolved-reference rule.

test_violates_if_old_version if {
	count(apt_versions.violation) == 1 with input as {"wget": "1.20.0"}
		with data.wget_version as "1.99.9" # regal ignore:unresolved-reference
}

test_passes_if_newer_version if {
	count(apt_versions.violation) == 0 with input as {"wget": "1.21.0"}

	count(apt_versions.violation) == 0 with input as {"wget": "1.22.0"}
		with data.wget_version as "1.0.0" # regal ignore:unresolved-reference
}

test_passes_if_not_installed if {
	count(apt_versions.violation) == 0 with input as {}
}

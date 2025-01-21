package compliance_framework.apt_versions.apt_versions_test

import data.compliance_framework.apt_versions.apt_versions

test_violates_if_old_version if {
       count(apt_versions.violation) == 1 with input as {
        "wget": "1.20.0"
    }
}

test_passes_if_newer_version if {
       count(apt_versions.violation) == 0 with input as {
        "wget": "1.21.0"
    }

    count(apt_versions.violation) == 0 with input as {
        "wget": "1.22.0"
    }
}

test_passes_if_not_installed if {
       count(apt_versions.violation) == 0 with input as {}
}

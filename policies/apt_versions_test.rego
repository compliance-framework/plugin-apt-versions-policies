package compliance_framework.apt_versions.apt_versions

test_ok if {
    count(violation) == 0 with input as {
        {"Package": "wget", "Version": "1.21.0"}
    }
}

test_fail if {
    count(violation) == 1 with input as {
        {"Package": "wget", "Version": "1.20.0"}
    }
}

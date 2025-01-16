package compliance_framework.apt_versions.apt_versions

test_bash_high_3 if {
    count(violation) == 1 with input as {
        "bash": "3"
    }
}

test_bash_high_11 if {
    count(violation) == 1 with input as {
        "bash": "11"
    }
}

test_bash_correct if {
    count(violation) == 0 with input as {
        "bash": "5.2.21-2ubuntu4"
    }
}

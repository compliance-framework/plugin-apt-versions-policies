package compliance_framework.apt_versions.apt_versions

violation [{
    "title": "wget version",
    "remarks": "Upgrade wget",
    "remarks": sprintf("Upgrade wget to 1.22.0, it is currently version: |%s|, input: |%v| compare: ", [input.wget, input, semver.compare(input.wget, "1.24.0")])
}] if {
    semver.compare("1.24.0", input.wget) == -1
}

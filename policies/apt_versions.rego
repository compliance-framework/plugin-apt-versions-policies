package compliance_framework.apt_versions.apt_versions

violation[{
    "title": "wget version",
    "description": "Version of wget on this server is too low, it should be >= 1.20.3",
    "remarks": sprintf("Upgrade wget to 1.20.3 or higher, it is currently version: |%s|", [input.wget])
}] if {
    semver.compare(input.wget, "1.20.3") == -1
}

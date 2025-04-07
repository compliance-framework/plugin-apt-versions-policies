package compliance_framework.apt_versions.apt_versions

violation[{
    "remarks": sprintf("WGET version is currently |%s|", [input.wget])
}] if {
    semver.compare(input.wget, "1.20.3") == -1
}

title := "Wget version is safe"
description := sprintf("Wget versions should be 1.20.3 or higher to avoid vulnerabilities. Current version |%s|", [input.wget])

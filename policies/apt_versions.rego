package compliance_framework.apt_versions.apt_versions

## Extract major, minor, patch as integers from a version string
parse_version(version) = { "major": major, "minor": minor, "patch": patch } if {
    parts := split(version, ".")
    major := to_number(parts[0])
    minor := to_number(parts[1])
    patch := to_number(parts[2])
}

## Check if version is greater than or equal to target
is_version_lt(version, target) if {
    parsed_version := parse_version(version)
    parsed_target := parse_version(target)
    # Compare major versions
    parsed_version.major < parsed_target.major
}
is_version_lt(version, target) if {
    parsed_version := parse_version(version)
    parsed_target := parse_version(target)
    # Compare minor versions if major versions are equal
    parsed_version.major == parsed_target.major
    parsed_version.minor < parsed_target.minor
}
is_version_lt(version, target) if {
    parsed_version := parse_version(version)
    parsed_target := parse_version(target)
    # Compare patch versions if major and minor versions are equal
    parsed_version.major == parsed_target.major
    parsed_version.minor == parsed_target.minor
    parsed_version.patch < parsed_target.patch
}

violation [{
    "title": "Apt versions.",
    "description": "Versions of software must be compliant",
    "remarks": "Upgrade wget"
}] if {
    some i
    input[i].Package == "wget"
    is_version_lt(input[i].Version, "1.21.0")
}

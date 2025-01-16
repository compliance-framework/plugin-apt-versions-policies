package compliance_framework.apt_versions.apt_versions

violation[{
    "title": "Apt versions.",
    "description": "Versions of software must be compliant",
    "remarks": "Upgrade bash"
}] if {
	input.bash != "5.2.21-2ubuntu4"
}

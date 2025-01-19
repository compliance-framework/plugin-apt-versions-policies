package compliance_framework.apt_versions.apt_versions

violation [{
    "title": "wget version",
    "remarks": "Upgrade wget",
    "remarks": sprintf("Upgrade wget to 1.21.0, it is currently %v", [input])
}] if {
    "1" == "2"
}

#import future.keywords.in
## Helper function to find the package by name
#get_package(name, packages) = result if {
#    result := packages[_]
#    result.Package == name
#}
#
#violation [{
#    "title": "wget version",
#    "remarks": "Upgrade wget",
#    "remarks": "Upgrade wget to 1.21.0, it is currently"
#}] if {
#    this_package := get_package("wget", input)
#    semver.compare(this_package.Version, "1.21.0") == -1
#}
#
#violation [{
#    "title": "xargs version",
#    "remarks": "Upgrade xargs",
#    "remarks": "Upgrade xargs to 2.22.1, it is currently"
#}] if {
#    this_package := get_package("xargs", input)
#    semver.compare(this_package.Version, "2.22.1") == -1
#}

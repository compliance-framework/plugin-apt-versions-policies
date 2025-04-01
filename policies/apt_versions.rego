package compliance_framework.apt_versions.apt_versions

# METADATA
# title: Ensure wget version is up-to-date
# description: Verifies that the version of `wget` installed on the server is at least 1.20.3 to mitigate potential security risks from outdated versions.
# custom:
#   controls:
#     - SAMA_CSF_1.0
#     - SAMA_ITGF_1.0
#     - SAMA_RMG_1.0
#     - SAMA_CCF_1.0
#   schedule: "* * * * * *"

controls := [
    # SAMA Cyber Security Framework v1.0
    {
        "class": "SAMA_CSF_1.0",
        "control-id": "3.2.4", # Vulnerability and Patch Management
        "statement-ids": [
            "2", # Ensure timely updates and patches for critical software like wget.
        ],
        "control-link": "https://csf.tools/reference/critical-security-controls/version-3/csc-3/csc-3-4/"
    },
    # SAMA IT Governance Framework v1.0
    {
        "class": "SAMA_ITGF_1.0",
        "control-id": "4.1.1", # Software and Patch Management
        "statement-ids": [
            "1", # Ensure patching of software to address known vulnerabilities.
        ],
        "control-link": "https://www.sama.gov.sa/en-US/RulesInstructions/CyberSecurity/SAMA-IT_Governance_Framework.pdf"
    },
    # SAMA Risk Management Guidelines v1.0
    {
        "class": "SAMA_RMG_1.0",
        "control-id": "3.4.5", # Vulnerability Management
        "statement-ids": [
            "1", # Ensure that vulnerabilities from outdated software are addressed by timely upgrades.
        ],
        "control-link": "https://csf.tools/reference/nist-cybersecurity-framework/v1-1/id/id-3/"
    },
    # SAMA Cloud Computing Framework v1.0
    {
        "class": "SAMA_CCF_1.0",
        "control-id": "3.4.3", # Cloud Software Maintenance
        "statement-ids": [
            "2", # Ensure that software running in cloud environments is updated regularly.
        ],
        "control-link": "https://rulebook.sama.gov.sa/en/cloud-computing-framework#security"
    },
]

violation[{
    "title": "wget version",
    "description": "Version of wget on this server is too low, it should be >= 1.20.3",
    "remarks": sprintf("Upgrade wget to 1.20.3 or higher, it is currently version: |%s|", [input.wget])
}] if {
    semver.compare(input.wget, "1.20.3") == -1
}

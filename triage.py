def get_severity_label(level):
    try:
        level = int(level)
    except ValueError:
        level = 0

    if level >= 15:
        return "Critical"
    if level >= 12:
        return "High"
    if level >= 7:
        return "Medium"
    return "Low"


def analyze_alert(alert):
    description = str(alert.get("description", ""))
    groups = str(alert.get("groups", ""))
    full_log = str(alert.get("full_log", ""))
    level = alert.get("level", 0)

    text = f"{description} {groups} {full_log}".lower()
    severity = get_severity_label(level)

    result = {
        "severity": severity,
        "attack_type": "General security event",
        "summary": "This alert indicates security-related activity that should be reviewed by a SOC analyst.",
        "mitre_tactic": "Not clearly mapped",
        "mitre_technique": "Needs analyst review",
        "severity_reason": f"Wazuh assigned this alert rule level {level}, which is treated as {severity}.",
        "investigation_steps": [
            "Review the full log message.",
            "Check the affected agent or host.",
            "Check whether similar alerts happened recently.",
            "Confirm whether the activity was expected or suspicious."
        ],
        "response_actions": [
            "Document the finding.",
            "Escalate if the activity is suspicious.",
            "Continue monitoring for repeated events."
        ],
        "false_positive_note": "This may be benign if it was caused by normal administrator or lab activity."
    }

    if "failed password" in text or "sshd" in text or "ssh" in text:
        result.update({
            "attack_type": "Possible SSH login attack",
            "summary": "This alert may indicate failed SSH login activity against a monitored Linux endpoint.",
            "mitre_tactic": "Credential Access",
            "mitre_technique": "Brute Force / Password Guessing",
            "severity_reason": "Failed SSH authentication can indicate password guessing or unauthorized remote access attempts.",
            "investigation_steps": [
                "Identify the source IP address that attempted the SSH login.",
                "Check how many failed attempts happened in a short time.",
                "Check whether there was a successful login after the failures.",
                "Review the targeted username.",
                "Confirm whether the source IP belongs to a trusted machine."
            ],
            "response_actions": [
                "Block the source IP if it is unknown or malicious.",
                "Disable password-based SSH login if possible.",
                "Use SSH keys and strong authentication.",
                "Review the affected user account.",
                "Rotate credentials if compromise is suspected."
            ],
            "false_positive_note": "This can be a false positive if you intentionally tested SSH login with a wrong password in the lab."
        })

    elif "sudo" in text or "authentication failure" in text or "pam" in text:
        result.update({
            "attack_type": "Possible privilege escalation or failed sudo authentication",
            "summary": "This alert shows sudo or PAM authentication activity on a Linux endpoint.",
            "mitre_tactic": "Privilege Escalation",
            "mitre_technique": "Valid Accounts / Sudo and Sudo Caching",
            "severity_reason": "Repeated failed sudo attempts may indicate someone is trying to gain higher privileges.",
            "investigation_steps": [
                "Check which user attempted to run sudo.",
                "Check what command the user tried to execute.",
                "Look for repeated failed sudo attempts.",
                "Confirm whether the activity was performed by the real user.",
                "Check for successful privilege escalation after failures."
            ],
            "response_actions": [
                "Review sudo permissions for the user.",
                "Remove unnecessary sudo access.",
                "Reset the user password if suspicious.",
                "Check command history for unusual activity.",
                "Escalate if the activity was not expected."
            ],
            "false_positive_note": "This may be normal if you typed the wrong sudo password during testing."
        })

    elif "syscheck" in text or "file added" in text or "file deleted" in text or "integrity checksum" in text:
        result.update({
            "attack_type": "File Integrity Monitoring event",
            "summary": "This alert shows that a monitored file or directory was created, modified, or deleted.",
            "mitre_tactic": "Defense Evasion or Persistence, depending on the file path",
            "mitre_technique": "File modification activity",
            "severity_reason": "Unexpected file changes can indicate malware activity, persistence changes, or unauthorized modification.",
            "investigation_steps": [
                "Check the file path that changed.",
                "Identify whether the file was added, modified, or deleted.",
                "Check which user or process made the change if available.",
                "Decide whether the file path is sensitive.",
                "Compare the change with expected admin activity."
            ],
            "response_actions": [
                "Restore the file if the change was unauthorized.",
                "Check the endpoint for suspicious processes.",
                "Review recent login activity on the same machine.",
                "Add sensitive directories to monitoring if not already covered.",
                "Escalate if the file change affects system security."
            ],
            "false_positive_note": "This can be benign if you created, edited, or deleted the file during the lab test."
        })

    elif "rootcheck" in text:
        result.update({
            "attack_type": "Host-based anomaly or configuration finding",
            "summary": "This alert is related to a host-based check, often used to identify suspicious files, weak configuration, or rootkit-like indicators.",
            "mitre_tactic": "Defense Evasion",
            "mitre_technique": "System checks required",
            "severity_reason": "Rootcheck alerts can indicate suspicious system state or configuration weaknesses.",
            "investigation_steps": [
                "Review the exact rootcheck message.",
                "Check whether the finding points to a suspicious file or configuration.",
                "Verify if the alert is known and expected in this lab environment.",
                "Search for repeated rootcheck alerts on the same agent."
            ],
            "response_actions": [
                "Harden the affected configuration if needed.",
                "Remove suspicious files only after confirmation.",
                "Run additional checks on the endpoint.",
                "Document whether this is a real issue or expected lab noise."
            ],
            "false_positive_note": "Some rootcheck alerts may be noisy in lab machines and should be validated before escalation."
        })

    elif "suricata" in text or "ids" in text:
        result.update({
            "attack_type": "Network IDS alert",
            "summary": "This alert appears to be related to network intrusion detection activity.",
            "mitre_tactic": "Command and Control or Discovery, depending on the alert",
            "mitre_technique": "Network-based suspicious activity",
            "severity_reason": "Network IDS alerts may indicate scanning, exploitation attempts, or suspicious traffic.",
            "investigation_steps": [
                "Identify the source and destination IP addresses.",
                "Check the destination port and protocol.",
                "Review the IDS signature name.",
                "Check whether the traffic was expected.",
                "Correlate with endpoint alerts from the same time."
            ],
            "response_actions": [
                "Block malicious traffic if confirmed.",
                "Investigate the source host.",
                "Check firewall and network logs.",
                "Tune noisy IDS rules if false positives occur."
            ],
            "false_positive_note": "IDS alerts can be false positives if triggered by lab scans or expected testing tools."
        })

    return result
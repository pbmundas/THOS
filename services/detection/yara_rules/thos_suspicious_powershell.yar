rule THOS_Suspicious_PowerShell_Artifacts
{
    meta:
        title = "Suspicious PowerShell Artifact Strings"
        description = "Triage lead for encoded or download-oriented PowerShell content"
        author = "THOS"
        severity = "high"
        status = "stable"
        attack = "T1059.001"
    strings:
        $ps = "powershell" nocase ascii wide
        $enc = "-encodedcommand" nocase ascii wide
        $download = "DownloadString" nocase ascii wide
    condition:
        $ps and 1 of ($enc, $download)
}

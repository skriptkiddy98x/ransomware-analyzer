/*
   ransomware_generic.yar — heuristic rules for the analyzer.
   These are intentionally generic indicators for research/triage, NOT a
   replacement for vetted threat-intel rule sets. Add your own rules here.
*/

rule Ransom_Note_Language
{
    meta:
        description = "Text commonly found in ransom notes"
        author = "ransomware-analyzer"
        mitre = "T1486"
    strings:
        $a = "your files have been encrypted" nocase
        $b = "all your files" nocase
        $c = "how to decrypt" nocase
        $d = "decryption key" nocase
        $e = "bitcoin" nocase
        $f = ".onion" nocase
        $g = "pay the ransom" nocase
    condition:
        2 of them
}

rule Shadow_Copy_Deletion
{
    meta:
        description = "Commands that delete backups / inhibit recovery"
        author = "ransomware-analyzer"
        mitre = "T1490"
    strings:
        $v1 = "vssadmin" nocase
        $v2 = "delete shadows" nocase
        $v3 = "wbadmin" nocase
        $v4 = "delete catalog" nocase
        $v5 = "recoveryenabled no" nocase
        $v6 = "shadowcopy delete" nocase
    condition:
        ($v1 and $v2) or $v5 or $v6 or ($v3 and $v4)
}

rule Crypto_API_Usage
{
    meta:
        description = "Windows cryptographic API usage (possible file encryption)"
        author = "ransomware-analyzer"
        mitre = "T1486"
    strings:
        $c1 = "CryptEncrypt"
        $c2 = "CryptGenKey"
        $c3 = "CryptAcquireContext"
        $c4 = "BCryptEncrypt"
        $c5 = "CryptImportKey"
    condition:
        uint16(0) == 0x5A4D and 2 of them
}

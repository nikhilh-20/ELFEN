rule Generic_BruteForceCredentials
{
    meta:
        score = 30
        author = "Nikhil Hegde <ka1do9>"
        description = "Detects presence of well-known password patterns"
        tags  = "generic"
        mitre_attack = "T1110.001: Brute Force: Password Guessing"

    strings:
        $ = /admin(istrator)?[!@_\.]?\d{3,}/i
        $ = /pass(w[0o]rd)?[!@_\.]?\d{3,}/i

    condition:
        all of them
}

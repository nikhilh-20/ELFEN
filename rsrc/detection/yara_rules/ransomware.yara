rule Linux_x86_Ransomware_AvosLocker
{
    meta:
        score = 100
        author = "Nikhil Hegde <ka1do9>"
        description = "(ELFEN Test) Detects AvosLocker Ransomware"
        family = "AvosLocker"
        tags  = "ransomware"

    strings:
        $ = ".avoslinux" nocase
        $ = ".avos2" nocase

    condition:
        any of them
}
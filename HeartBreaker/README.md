# HeartBreaker Sherlock - DFIR Write-up

**Hack The Box Initial information:**

Delicate situation alert! The customer has just been alerted about concerning reports
indicating a potential breach of their database, with information allegedly being circulated on
the darknet market. As the Incident Responder, it's your responsibility to get to the bottom of
it. Your task is to conduct an investigation into an email received by one of their employees,
comprehending the implications, and uncovering any possible connections to the data
breach. Focus on examining the artifacts provided by the customer to identify significant
events that have occurred on the victim's workstation.



**Initial Email Review**

Based on the initial Information, I began by reviewing the user's email artifacts. I navigated to: `C:\Users\ash.williams\AppData\Local\Microsoft\Outlook`

![](./screenshots/Task1-OST-File.PNG)

Within this directory, I identified an Outlook data file: `ashwilliams012100@gmail.com.ost`

To review the contents, I loaded the OST file into an OST/PST viewer (I would recommend finding a better OST/PST tool). The user's inbox contained five emails, once of which immediately stood out as suspicious.

![](./screenshots/Task1-Email.PNG)

Suspicious Email Details:
- Sender: `ImSecretlyYours@proton.me`
- Received: `2024-03-13 03:37 AM`
- Attachment: `4YourEyesOnly.tiff`
- Embedded URL: `http://44.206.187.144:9000/Superstar_MemberCard.tiff.exe`

The email body used romantic language to entice the user into downloading a so-called "digital membership card" for access to a private club, where the threat actor and the victim can meet. Aligning with common social engineering techniques designed to lower user suspicion and encourage execution of an attachment.



**Malicious File Execution**

Further analysis showed that the file `Superstar_MembershipCard.tiff.exe` was downloaded and executed from the user's Downloads directory.

![](./screenshots/prefetch-execution.PNG)

Execution:
- File Path: `C:\Users\ash.williams\Downloads\Superstar_MemberCard.tiff.exe`
- Execution Time: `2024-03-13 10:45:02`

I identified a Prefetch artifact associated with the malicious executable. Parsing the Prefetch file confirmed execution of `Superstar_MembershipCard.tiff.exe` and provided additional confidence around the timing of the event.

To gain further context around this activity, I correlated Prefetch data with `$MFT`, `$J`, and `Microsoft-Windows-Sysmon/Operational.evtx` logs to examine file creation and modification activity, as well as any child processes spawned by the executable.

This activity aligns with MITRE ATT&CK T1204 - User Execution, as the malware required user interaction to run.



**Post-Execution User Activity**

After execution of the file, the user conducted web searches related to the theme of the phishing email. Reviewing Firefox artifacts using DB Browser for SQLite, I examined the `moz_formhistory` table and identified five total search entries.

![](./screenshots/Task6-Searchbar-history.PNG)

Two searches were particularly notable to this incident:
- "what to wear to impress date"
- "Superstar café membership"

These searches support the conclusion that the social engineering attempt was successful in convincing the user the email was legitimate.



**Malicious Outbound Email Activity**

Shortly after execution, the system sent an identical email to the user's entire contact list.

![](./screenshots/Task7-ClientSubmitTime.PNG)
![](./screenshots/Task8-Contacts.PNG)

Email Metadata Findings:
- `ClientSubmitTime`: `2024-03-13 10:47:51`
- Recipients: 58 contacts (excluding the victim's own address)

This provides supporting evidence that the malware was capable of accessing the user's email data and automating outbound messages, increasing the scope of potential compromise.

**Credential Exposure Observations**

While reviewing the OST file, I identified a draft email created by the user that contained AWS credentials. Although the email was never sent, it remained stored locally within the mailbox data.

This represents a significant security risk, as any process capable of accessing the OST file could potentially extract sensitive credentials. While direct evidence of exfiltration of these credentials was not observed in the available artifacts, their presence within the scope of the incident increases the impact of the compromise.



**Host-Level Behavioral Analysis**

To gain a better understanding of the post-execution behavior, I filtered Sysmon logs to focus on activity where `Superstar_Membership.tiff.exe` appeared as the source image. This revealed several interactions with legitimate Windows binaries.

![](./screenshots/Task9-TimelineFilter.PNG)

![](./screenshots/Task9-LegitProgram.PNG)

One notable example was `nltest.exe`, a legitimate tool commonly used for domain controller enumeration. Its execution suggests the malware attempted to gather information about the environment.



**Network Activity & Tool Staging**

During Sysmon analysis, I observed `Superstar_Membership.tiff.exe` making a DNS query to `us.softradar.com`. Shortly after this query, a new directory appeared: `C:\Users\Public\HelpDesk-Tools\`

![](./screenshots/Task10-11Data.PNG)

This directory contained:
- `license.txt`
- `readme.txt`
- `WinSCP.exe` (a free, open source file manager and secure file transfer client for Windows)
- `WinSCP.com`
- `maintenanceScript.txt`

The structure and naming of this directory resemble a legitimate administrative toolkit, consistent with MITRE ATT&CK T1036 - Masquerading. Based on timestamps and network activity, it is likely these tools were staged after the DNS request.



**Data Staging & Compression Indicators**

While reviewing Sysmon logs, I noticed that `Superstar_MemberCard.tiff.exe` accessed numerous sensitive files located under public directories. Later correlation showed at least 26 files being accessed prior to the appearance of compressed archives:
- `WB-WS-01.zip`
- `WinSCP.zip`
![](./screenshots/Task13-Data.PNG)

The timing and suspicious file activity strongly suggest these files were staged and compressed prior to exfiltration.

**Data Exfiltration Evidence**

Further Sysmon Event ID 1 (Process Creation) analysis revealed execution of WinSCP using the following command:
- C:\Users\Public\HelpDesk-Tools\WinSCP.com /script=C:\Users\Public\HelpDesk-Tools\maintenanceScript.txt

![](./screenshots/Task14-Data.PNG)

Moments after this execution, Sysmon Event ID 3 (Network Connection) logged an outbound connection:
- Destination IP: `35.169.66.138`
- Timestamp: `2024-03-13 10:45:29`
- Executable: `WinSCP.exe`

The Use of a `.txt` script file to store WinSCP commands suggests an attempt to blend malicious activity into seemingly administrative files.



**Final Assessment**

Based on the available artifacts, the investigation supports the following conclusions:
- The user was successfully socially engineered into executing a malicious binary
- The malware propagated via outbound email using the victim's account.
- Additional tools were staged to facilitate data collection and transfer.
- Sensitive files were likely compressed and exfiltrated using WinSCP

While not every stage of exfiltration is directly observable, the consistency across host, email, and network artifacts strongly supports a full compromise of the workstation.



**Next Steps**

If this were a live incident, my next steps would include:
- Credential rotation (email and cloud accounts)
- Scoping other recipients of the malicious email
- Network-wide search for related indicators
- Reviewing proxy and firewall logs for additional exfiltration attempts
- Host reimaging and post-incident hardening





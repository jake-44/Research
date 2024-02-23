# Research

## Table of Contents

- **Weekly Dives**
  - Table of Contents
  - Description
    - **2022**
      - [iOS 16 Security](#ios)
      - [RomCom RAT](#rat)
      - [Rackspace](#rack)
      - [LastPass Breach](#last)
    - **2023**
      - [SentinelSneak Trojan](#sentinel)
      - [ChatGPT in Cyber](#chat)
      - [Lunch n' Learn](#lunch)
      - [OneNote Exploit](#one)
      - [Patch Tuesday](#patch)
      - [Wazuh](#wazuh)
      - [CVE-2023-23397 "Zero-Touch" Calendar Invite](#zero)
      - [Raspberry Robin malware](#rasp)
      - [3CX VOIP Compromise](#3cx)
      - [CVE-2023-28205 & CVE-2023-28206 Apple IOSurfaceAccelerator and WebKit Vulnerabilities](#apple)
      - [Hidden Layer Artificial Intelligence](#ai)
      - [Microsoft AtRisk](#atrisk)
      - [Microsoft Outage](#outage)
      - [CLoP Cybercrime](#clop)
      - [Big Head Ransomware](#big)
      - [chmod](#chmod)
      - [CVE-2023-36895 Microsoft ActiveX](#activex)
      - [2020 Microsoft Data Leak](#data)
      - [Quishing](#qr)
      - [NSA and CISA Joint Cybersecurity Advisory](#advise)
      - [Search Engine Optimization (SEO) Poisoning](#seo)
      - [Msbuild.exe -> XML](#xml)
    - **2024**
      - [NetScaler CVEs](#netscaler)
      - [Ivanti CVEs](#ivanti)
      - [AnyDesk Breach](#any)
      - [LockBit Disruption](#lock)
      - [ScreenConnect Vulnerability](#scvuln)


## Description
This content includes some notes I've taken on some of the topics I've researched in the past. I try to highlight the important details and what my key takeaways are.

## 2022-09-13 - iOS 16 Security <a name="ios"></a>
Pretty interesting stuff regarding Apple’s new update. It implemented the use of “Lockdown Mode” which provides additional messaging, web browsing, and connectivity protection that blocks commercial spyware (like NSO Group's Pegasus) used by government-backed attackers to monitor compromised Apple devices. Apple said, "turning on Lockdown Mode in iOS 16, iPadOS 16, and macOS Ventura further hardens device defenses and strictly limits certain functionalities, sharply reducing the attack surface that potentially could be exploited by highly targeted mercenary spyware.” 

My thought is that they needed something to combat this zero day software which had previously stole information from the phone of Amazon’s ex CEO, Jeff Bezos. This should put the public at ease. 

Resource:
- https://www.bleepingcomputer.com/news/apple/apple-released-ios-16-with-lockdown-safety-check-security-features/


## 2022-11-01 - RomCom RAT <a name="rat"></a>
There’s a lot of cool topics online for new potential cyber-threats but one article in particular rang some bells at first sight which was the new “RomCom RAT”. This remote access trojan is downloaded by a victim through accessing different look-a-like domains that appear to be related to legitimate software such as Solarwinds, KeePass, and Veeam. Of course, this is not the case. The websites hint at free trials of the software for download that, when clicked, load the binaries needed for the trojan to operate in the file path below:

C:\Users\user\AppData\Local\Temp\winver.dll

**These download packages that include the trojan have the tendency to be signed by the legitimate publisher for means of evading detection.

Resource:
- https://www.bleepingcomputer.com/news/security/romcom-rat-malware-campaign-impersonates-keepass-solarwinds-npm-veeam/

## 2022-12-06 - Rackspace <a name="rack"></a>
Rackspace, a cloud computing service provider, had recently experienced an outage which was affecting its Microsoft Exchange environments. Though unconfirmed, experts have reason to believe that Rackspace was running a Microsoft Exchange server version that is vulnerable to the “ProxyNotShell” vulnerability. This was a zero-day exploit discovered in the wild just two months ago which installs web shells on Microsoft Exchange servers. Although Microsoft had patched this vulnerability in November, Rackspace did not keep up to date with their patches and was running the server patch version from August. Four days later, Rackspace confirmed that the affected exchange server is the result of ransomware and as of right now, is too early to tell what data might have been accessed and how much revenue will be lost. Not to mention the lingering loss of business following the event, all due to patch management (and lazy analysts?).

Resource: 
- https://www.bleepingcomputer.com/news/security/rackspace-confirms-outage-was-caused-by-ransomware-attack/


## 2022-12-27 - LastPass Breach <a name="last"></a>
Continuing on to this week’s attention check involving a breach in the password management firm, Last Pass, they’ve had a rough few months since their development environment was compromised in August 2022. This activity stemmed from a threat actor gaining access to a developer’s account and successfully bypassing multi-factor authentication, to which they had access for roughly four days. Initially, the response from LastPass’ CEO was that “…our system design and controls prevented the threat actor from accessing any customer data or encrypted password vaults", however, according to the CEO’s most recent announcement (Dec 22), there’s a lot to unpack but essentially the threat actor copied user’s PII, host IP addresses, contact information, encrypted backups containing passwords and usernames for specified domains.

Resource:
- https://www.bleepingcomputer.com/news/security/lastpass-developer-systems-hacked-to-steal-source-code/ (August)
- https://www.bleepingcomputer.com/news/security/lastpass-says-hackers-had-internal-access-for-four-days/ (September)
- https://www.bleepingcomputer.com/news/security/lastpass-hackers-stole-customer-vault-data-in-cloud-storage-breach/ (December)


## 2023-01-03 - SentinelSneak Trojan <a name="sentinel"></a>
This week’s attention check dives into a newly discovered trojan campaign named “SentinelSneak”, which involves a malicious Python package disguised as a SentinelOne agent installer. The backdoor is designed to exfiltrate data specific to development environments, such as shell command execution history and the contents of the SSH folder, which stores SSH keys and configuration information, including login credentials for Git, Kubernetes, and AWS services. The malicious package has been manipulated at least 20 times since its discovery which indicates the attackers are fine tuning it to evade detection and hone the code to fit the target scope.

Resources:
- https://www.darkreading.com/vulnerabilities-threats/malicious-python-trojan-impersonates-sentinelone-security-client
- https://www.securityweek.com/malicious-pypi-module-poses-sentinelone-sdk
- https://www.reversinglabs.com/blog/sentinelsneak-malicious-pypi-module-poses-as-security-sdk


## 2023-01-10 - ChatGPT in Cyber <a name="chat"></a>
For the attention check this week, we were to look into the open-source, artificial intelligence project named ChatGPT and determine its relevance within the cyber world. Outside of article headlines from the mainstream media and popular talk claiming that humans are “not ready” for this be-all and end-all AI program, it actually has some interesting use cases relative to cybersecurity. 

The list can be extensive because there is a lot to be said on this topic, but the capabilities of the AI seem to balance out between both blue teaming and red teaming scenarios. Some of these capabilities, as of now, involve engineering and reverse engineering malware, designing flawless phishing emails, scraping the internet for intelligence, developing scripts, scans, vulnerability detection within networks and coding segments that includes descriptive proof of concept… The possibilities and examples are endless, to an extent, if you apply the correct training techniques to the AI for your desired scenario. Regardless of its reputation, ChatGPT is currently another valuable tool within cybersecurity.

Resources:
- https://www.bleepingcomputer.com/news/technology/openais-new-chatgpt-bot-10-dangerous-things-its-capable-of/
- https://www.darkreading.com/attacks-breaches/attackers-are-already-exploiting-chatgpt-to-write-malicious-code


## 2023-01-24 - Lunch n' Learn <a name="lunch"></a>
Lunch n’ learn
Fun fact: Approximately 88% of the information required to initiate a campaign against a user and their organization. This props up sophisticated social engineering attacks including every type of targeted phishing and well-educated brute force guesses.


## 2023-02-07 - OneNote Exploit <a name="one"></a>
Our attention check this week included detailing the OneNote exploit that has recently affected multiple of our clients on multiple occasions. What I wanted to dig through was the reason behind what makes this exploit much different than the average phishing campaign. Why are so many users falling victim? The exploit is essentially a template for threat actors to modify to accomplish their goal which is the reason why an abundance of different groups are using this attack vector. Besides the sheer volume of malicious phish being sent, the phish itself appears relatively believable and can be constructed for specific users such as targeted invoices or other appropriate interdepartmental communication.
This attack vector is becoming popular in use by Qakbot, RATs, and worms for the simplicity of infecting a machine.

Resource:
- https://opalsec.substack.com/p/the-defenders-guide-to-onenote-maldocs?sd=pf


## 2023-02-14 - Patch Tuesday <a name="patch"></a>
In summary, there were nine critical vulnerabilities that were tended to. These include RCE through Visual Studio, Windows iSCSI, and PEAP protocol exploitation, according to Microsoft. I found the most important and relevant to our every day job was CVE-2023-21716 which defines a notable Microsoft 365 exploit stemming from a rich text format (RTF) formatted file payload that when opened (even in the preview pane), grants RCE. Threat actors can construct and format their phishing campaign payloads to take advantage of this exploit if the client does not have a file block policy in place.

Resources:
- https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-21716
- https://www.tenable.com/blog/microsofts-february-2023-patch-tuesday-addresses-75-cves-cve-2023-23376#:~:text=CVE%2D2023%2D21716%20is%20a,applications%20is%20an%20attack%20vector.


## 2023-03-07 - Wazuh <a name="wazuh"></a>
Understanding Wazuh. Wazuh provides unified SIEM and XDR protection through cloud monitoring, endpoint agents, and agentless monitoring for devices such as routers, firewalls, and switches that do not support the installation of agents. Unlike our NIDS AlienVault, Wazuh can perform responsive actions like removing malicious files, blocking malicious network connections, and other active countermeasures.

Resources:
- https://wazuh.com/
- https://www.bleepingcomputer.com/news/security/wazuh-the-free-and-open-source-xdr-platform/
- https://www.g2.com/products/wazuh-the-open-source-security-platform/reviews


## 2023-03-21 - CVE-2023-23397 "Zero-Touch" Calendar Invite <a name="zero"></a>
Researching the zero-day vulnerability CVE-2023-23397 which was included in this month’s patch Tuesday. This CVE is an elevation of privilege vulnerability in Microsoft Outlook and requires no user interaction as a “zero-touch” exploit via email. This means that the vulnerability is exploited whether the recipient has seen the message or not. The kill chain is as follows:

1.	The attacker remotely sends a malicious calendar invite represented by .msg — the message format that supports reminders in Outlook.
2.	The message triggers the vulnerable API endpoint PlayReminderSound using “PidLidReminderFileParameter” (the custom alert sound option for reminders).
3.	The victim connects to the attacker’s SMB server.
4.	The connection to the remote server sends the user’s New Technology LAN Manager (NTLM) negotiation message automatically, which the attacker can use for authentication against other systems that support NTLM authentication (relay).

Once attackers are in the system, they can use the network for lateral movement and navigate the organization’s lines over SMB. 

There are no significant indicators of compromise besides unusual NTLM authentication and port 445 (SMB) traffic involving external IP addresses as well as post exploitation activity involving mailbox modifications and usage for further activity.

Resources:
- https://www.trendmicro.com/en_us/research/23/c/patch-cve-2023-23397-immediately-what-you-need-to-know-and-do.html
- https://www.microsoft.com/en-us/security/blog/2023/03/24/guidance-for-investigating-attacks-using-cve-2023-23397/


## 2023-03-28 - Raspberry Robin <a name="rasp"></a>
Reading through the Raspberry Robin section within the Red Canary Threat Detection Report for 2023 and identify the code name used for the DLL file associated with the malware. The DLL known as “Roshtyak” is downloaded from the internet using msiexec, following successful execution, and is normally found randomly named in a randomly named directory in the following file path: 

C:\ProgramData\<randomly-named subdirectory> 

The malware employs multiple layers of obfuscation within the code as well as a built-in payload crafted to mislead analysts into believing this decoy is “just” an obfuscated piece of adware (and a very old one at that), which could cause the analyst to lose interest in digging deeper.

Nasty activity occurs following this DLL execution including process privilege elevation, penetration testing (exception checks), permission enumeration, shellcode execution, covering tracks, and MUCH MORE possible “pre-ransomware behavior”.

Resources:
- https://decoded.avast.io/janvojtesek/raspberry-robins-roshtyak-a-little-lesson-in-trickery/
- https://redcanary.com/threat-detection-report/threats/raspberry-robin/


## 2023-04-04 - 3CX VOIP Compromise <a name="3cx"></a>
Diving into the recent 3CX VOIP desktop client compromise which is believed to be carried out by a North-Korean state-backed group called “Labyrinth Chollima”. As said best in the security advisory recently sent out to our clients, the highly sophisticated attack being dubbed the “SmoothOperator”, “…starts when an installer file is downloaded from 3CX’s website or when an update is pushed to an already installed desktop application. When the application is updated or installed, malicious DLLs (or libraries) are sideloaded and used to execute malicious code on the affected system.” The binaries used in this attack are legitimate BUT manipulated files associated with 3CX installations:

ffmpeg.dll - https://www.virustotal.com/gui/file/7986bbaee8940da11ce089383521ab420c443ab7b15ed42aed91fd31ce833896 (52/70)
d3dcompiler_47.dll - https://www.virustotal.com/gui/file/11be1803e2e307b647a8a7e02d128335c448ff741bf06bf52b332e0bbf423b03 (39/70)

From research, both binaries work in conjunction with each other to achieve the following kill chain:
1.	Attacker modifies source code, compiles, builds, and signs new installer, then publishes to web server.
2.	Trojanized MSI or update is installed (3CXDesktopAPP-18.12.407.msi) with both manipulated dlls listed above.
3.	Ffmpeg.dll is used to extract and decrypt encrypted shell code appended to d3dcompiler_47.dll. 
4.	This shell code reaches out to a GitHub repository to download files that contain encoded commands. (These files named “icon0.ico” through “icon15.ico” – repository recently archived).
5.	This base64 encoding will then download the final malicious binary onto the infected system and inject it straight into memory. This binary acts as an info stealer, harvesting system data and stored browser creds. 

*This is spooky since 3CX is used by over 600,000 companies worldwide and has over 12 million daily users including high-profile companies that drive The United States’ economy and carry millions of people’s PII*

Resources:
- https://www.3cx.com/blog/news/security-incident-updates/
- https://www.bleepingcomputer.com/news/security/hackers-compromise-3cx-desktop-app-in-a-supply-chain-attack/
- https://news.sophos.com/en-us/2023/03/29/3cx-dll-sideloading-attack/ 


## 2023-04-11 - CVE-2023-28205 & CVE-2023-28206 Apple IOSurfaceAccelerator and WebKit Vulnerabilities <a name="apple"></a>
Research the two Apple product zero-day vulnerabilities involving the IOSurfaceAccelerator and WebKit, both of which were patched this past Friday (2023-04-07). The IOSurfaceAccelerator vulnerability or CVE-2023-28206, takes advantage of an Out-of-Bounds Write weakness within the IOSurfaceAccelerator that allows a malicious application to execute arbitrary code with kernel privileges (protection ring level 0, full machine privilege). This weakness typically occurs when the pointer or its index is incremented or decremented to a position beyond the bounds of the buffer or when pointer arithmetic results in a position outside of the valid memory location. This was addressed with improved input validation.

The WebKit vulnerability, CVE-2023-28205, takes advantage of a Use-After-Free (UAF) weakness within the Apple WebKit which processes malicious web content through applications, Safari, or email. This malicious content includes code that leverages the UAF weakness by referencing memory after it has been freed which can cause a program to crash, use unexpected values, or execute code. This was addressed with improved memory management. 

These vulnerabilities are for old device generations prior to the 8th iPhone, iPads before the 5th, and MacOS Ventura.

Resources:
- https://support.apple.com/en-us/HT213723
- https://www.bleepingcomputer.com/news/apple/apple-fixes-recently-disclosed-zero-days-on-older-iphones-and-ipads/
- https://www.cvedetails.com/cwe-details/787/Out-of-bounds-Write.html
- https://www.cvedetails.com/cwe-details/416/Use-After-Free.html


## 2023-04-25 - Hidden Layer Artificial Intelligence <a name="ai"></a>
It’s no surprise that the development of artificial intelligence took over the RSA Conference this year with the rise of AI model customization. One company, Hidden Layer, took the win with their very popular “MLDR” while VirusTotal announced their new code analyzer called Code Insight. The platform, powered by Google Cloud’s new Security AI Workbench, takes code or scripting input and outputs plaintext describing in detail, what the commands are doing, for what purpose, and whether for good or bad. The platform can be used by security analysts, but also by development and intelligence teams who are looking to debug, harden code, or dynamically and statically analyze processes in a safe environment. 

Resources:
- https://blog.virustotal.com/2023/04/introducing-virustotal-code-insight.html (VirusTotal Announcement)
- https://www.prnewswire.com/news-releases/google-cloud-announces-new-security-ai-workbench-and-ecosystem-expansion-at-rsac-2023-301804984.html (Google Security AI Workbench Announcement)
- https://www.securityweek.com/rsa-conference-2023-announcements-summary-day-1/ (All RSA Conference Announcements)
- YouTube – “HiddenLayer – RSA Conference 2023 Innovation Sandbox”


## 2023-05-02 - Microsoft AtRisk <a name="atrisk"></a>
The new Microsoft AtRisk User detections. 
I won’t get into the technical configurations specific to Azure but essentially, it all boils down to introducing another layer into the zero-trust architecture. Depending on the organization, many different conditional access controls could be at play to authenticate a user’s behavior, including the most common, dual authentication of a username & password, and MFA application. Another popular choice is geo-blocking, but the list goes on to include filtering a user’s device information (IP and MAC), operating protocol, local user group, and to top it off, machine learning can be implemented to block a sign in based on anomalous behavior. This detection adds another layer of depth by having an analyst judge whether this login or attempted login meets the criteria to be authorized.

Lastly, this detection gives analysts a magnitude of information about the specific sign in observed. Most importantly, whether the login has successfully met all the authentication criteria. However, in most cases, only a username and password have been fulfilled, suggesting that the only barrier between the suspected threat actor and access to the network is the specified conditional access. This is still a concern due to the reason that all the threat actor has to do in this situation is either spoof or change their configurations to match the conditional access or brute force the MFA application through MFA fatigue. After successful authentication, this login may even allow the threat actor to bypass detection hence why this detection attempts to cover an area which our impossible travel threshold or other login detection methods may not catch. 


## 2023-06-06 - Microsoft Outage <a name="outage"></a>
Read up about the outage which Microsoft faced yesterday 2023-06-05, that prevented users worldwide from reliably accessing or sending email and using the mobile Outlook app. Microsoft was/is providing updates on Twitter regarding the outage and while they have claimed the issues were internal and technical, a group named Anonymous Sudan, is taking responsibility for the DDoS attacks. The religiously motivated hacktivists from Sudan continue to posture on their Telegram account, claiming that they can repeat this attack at will and are requesting one million USD from Microsoft in exchange “…we teach your cyber-security experts how to repel the attack…”.
These claims are unverified.

Resources:
- bleepingcomputer.com/news/microsoft/outlookcom-hit-by-outages-as-hacktivists-claim-ddos-attacks/
- https://cybernews.com/security/microsoft-outlook-outage-anonymous-sudan/
- https://www.radware.com/cyberpedia/ddos-attacks/anonymous-sudan/


## 2023-06-20 - CLoP Cybercrime <a name="clop"></a>
This week’s attention check was to research the exploit conducted by the cybercrime group “CLoP” (later confirmed to be a group called Lace Tempest (TA505 and FIN11)) in their most recent U.S. Government breach. The exploit targets a specific file transfer software platform called MOVEit and was observed being executed as early as July 2021 but most recently affected hundreds of US companies over memorial day weekend. 

The exploit targets a previously known SQL injection vulnerability in the MOVEit web application that has the identifier (CVE-2023-34362) and CVSS score of 9.8. It utilizes a specially crafted web shell called human2.aspx and legitimate binaries within the software, to establish a successful reverse shell, arbitrary code execution, privilege escalation, and ultimately payload deployment. It takes all of a few minutes to conduct the breach which John Hammond of Huntress actually expedited with a basic Meterpreter session. This is shown in the proof of concept in the reference section below.

Resources:
- https://www.huntress.com/blog/moveit-transfer-critical-vulnerability-rapid-response
- https://www.bleepingcomputer.com/news/security/new-moveit-transfer-zero-day-mass-exploited-in-data-theft-attacks/
- https://nvd.nist.gov/vuln/detail/CVE-2023-34362
- https://www.bleepstatic.com/images/news/ransomware/c/clop/clop-message-dls.jpg (Ransom Note)


## 2023-07-11 - Big Head Ransomware <a name="big"></a>
Research a recent ransomware attack called “Big Head” and determine the how what and why questions about it. It was discovered in the wild, May of 2023 and was determined to be the product of malicious advertising which promotes Windows updates and Microsoft Word installers. The installations are seamless and even have mimicked the Windows update bluescreen and loading UI, as well as the Microsoft Word icon.

In the weeds, a .NET binary installs three encrypted files, a propagation tool, C&C setup, and an encryptor. All with surprisingly suspicious names but drop files with generic and look-a-like names such as discord.exe and Server.exe. Like all ransomware, shadow copies are deleted, recovery disabled, the user’s files are encrypted, but uniquely, their files are renamed with the best file extension name of all time, “.poop”. There are three variants however, they do not vary much besides the later use RSA-2048 rather than AES-256 for better encryption and the ransom payment is greater.

Over-all the goal is money. Although the second and third variants steal browser data, directory listings, passwords, ect. Likely Russia.

Resources:
- https://www.bleepingcomputer.com/news/security/new-big-head-ransomware-displays-fake-windows-update-alert/
- https://www.fortinet.com/blog/threat-research/fortiguard-labs-ransomware-roundup-big-head


## 2023-08-01 - chmod <a name="chmod"></a>
Which chmod command you should avoid using as much as possible. The chmod command "chmod 777" should be avoided as much as possible. This command gives full read, write, and execute permissions to the owner, group, and others on a file or directory. As josh pointed out, this is obviously a security risk because it allows unrestricted access to everyone, making it easier for unauthorized users to modify or execute files. The great and powerful principle of least privilege should be enforced, limiting access to well managed groups and appropriate users.


## 2023-08-19 - CVE-2023-36895 Microsoft ActiveX <a name="activex"></a>
The Outlook vulnerability noted in this month’s patch Tuesday. CVE-2023-36895 identifies a critical Microsoft Outlook RCE vulnerability which originates from a flaw in the way that Outlook parses certain types of “ActiveX” controls. ActiveX is an embedded software framework created by Microsoft that other applications can reuse to enable the same functionality. A specially crafted phishing file containing one of these ActiveX controls containing malicious code are used for exploitation.

Resources:
- https://www.rapid7.com/blog/post/2023/08/08/patch-tuesday-august-2023/
- https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2023-36895
- https://www.crowdstrike.com/blog/patch-tuesday-analysis-august-2023/


## 2023-09-19 - 2020 Microsoft Data Leak <a name="data"></a>
Research and find the source of a Microsoft data leak that occurred back in 2020. In summary, a Microsoft AI research division employee accidentally shared the URL for a misconfigured Azure Blob storage bucket containing sensitive data while contributing open-source AI learning models to a public GitHub repository. The repository's README.md file instructed developers to download the models from an Azure Storage URL that was misconfigured, indirectly granting access to an entire storage account, containing additional private data. 

Accessors were able to access the information with the use of a Shared Access Signature (SAS) token, which was intended to allow only read-only permissions but instead was configured to allow "full control" over the shared files. SAS tokens are an Azure feature for sharing data and offering a secure means of granting delegated access to resources within a storage account. It has been noted that Microsoft does not provide a centralized way to manage (or log) them within the Azure portal and their usage should be avoided due to this lack of governance.

The Wiz Research Team found that the exposed data included backups of personal information belonging to Microsoft employees, including passwords for Microsoft services, secret keys, and an archive of over 30,000 internal Microsoft Teams messages.

Resources:
- https://www.bleepingcomputer.com/news/microsoft/microsoft-leaks-38tb-of-private-data-via-unsecured-azure-storage/
- https://thehackernews.com/2023/09/microsoft-ai-researchers-accidentally.html
- https://dataconomy.com/2023/09/18/microsoft-data-leak-wiz-azure/

## 2023-10-03 - Quishing <a name="qr"></a>
Suggest some ways we can reduce the risk of the QR code phishing (Quishing) campaign TTPs. We can derive a lot of tactics for QR code phishing from normal phishing emails, where obtaining user credentials is the motivation for attack. With this in mind, we can conduct proper end user training.
•	Approach external emails with caution. Especially those asking for credentials or personal information.
•	If no QR code activity is applicable for the environment to include vendor and client communication, inform your team that this should not be expected. (QR code policy)
•	If a trusted sender is requesting a QR code to be scanned, report the email or ask them to send the content in another form. (Confirm with sender via out-of-band channel)
•	Verify the redirect link prompted by the QR code following a successful scan.
•	Do not approve any unprompted MFA requests.

Apart from training, we can dive into what we know to be malicious from experience and quarantine certain messages within Office365 and Exchange Online. For instance, a reported phish that we encountered with our client, RSH, in alert #180362, includes the explicit string text “Scan the QR code with your camera on your mobile device to access your files.” We could set a rule to include the whole text string or “QR code” to quarantine all messages scanned that fit the criteria. We can also audit our web filtering solution and reconsider, if necessary.

Malicious redirect domains are also tough to track down when QR codes are often scanned via mobile device which do not support EDR tools. Even proper mobile device management will not prevent an end user using a personal mobile device for scanning, but it will prevent access to business resources from an unauthorized device. Blocking access to google lens will serve nicely, at least prevent the user from scanning the code via desktop.

Additionally, research suggests that organizations use image recognition tools as part of their phishing protection measures, although these are not guaranteed to catch all QR code threats. AI tools being created can detect QR codes for potential phishing as an added layer of content filtering such as Perception Point's Advanced Email Security or The Qryptal System. Reputable QR code scanning apps should be considered if the environment expects QR code activity.
With or without the assistance of technology, end user training trumps all priorities.

Resources:
- https://www.techtarget.com/searchsecurity/feature/Quishing-on-the-rise-How-to-prevent-QR-code-phishing
- https://www.qryptal.com/blog/secure-qr-can-artificial-intelligence-help-detect-malicious-qr-codes/
- https://perception-point.io/blog/qr-code-red-quishing-attacks-and-how-to-prevent-them/
- https://www.csoonline.com/article/651400/perception-point-tackles-qr-code-phishing-attacks-2.html#:~:text=Perception%20Point's%20Advanced%20Email%20Security,attempts%2C%20according%20to%20the%20vendor.


## 2023-10-10 - NSA and CISA Joint Cybersecurity Advisory <a name="advise"></a>
Review the NSA and CISA Joint Cybersecurity Advisory regarding their teams’ top ten cybersecurity misconfigurations and discuss one of them. The most critical, relevant, and overlooked, in my opinion is number 10, “Unrestricted code execution”. This refers to a situation where a user or program has the ability to execute any type of code without any limitations or restrictions, for good or bad.

This misconfiguration can be leveraged in many ways and at any point in a kill chain to cause damage. The example the agencies provide is a phishing email containing a file that executes arbitrary code on the victim’s machine after being clicked on. However, it can also be used to establish persistence, lateral move throughout the environment, obtain system level privileges, and more, depending on the objective.
There are many configuration recommendations for locking down code execution within an environment due to the large attack surface available. 

•	Verify host and perimeter content filter (Signature Based Anti-virus) and spam-filtering capabilities are actively blocking messages containing malicious content and executions.
•	Restrict what script/programming languages and processes can execute within an environment based on the supporting software and applications tools used.
•	Define rules, permissions, and group policies that prevent the regular users from running certain applications, especially those downloaded from untrusted sources.

Most applications support secure default settings to prevent this misconfiguration, but newly discovered vulnerabilities and supply chain attacks do not guarantee this. Additionally, common TTPs such as obfuscating code make it hard for allowlists to operate as intended, hence the reason for mitigative solutions and not just preventative (Access Management). 

Resources:
- https://attack.mitre.org/versions/v13/techniques/T1027/010/
- https://learn.microsoft.com/en-us/windows-server/identity/software-restriction-policies/administer-software-restriction-policies
- https://media.defense.gov/2023/Oct/05/2003314578/-1/-1/0/JOINT_CSA_TOP_TEN_MISCONFIGURATIONS_TLP-CLEAR.PDF


## 2023-11-07 - Search Engine Optimization (SEO) Poisoning <a name="seo"></a>
This week’s research regarded members of a team clicking on a malicious Google sponsored link that was imitating a legitimate third-party vendor. Threat actors leverage many key components that play into how Google’s algorithms determine which link is sponsored to appear first after a search. These components often include key word stuffing, cloaking, and article spinning, essentially bolstering their authenticity (to the search engine’s “crawlers”) as an active web page that supports the legitimate business. These sites commonly utilize “doorway pages” and typo squatting techniques as a way to avoid detection and redirect users to a malicious domain. 

Something that I found interesting is that Google and other search engines actually penalize the legitimate organization for one or multiple malicious domains and webpages “backlinking” to your legitimate domain. So out of no control of your own, you can find yourself losing reputation within a search engine just from being targeted by a threat actor but not necessarily being attacked. Backlinking is simply listing another website or domain as a redirect or hyperlink within your domain. However, proactive SEO audits can be performed to boost the reputation of your link / domain. 

Resources: 
- https://www.blackberry.com/us/en/solutions/endpoint-security/ransomware-protection/seo-poisoning#threats
- https://www.crowdstrike.com/cybersecurity-101/attack-types/seo-poisoning/ 


## 2023-11-14 - Msbuild.exe -> XML <a name="xml"></a>
An interesting IOC was recently discovered in the wild which involved msbuild.exe targeting an extensible markup language payload file. Msbuild locally compiles available source code or software to build an application project or solution file. After initial compromise with the help of remote access tools, webclient was observed being used to download cradle the XML file along with other remote access tools and .msi files. The significance of the XML file is that it is essentially a payload which contained C# programming which was actually forking an online project or LOLBin in order to load an instance of Metasploit in the memory of the machine. Also notably able to bypass anti virus. This calls for immediate isolation if observed as developers rarely utilize this build method.

Resources: 
- https://www.huntress.com/blog/third-party-pharmaceutical-vendor-linked-to-pharmacy-and-health-clinic-cyberattack
- https://attack.mitre.org/techniques/T1027/004/


## 2024-01-16 - NetScaler CVEs <a name="netscaler"></a>
Beginning with the NetScaler CVE and associated devices noted below, two vulnerabilities for two different customer-managed Citrix NetScaler devices have been actively exploited in the wild.
 
•  CVE-2023-6548 - NetScaler ADC (formerly Citrix ADC)
 
The Application Delivery Controller or ADC is quite literally a multi-tool for application networking. It operates as an intermediary between clients (such as web browsers) and servers, helping to ensure that user requests are handled efficiently and securely. Some of the key functionalities provided by Citrix ADC includes load balancing, monitoring and management, traffic direction, and serves as an application firewall.
 
The attack vector for CVE-2023-6548 is through the Management Interface of the NetScaler ADC. This interface is typically accessed via a web browser or command-line interface and is intended for use by administrators to manage the appliance settings. The vulnerability allows an attacker to inject and execute arbitrary code on the appliance, which can lead to remote code execution (RCE) (initially with low privileges). This means that an attacker could potentially gain control over the NetScaler ADC appliance and manipulate its behavior, intercept or modify traffic, create new routing rules, or perform other malicious activities.
 
The pre-requisite for an attacker to exploit CVE-2023-6548 is to have access to one of the IP addresses used by the Management Interface, which could be the NetScaler IP (NSIP), Cluster IP (CLIP), or Subnet IP (SNIP). This access implies that the attacker already has some level of network access, either through prior compromise or because they are an insider threat (e.g., a low-privileged user who has legitimate access to the Management Interface).
 
It is important to note that while the attack requires authenticated access, the attacker does not necessarily need to have high-level administrative privileges. Even a low-privileged user account could potentially exploit this vulnerability if they have access to the Management Interface.
 
•  CVE-2023-6549 - NetScaler Gateway (formerly Citrix Gateway)
 
The NetScaler Gateway is a secure application, desktop, and data access solution that gives IT administrators application and data-level control while providing users with SSO remote access from anywhere. In other words, a juicy VPN gateway.
 
The vulnerability identifies a critical buffer overflow flaw in the NetScaler Gateway, which could be exploited by an attacker to cause a Denial of Service (DoS). In order for the vulnerability to be exploitable, the NetScaler appliance must be configured to operate in specific roles such as a gateway with services like a VPN virtual server, ICA Proxy, CVPN, or RDP Proxy enabled, or as an AAA virtual server.
 
The attack vector consists of sending specially crafted packets to the vulnerable service, which due to inadequate buffer size validation, could result in an overflow condition. This overflow can disrupt the normal functioning of the appliance, leading to a DoS condition where legitimate users may be unable to access network resources. Exploiting this vulnerability would result in service interruption, causing operational impact without necessarily granting the attacker unauthorized access to sensitive data or system privileges. However, the risk is significant as it can affect the availability of critical network services.
 
Resources:
(CVE-2023-6548)
- https://arcticwolf.com/resources/blog/cve-2023-6548-cve-2023-6549-dos-and-rce-vulnerabilities-exploited-in-citrix-netscaler-adc-and-netscaler-gateway/
- https://support.citrix.com/article/CTX584986/netscaler-adc-and-netscaler-gateway-security-bulletin-for-cve20236548-and-cve20236549
 
(CVE-2023-6549)
- https://www.tenable.com/blog/cve-2023-6548-cve-2023-6549-zero-day-vulnerabilities-netscaler-adc-gateway-exploited
- https://arcticwolf.com/resources/blog/cve-2023-6548-cve-2023-6549-dos-and-rce-vulnerabilities-exploited-in-citrix-netscaler-adc-and-netscaler-gateway/


## 2024-01-30 - Ivanti CVEs <a name="ivanti"></a>
Ivanti Connect Secure (ICS), formerly known as Pulse Connect Secure and Ivanti Policy Secure gateways. Both devices provide a seamless, cost-effective, SSL VPN solution for remote and mobile users from any web-enabled device to corporate resources anytime, anywhere.
 
CVE-2024-21887 is a command injection vulnerability in the web component that could allow an authenticated threat actor to send specially crafted requests and execute arbitrary commands on the vulnerable appliance. On the other hand, CVE-2023-46805 is an authentication bypass vulnerability in the web components that could allow a remote threat actor to access the vulnerable appliance by bypassing control checks.  
 
If CVE-2024-21887 is used in conjunction with CVE-2023-46805, exploitation does not require authentication and enables a threat actor to craft malicious requests and execute arbitrary commands on the system. Both vulnerabilities rate a CVSS score of 8.2 and 9.1 and have been actively exploited in the wild, allegedly by a Chinese state sponsored group.
 
Resources: 
- https://packetstormsecurity.com/files/176668/Ivanti-Connect-Secure-Unauthenticated-Remote-Code-Execution.html
- https://arcticwolf.com/resources/blog/cve-2024-21887-cve-2023-46805/


## 2024-02-06 - AnyDesk Breach <a name="any"></a>
I looked into the recent incident involving the remote access tool, AnyDesk’s data breach, where threat actors were able to access production servers and according to some sources, client’s sensitive information. The attack happened late last week that put AnyDesk’s 170,000 customers at risk including NVIDIA, Samsung, Comcast, and even the United Nations. Initial access has not been released to the public; however, it was clear that the attackers were planning to use AnyDesk as a conduit to infect their customers and partners.
 
Sources claim that the threat actor was able to steal source code and code signing certificates for their software. This means that the certificates of the compromised software versions could be used to manipulate the code to implement a backdoor or create a supply chain attack with a legitimate version of AnyDesk. It can also allow a bad actor to sign their own piece of software, with the stolen certificate, which can fool security personnel (or Antivirus) or customers into thinking something is published by the company. The loss of source code is also a loss of intellectual property which comes with a loss of exclusivity (product duplication), making the innerworkings of the platform, not so secret.
 
Spiceworks noted that shortly following the breach, a security analyst made an observation on the Dark web of 18,317 AnyDesk customer credentials going up on sale for $15,000. The seller noted that “This data is ideal for technical support scams and mailing (phishing)”. The source also claims that the breach could potentially expose AnyDesk customers’ license keys, number of active connections, duration of sessions, customer ID and contact information, email associated with the account, and the total number of hosts that have remote access management software activated.
 
AnyDesk stated that session hijacking posed no risk in this case. Consequently, they have reset passwords for the online portal and revoked the compromised signature keys and certificate. Additionally, they have advised clients to change their passwords on other sites should they coincide with their AnyDesk password, as a precautionary measure. The AnyDesk tool was non-operational for only a few days.
 
This case was particularly spooky because it resembles the 2019-2020 SolarWinds breach that infected 18,000 customers within the federal and private sectors with a trojanized version of SolarWinds Orion. Some dub this as one of the most widespread and sophisticated hacking campaigns ever conducted against the federal government and private sector. AnyDesk’s case was caught just one phase prior to this.
 
Resources:
- https://www.bleepingcomputer.com/news/security/anydesk-says-hackers-breached-its-production-servers-reset-passwords/
- https://www.spiceworks.com/it-security/data-security/news/anydesk-server-breach/
- https://www.gao.gov/blog/solarwinds-cyberattack-demands-significant-federal-and-private-sector-response-infographic


## 2024-02-20 - LockBit Disruption <a name="lock"></a>
I recently looked into the recent joint operation conducted by the United States Government organizations and the United Kingdom, “Operation Cronos”. This operation was a very large success story against the alleged Russian threat actor group named LockBit. LockBit may be the most prolific ransomware-as-a-service groups in the world. They are responsible for roughly 2,000 confirmed cyber-attacks, begging forfeiture of nearly $150 million worth of ransom payments received ($90 million from The United States) from big-wigged organizations such as Boeing, The Ministry of Defense of the United Kingdom, Royal Mail Service, and many more.

The operation began in April 2022, headed by the U.K. National Crime Agency, and resulted in the seizure of 34 servers in the Netherlands, Germany, Finland, France, Switzerland, Australia, the United States and the United Kingdom, dark web websites, 14,000 rogue accounts, 200 cryptocurrency wallets, and the creation of the LockBit variant 3.0 (Black) decryption tool. Funds that were seized may be eligible for reimbursement depending on correlation of transactions. Two Russian members of the organization were indicted, and the U.S. State Department is now offering rewards of up to $15 million for information about additional members and their associates.

LockBit was notably the longest running ransomware group to date, falling just after the ALPHHV (BlackCat) and Hive ransom groups. Per the reports, this operation only caused a “disruption” and additional LockBit sites could very well be active and conducting operations.

Resources:
- https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-165a
- https://www.bleepingcomputer.com/news/security/police-arrest-lockbit-ransomware-members-release-decryptor-in-global-crackdown/
- https://www.justice.gov/opa/pr/us-and-uk-disrupt-lockbit-ransomware-variant
- https://www.bleepingcomputer.com/news/security/us-offers-15-million-bounty-for-info-on-lockbit-ransomware-gang/
- https://www.youtube.com/watch?v=-jKykhKKMZw

## 2024-02-23 - ScreenConnect Vulnerability <a name="scvuln"></a>
<INPRO>

# Ethical_Hacking_Projects
This repository contains project reports from my ethical hacking learning journey on the Infosec Lab platform. Each report documents a specific lab exercise, its objectives, methodologies, tools used, and conclusions. Below is an overview of the Infosec Lab and summaries of each report.

**Project 1: Performing Reconnaissance from the WAN** 
**Objective:** Conduct external reconnaissance on a network, capture credentials, and compromise a system using the gathered information.
**Tools & Tech:** Nmap, John the Ripper, Remote Desktop Protocol (RDP), Netcat/Telnet, pfSense firewall.
**Summary:** The project involved several key steps in the ethical hacking process:
Reconnaissance: Performed banner grabbing on the external IP of the pfSense firewall and used Nmap to scan for open ports.
Scanning: Utilized advanced Nmap options to determine operating systems and applications running on internal machines behind the firewall.
Gaining Access: Used banner information from port 23 to obtain initial system credentials.
Maintaining Access: Accessed the /etc/shadow file to retrieve the administrator's password hash, then used John the Ripper to crack it.
Escalating Privileges: Used the cracked administrator credentials to log into the Windows Server via RDP, gaining full system access.
**Conclusion:** This project demonstrated the ethical hacking process from initial reconnaissance to system compromise. It highlighted the importance of secure configurations and the potential vulnerabilities that can be exploited through external scanning and credential capture. The exercise emphasized the need for robust security measures, especially in firewall configurations and credential management.

**Project 2: Scanning the Network on the LAN**
**Objective:** Map local network hosts, identify vulnerabilities in a Postgres database system, and gain system access through credential escalation.
**Tools & Tech Stack:** Kali Linux OS, Nmap (SYN/Ping scans), Metasploit Framework, Armitage GUI, PostgreSQL.
**Key Activities:** This exercise focused on internal network reconnaissance through three phases:
Phase 1: Network Mapping
Ran targeted Nmap scans to fingerprint devices, discovering a Linux server running vulnerable Postgres 8.1. The TCP SYN scan (-sS flag) helped avoid detection while identifying open port 5432.
Phase 2: Vulnerability Exploitation
Armitage's visual interface simplified finding and launching the postgres_login module against the target. The tool automatically suggested viable exploits based on service banners, making this phase surprisingly straightforward compared to command-line alternatives.
Phase 3: Privilege Escalation
After initial access, used Meterpreter's hashdump to extract credentials. The real challenge came when pivoting to other systems using these hashes - several required manual cracking with John the Ripper before successful lateral movement.
**Conclusion:** The lab highlighted how outdated database systems become easy targets. While automated tools like Armitage streamline exploitation, manual analysis of scan results (like service versions) proved crucial for identifying viable attack vectors.

**Project 3: Capturing and Analyzing Network Traffic Using a Sniffer**
**Objective:** Capture and analyze cleartext protocol traffic to understand network communication vulnerabilities.
**Tools Used:** Wireshark 4.2, ifconfig (promiscuous mode setup), Legacy protocols: FTP, Telnet, POP3
**Practical Findings**
Traffic Capture Setup:  Configured Kali's eth0 interface in promiscuous mode - a simple ifconfig eth0 promisc command that surprisingly caused initial driver issues on virtualized hardware.
Protocol Analysis: Captured FTP/Telnet sessions revealed credentials transmitted openly. The SMTP analysis showed similar exposure - entire email bodies visible as plaintext.
Security Implications:
Wireshark's filter syntax (ftp.request.command == PASS) made finding sensitive data efficient. The exercise drove home why modern systems:
Replace FTP with SFTP/SCP.
Use SSH instead of Telnet.
Prefer IMAP over POP3.
**Conclusion:** While basic, this lab demonstrated why encryption matters. Seeing actual password extraction from packet captures makes textbook concepts tangible - you remember why we hash credentials after watching live credential harvesting.

**Project 4: Enumerating Hosts Using Wireshark, Windows, and Linux Commands**
**Objective:** Learn to enumerate resources on a target host using both passive and active scanning techniques.
**Tools & Tech Stack**
Wireshark: For passive scanning and packet analysis.
Windows Commands: net and nbtstat for active enumeration.
Linux Commands: ifconfig for interface configuration.
Armitage & Metasploit: For visualizing network hosts and performing active scans.
**Key Activities**
This lab focused on enumeration, an essential step in penetration testing, by leveraging both passive and active methods:
Passive Scanning with Wireshark: Captured network traffic to identify IP addresses, MAC addresses, and protocols used within the network. Filtered packets to analyze specific traffic patterns without alerting the target system.
Active Enumeration with Commands: Used the net command on Windows to list users, domains, and shared resources. Ran nbtstat to query NetBIOS name resolution and uncover machine names and services.
Leveraged Metasploit's db_nmap to scan the network (192.168.1.0/24) for live hosts and open ports.
Graphical Scanning with Armitage: Conducted Nmap scans through Armitage's GUI to visualize discovered hosts and their services.
**Conclusion:** Enumeration is a critical phase in ethical hacking that bridges reconnaissance and exploitation. Passive methods like Wireshark are stealthy but limited in scope, while active tools like nbtstat or Metasploit provide deeper insights at the cost of detectability. The lab emphasized balancing these approaches based on the engagement's goals.

**Project 5: Remote and Local Exploitation**
**Objective:** Exploit a vulnerable Postgres database service on a Linux server using advanced tools like OpenVAS, Greenbone Security Assistant, and Metasploit to gain privileged access.
**Tools & Technologies Used**
Nmap/Zenmap: For initial scanning of open ports and services.
OpenVAS & Greenbone Security Assistant (GSA): To identify critical vulnerabilities in the target system.
Metasploit Framework & Meterpreter: For exploiting vulnerabilities and privilege escalation.
**Key Activities**
This lab simulated a real-world penetration test through structured phases:
Planning & Scanning: Conducted initial scans with Nmap/Zenmap to identify open ports (e.g., Postgres on port 5432). Used OpenVAS with GSA to pinpoint specific vulnerabilities in the Postgres database service.
Exploitation with Metasploit:  Leveraged Metasploit modules to exploit the vulnerable Postgres service, gaining initial access to the target system.
Privilege Escalation & Persistence: Used Meterpreter commands (hashdump, getuid) to escalate privileges to root access. Explored techniques for maintaining access while evading detection.
Analysis of Results: Documented findings on exploited vulnerabilities and recommended mitigation strategies.
**Conclusion:** This lab reinforced the importance of combining vulnerability scanning tools (like OpenVAS) with exploitation frameworks (like Metasploit) for effective penetration testing. It also highlighted how privilege escalation can turn minor vulnerabilities into critical security risks if left unaddressed.

**Project 6: Crafting and Deploying Malware Using a Remote Access Trojan (RAT)**
**Objective:** This lab simulated a real-world attack scenario where we breached a network, gained unauthorized access, and established persistent control. The main goals were to scan for vulnerabilities, crack passwords, and deploy malware – all while evading detection.
**Key Tools and Terminologies:**
Nmap/Zenmap: Network scanning powerhouses.
Bruter: A password-cracking GUI that saved us from command-line headaches
DarkComet: The Remote Access Trojan (RAT) of choice for this exercise
Remote Desktop Protocol (RDP): Our entry point once we had credentials
**Key Activities:** Started by poking around the network from the outside, hunting for any open doors. Once we found RDP exposed, it was time to break out the digital lockpicks. Bruter did the heavy lifting, trying thousands of passwords until we struck gold. With admin access in hand, things got interesting. Crafted our malware using DarkComet, dressing it up to look like a harmless Firefox update. Sneaking it onto the target machine was a bit nerve-wracking – one wrong move and we'd blow our cover. The real thrill came when our RAT phoned home. Suddenly, we had full control of the compromised system. To prove the point, we snagged some "top-secret" files (in this case, totally fake Death Star plans).
**Conclusion:** This lab was an eye-opener. It showed how a determined attacker can chain together seemingly small vulnerabilities to completely own a system. As defenders, we need to think like the bad guys – because they're definitely thinking about ways to outsmart us.

**Project 7: Performing a Denial of Service Attack from the WAN**
**Objective:** In this lab, we unleashed digital chaos (in a controlled environment, of course). The goal was to understand and execute various types of Denial of Service (DoS) attacks, seeing firsthand how they can cripple network services.
**Key Tools and Terminologies:**
Low Orbit Ion Cannon (LOIC): Our primary DoS weapon.
tcpdump: For capturing the flood of packets we generated.
capinfos: Helped us analyze just how much havoc we wreaked.
TCP, UDP, and HTTP floods: Different flavors of digital firehoses.
**Key Activities:** Kicked things off by setting up our packet-sniffing station to capture all the mayhem. Then, it was time to let LOIC loose. We launched three types of attacks:
TCP Flood: Overwhelmed the target with a barrage of SYN packets.
UDP Flood: Bombarded random ports with a deluge of datagrams.
HTTP Flood: Drowned a web server in seemingly legitimate requests.
After each attack, we dug into the captured traffic. The sheer volume of packets generated in such a short time was staggering.
**Conclusion:** This lab hammered home why DoS attacks are such a headache for network defenders. It's frighteningly easy to bring services to their knees with the right tools. But more importantly, it highlighted the need for robust traffic analysis and filtering systems. In the real world, these attacks often serve as smoke screens for more subtle intrusions – so understanding them inside and out is crucial for any security pro.

**Project 8: Using Browser Exploitation to Take Over a Host's Computer**
**Objective:** This lab simulated exploiting an Internet Explorer vulnerability to gain unauthorized access to a victim's machine. The goal was to understand how attackers can leverage browser flaws for system compromise.
Key Tools and Terminologies: Metasploit Framework, Internet Explorer (vulnerable version), Meterpreter payload, Spear phishing techniques, John the Ripper password cracker, XAMPP web server.
**Key Activities:**
Set up a malicious exploit server using Metasploit on the Kali Linux machine.
Crafted a convincing spear phishing email with a malicious link, masquerading as a legitimate Facebook message.
Tricked the victim into clicking the link, triggering the IE vulnerability (ms08_078).
Gained remote access through Meterpreter once the exploit succeeded.
Performed post-exploitation tasks:
Stole sensitive files (DeathStar blueprints).
Dumped password hashes using Meterpreter's hashdump command.
Cracked the administrator password with John the Ripper.
Defaced the victim's website.
**Conclusion:** This lab demonstrated the power of browser exploits when combined with social engineering. It highlighted why keeping browsers updated is crucial and how a single click on a malicious link can compromise an entire system. The exercise also showed the importance of post-exploitation actions in maintaining access and extracting valuable data.

**Project 9: Attacking Webservers from the WAN**
**Objective:** This lab simulated attacking a web server from an external network position, emphasizing the importance of securing internet-facing services.
Key Tools and Terminologies: Nmap/Zenmap for network scanning, Bruter for password attacks, Remote Desktop Protocol (RDP), XAMPP web server, SMTP (Simple Mail Transfer Protocol)
**Key Activities:**
Scanned the WAN using Nmap to identify open ports, particularly focusing on SMTP.
Used Bruter to perform a dictionary attack against SMTP, capturing admin credentials.
Leveraged the stolen credentials to access the victim machine via RDP.
Defaced the website hosted on the compromised server.
Covered tracks by removing incriminating log entries.
**Conclusion:** This exercise highlighted the risks of exposed services and weak authentication. It demonstrated how attackers can chain together reconnaissance, exploitation, and post-compromise actions to fully compromise a target. The importance of robust logging and intrusion detection was underscored by the ease of covering tracks.

**Project 10: Exploiting a Vulnerable Web Applicatio**n
**Objective:** This lab focused on exploiting a vulnerable web application, showcasing how attackers can leverage common misconfigurations to gain unauthorized access.
**Key Tools and Terminologies:**
Nmap for initial scanning, Armitage (GUI for Metasploit), XAMPP WebDAV vulnerability, Meterpreter payload, SMB (Server Message Block) protocol
**Key Activities:**
Used Nmap to identify open ports, particularly looking for Apache WebDAV services.
Exploited the XAMPP WebDAV vulnerability using Metasploit through Armitage.
Leveraged the compromised web server to pivot and attack an internal Windows server.
Utilized an SMB vulnerability (MS09-50) to gain access to the Windows machine.
Established persistence using Meterpreter.
**Conclusion:** This lab demonstrated the dangers of misconfigured web applications and the potential for lateral movement within a network. It emphasized the need for proper patch management, secure configurations, and network segmentation. The exercise also showcased how attackers can chain multiple exploits to deeply penetrate a network.


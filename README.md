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
Security Implications
Wireshark's filter syntax (ftp.request.command == PASS) made finding sensitive data efficient. The exercise drove home why modern systems:
Replace FTP with SFTP/SCP
Use SSH instead of Telnet
Prefer IMAP over POP3
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


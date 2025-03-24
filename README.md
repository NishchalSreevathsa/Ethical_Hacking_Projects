# Ethical_Hacking_Projects
This repository contains project reports from my ethical hacking learning journey on the Infosec Lab platform. Each report documents a specific lab exercise, its objectives, methodologies, tools used, and conclusions. Below is an overview of the Infosec Lab and summaries of each report.

**Project 1: Performing Reconnaissance from the WAN** 
**Objective:** Conduct external reconnaissance on a network, capture credentials, and compromise a system using the gathered information.
**Tools & Technologies Used:** Nmap, John the Ripper, Remote Desktop Protocol (RDP), Netcat/Telnet, pfSense firewall
**Summary:** The project involved several key steps in the ethical hacking process:
Reconnaissance: Performed banner grabbing on the external IP of the pfSense firewall and used Nmap to scan for open ports.
Scanning: Utilized advanced Nmap options to determine operating systems and applications running on internal machines behind the firewall.
Gaining Access: Used banner information from port 23 to obtain initial system credentials.
Maintaining Access: Accessed the /etc/shadow file to retrieve the administrator's password hash, then used John the Ripper to crack it.
Escalating Privileges: Used the cracked administrator credentials to log into the Windows Server via RDP, gaining full system access.
**Conclusion:** This project demonstrated the ethical hacking process from initial reconnaissance to system compromise. It highlighted the importance of secure configurations and the potential vulnerabilities that can be exploited through external scanning and credential capture. The exercise emphasized the need for robust security measures, especially in firewall configurations and credential management.


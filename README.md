# 🛡️ Deception-Based SSH Honeypot (Paramiko)

A high-interaction SSH honeypot built using Python that emulates a real SSH server and captures attacker behavior in a controlled environment. It speaks the actual SSH protocol using Paramiko, allowing standard SSH clients to connect without any issues while safely logging credentials, commands, and session activity.

This project simulates a vulnerable Linux machine and is designed for cybersecurity learning, ethical hacking practice, and demonstrating real-world attack monitoring techniques.

The honeypot listens on a configurable port (default 2222) and presents a realistic SSH banner. When a user attempts to authenticate, their username and password are captured and logged. Only predefined fake credentials are accepted, allowing the attacker to enter a controlled fake shell environment where all commands are monitored.

Fake credentials that grant access:

* root / 12345678
* admin / admin123

Any other credentials are rejected with a standard “Permission denied” response. If multiple failed attempts (5 or more) occur from the same IP, the system flags it as a brute-force attack and logs it as a high-risk event.

Once inside the fake shell, the attacker interacts with a simulated Linux environment. Common commands such as `ls`, `whoami`, `uname`, `ps aux`, `netstat`, `ifconfig`, `cat /etc/passwd`, and `cat /etc/shadow` return realistic outputs. Unknown commands return typical Linux errors like “command not found”. Potentially dangerous commands such as reverse shells, file deletions, or privilege escalation attempts are detected, logged, and classified by risk level but never actually executed, ensuring complete safety.

The system includes a detection engine that categorizes activity into LOW, MEDIUM, and HIGH risk levels. High-risk commands include actions like accessing sensitive files, attempting reverse shells, or using encoded payloads. Medium-risk commands typically involve system enumeration such as checking processes or network configurations. Low-risk commands include basic navigation like listing directories.

All activity is logged into a file (`honeypot.log` by default), including connection attempts, login credentials, executed commands, and session duration. The program also prints real-time logs to the terminal with optional colored output for better visibility. When the honeypot is stopped, it displays a summary including total connections, unique IP addresses, successful logins, brute-force attempts, and high-risk command counts.

To run the project, first install the required dependencies:
pip install paramiko colorama

Then start the honeypot:
python ssh_honeypot.py

You can optionally specify a custom port:
python ssh_honeypot.py --port 2222

To run it on port 22 (for a more realistic setup), use:
sudo python ssh_honeypot.py --port 22

To test the honeypot, open another terminal or machine and connect using:
ssh root@<your-ip> -p 2222
or
ssh admin@<your-ip> -p 2222

Replace `<your-ip>` with your system’s IP address (or use 127.0.0.1 for local testing).

Example interaction:

* Attacker connects via SSH
* Attempts multiple passwords (logged)
* Eventually logs in using fake credentials
* Executes commands in fake shell
* All actions are recorded and analyzed

Example log output:
[2026-04-08 12:00:01] INFO     [LOW] [192.168.1.5] New SSH connection
[2026-04-08 12:00:05] INFO     Failed login #1 user='admin' pass='123'
[2026-04-08 12:00:10] WARNING  [HIGH] CMD [HIGH] user='root' $ cat /etc/shadow

Security note: this honeypot does not execute any real system commands and does not provide actual shell access. It is completely isolated and safe when used properly. However, it should only be deployed in controlled environments such as local machines or private servers. Do not expose it to networks you do not own or have permission to monitor.

This project is intended strictly for educational purposes, cybersecurity research, and ethical hacking practice. Any misuse is the responsibility of the user.

Possible future improvements include adding attacker IP geolocation, integrating a web dashboard for log visualization, enabling real-time alerts via email or messaging platforms, containerizing the application using Docker, and integrating with SIEM tools for advanced analysis.

Author: Taher Musaji

If you find this project useful, consider starring it on GitHub and using it as part of your cybersecurity portfolio.

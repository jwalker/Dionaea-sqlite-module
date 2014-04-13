Dionaea Sqlite Module

The Dionaea sqlite module (DSM), is a python module that parses through Dionaea honeypots's sql files.
As development continues, more will be added to the README.md

Prerequisites:
- pysqlite - https://docs.python.org/2/library/sqlite3.html

This module tracks connections, protocols stats, default passwords used in attacks, sorts unique IP address of attackers,
downloads by hashes offering original execution links, and SIP information.

DSM has a potential to keep growing as new threats and analysis techniques arise. The module was written in a generic way to illustrate what can be done once your honeypot has enough data to be processed. Any suggestions or ideas are welcome.

## Usage:
### quickanalysis.py - a test script to show DSM usage
./quickanalysis.py
------------------------------
Connections/Protos @ Glance

Total # of connections 56815
Total # of tcp connections 55980
Total # of udp connections 834
------------------------------
Count   Protocol
------------------------------
26783   | p0fconnection
14052   | pcap
10042   | mssqld
1357    | mirrorc
1357    | mirrord
1219    | mysqld
844     | SipSession
714     | httpd
203     | epmapper
148     | smbd
78      | ftpd
12      | ftpdataconnect
5       | ftpdatalisten
1       | SipCall
------------------------------
Malware downloads - hashes
http://96.51.68.167:14932/x - 743132b629b3f160aa640dde052d4151
smb://184.94.231.195/winnt\lsass.exe - 786ab616239814616642ba4438df78a9
smb://187.232.90.78/winnt\lsass.exe - 786ab616239814616642ba4438df78a9
http://94.140.77.230:29092/x - 9c064772651a14ca8936d02d98f843ed
smb://114.86.186.78/csrss.exe - 065172e07a125623ea0a0fbcdaaa6dee
http://96.51.70.82:28113/x - 743132b629b3f160aa640dde052d4151
smb://78.97.136.59/csrss.exe - 3a5c1c2ce9bd9f21bcf0e87dae4c0fed
------------------------------

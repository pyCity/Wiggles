# Wiggles
Linux POC Network Worm in Python 3

Network worm with spreading and persistence

From pseudocode.txt:

- Worm is executed on victim pc
- Worm analyzes current environment and resources
    - Gets public and private IP
    - Gets list of available hosts
- Worm escalates privileges
- Worm begins executing persistence
- Worm executes spreading

-----------SPREADING-------------
1) Scans all hosts in current subnet for target ports
2) Verify that host is vulnerable to an available exploit
3) Fire exploit at vulnerable hosts with a reverse shell payload
4) Pass shell to propagate class to escalate privileges (QUIETLY)
5) Apply persistence
6) Repeat 1-5 for all hosts

-----------PRIV ESC-------------
- Dirty Sock    - (Snap)
- Full-Nelson   - Kernel 2.6.37 <= 'Full-Nelson.c' (RedHat/Ubuntu 10.04)
- CVE-2010-3904 - Kernel <=2.6.36-rc8 (RDS protocol)
- CVE-2016-5195 - Dirty Cow (LOUD! Last resort)
    - https://dirtycow.ninja/
    - Compile:  g++ -Wall -pedantic -O2 -std=c++11 -pthread -o dcow 40847.cpp -lutil

--------Exploits----------
- Libssh Authentication Bypass
- Heartbleed (CVE-2014-0160)
- Shellshock

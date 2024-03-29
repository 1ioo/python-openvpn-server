import subprocess
import platform
import os
import shlex

# Menu Page
def menu():
    print('''#################################################################################
#################################################################################
##   ___                __     ______  _   _   ____                            ##
##  / _ \ _ __   ___ _ _\ \   / /  _ \| \ | | / ___|  ___ _ ____   _____ _ __  ##
## | | | | '_ \ / _ \ '_ \ \ / /| |_) |  \| | \___ \ / _ \ '__\ \ / / _ \ '__| ##
## | |_| | |_) |  __/ | | \ V / |  __/| |\  |  ___) |  __/ |   \ V /  __/ |    ##
##  \___/| .__/ \___|_| |_|\_/  |_|   |_| \_| |____/ \___|_|    \_/ \___|_|    ##
##       |_|                                                                   ##
#################################################################################
#################################################################################''')
    print("1. Server Set Up")
    print("2. Client Certificate Creation")
    print("3. Revoke Client Certificates")
    print("4. Exit")
    print("==================================================================================")

# Upgrade and Update System
def upgradeSystem():
    commands = ["update","upgrade"]
    for command in commands:
        if subprocess.call(["sudo","apt","-y",command]) == 0:
            print(f"\nSystem {command}d successfully...\n")
        else:
            raise Exception(f"\nSystem failed to {command}...\n")

# Check if package provided is installed
def checkPackage(packageName: str):
    with open(os.devnull,"w") as devnull:# discard output
        return "" if subprocess.call(["dpkg","-s",packageName],stdout=devnull,stderr=subprocess.STDOUT) == 0 else str(packageName)

# Execute Commands
def cmd(command: str):
    commandList = shlex.split(command)
    try:
        subprocess.run(commandList, check=True)
        print(command + " executed successfully.")
    except subprocess.CalledProcessError as e:
        raise Exception(f"\n\nError: {e}\n")

# Installing Related Packages
def installPackages():
    try:
        upgradeSystem()
        packages = {}
        packages["easy-rsa"] = checkPackage("easy-rsa")
        packages["openssh-server"] = checkPackage("openssh-server")
        packages["iptables"] = checkPackage("iptables")
        packages["iptables-persistent"] = checkPackage("iptables-persistent")
        packages["openvpn"] = checkPackage("openvpn")
        packages["fail2ban"] = checkPackage("fail2ban")
        packages["python3-psutil"] = checkPackage("python3-psutil")
        packages["rsyslog"] = checkPackage("rsyslog")

        for package in packages:
            if packages[package] == "":
                print("\n" + package + " has already been installed...\n")
            else:
                cmd(f"sudo apt -y install {packages[package]}")
                print("\n" + packages[package] + " has been installed...\n")

    except Exception as e:
        raise Exception(e)

# Embed Relevant Certificates or Keys in Configuration Files
def embedCertificate(embedPath: str, configPath: str):
    try:
        tags = {"ca":"ca",".crt":"cert","ta":"tls-auth",".key":"key",".pem":"dh"}
        for tag in tags:
            if tag in embedPath:
                embedType = tag if tag in embedPath else None
                break
        embedType = tags[embedType]
        openingTag = f"\n<{embedType}>\n"
        closingTag = f"</{embedType}>\n"
        cmd(f"sed -i '/{embedType} / s/^{embedType}/#{embedType}/' {configPath}")
        with open(configPath,"a") as conf:
            with open(embedPath,"r") as embedFile:
                conf.write(openingTag)
                conf.write(embedFile.read())
                conf.write(closingTag)
    except Exception as e:
        if embedType != None:
            raise Exception(f"Is the path correct?\n\n{e}")
        else:
            raise Exception("File Type not supported.")
def uncommentLines(line: str, filepath: str):
    try:
        cmd(f"sudo sed -i '/^{line}/ s/^[;#]//g' {filepath}")
    except Exception as e:
        raise Exception(f"Error: {e}")

# Setting Up OpenVPN Server Configuration
def createServerConfig():
    try:
        serverConfigPath = "/etc/openvpn/server/server.conf"
        cmd(f"sudo sed -i 's/port 1194/port {openVPNPort}/' {serverConfigPath}")
        embedCertificate("/etc/openvpn/server/dh.pem", serverConfigPath)
        embedCertificate("/etc/openvpn/server/ta.key", serverConfigPath)
        embedCertificate("/etc/openvpn/server/ca.crt", serverConfigPath)
        embedCertificate("/etc/openvpn/server/issued/server.crt", serverConfigPath)
        embedCertificate("/etc/openvpn/server/private/server.key", serverConfigPath)
        uncommentLines(';push "redirect-gateway def1 bypass-dhcp"', serverConfigPath)
        uncommentLines(';push "dhcp-option', serverConfigPath)
        cmd(f"sudo sed -i 's/cipher AES-256-CBC/cipher AES-256-GCM/' {serverConfigPath}")
        uncommentLines(";log-append", serverConfigPath)
    except Exception as e:
        raise Exception(e)

# Change Working Directory
def cd(path: str):
    try:
        os.chdir(path)
    except FileNotFoundError as f:
        raise Exception(f"{path} does not exist.")

# Commands to Generate Certificates
def commands():
    try:
        serverDirectory = "/etc/openvpn/server/"
        cd("/usr/share/easy-rsa")
        cmd("sudo ./easyrsa init-pki")
        cmd("sudo ./easyrsa build-ca nopass") # Enter 'ca' for name of CA
        cmd("sudo ./easyrsa build-server-full server nopass") # enter 'yes' to confirm
        cmd("sudo ./easyrsa gen-dh")
        cmd("sudo openvpn --genkey secret ./pki/ta.key")
        cmd(f"sudo cp -pR /usr/share/easy-rsa/pki/issued {serverDirectory}")
        cmd(f"sudo cp -pR /usr/share/easy-rsa/pki/private {serverDirectory}")
        cmd(f"sudo cp -pR /usr/share/easy-rsa/pki/ca.crt {serverDirectory}")
        cmd(f"sudo cp -pR /usr/share/easy-rsa/pki/dh.pem {serverDirectory}")
        cmd(f"sudo cp -pR /usr/share/easy-rsa/pki/ta.key {serverDirectory}")
        cmd(f"sudo cp /usr/share/doc/openvpn/examples/sample-config-files/server.conf {serverDirectory}")
    except Exception as e:
        raise Exception(e)
    
# Creation of Bridges (IP Forwarding)
def createBridges():
    try:
        import psutil
        with open("/etc/openvpn/server/add-bridge.sh","w") as script:
            network_interfaces = list(psutil.net_if_addrs().keys())
            script.write("#!/bin/bash\n")
            script.write("echo 1 > /proc/sys/net/ipv4/ip_forward\n")
            script.write("iptables -A FORWARD -i " + "tun0" + " -j ACCEPT\n")
            script.write("iptables -t nat -A POSTROUTING -o " + network_interfaces[1] + " -j MASQUERADE\n")

        with open("/etc/openvpn/server/remove-bridge.sh","w") as script:
            network_interfaces = list(psutil.net_if_addrs().keys())
            script.write("#!/bin/bash\n")
            script.write("echo 0 > /proc/sys/net/ipv4/ip_forward\n")
            script.write("iptables -D FORWARD -i " + "tun0" + " -j ACCEPT\n")
            script.write("iptables -t nat -D POSTROUTING -o " + network_interfaces[1] + " -j MASQUERADE\n")

        cmd("chmod 700 /etc/openvpn/server/add-bridge.sh")
        cmd("chmod 700 /etc/openvpn/server/remove-bridge.sh")

        appendAfter = "Restart=on-failure"
        appendFile = "/lib/systemd/system/openvpn-server@.service"
        cmd(f"sudo sed -i '/{appendAfter}/a ExecStopPost=/etc/openvpn/server/remove-bridge.sh\n' {appendFile}")
        cmd(f"sudo sed -i '/{appendAfter}/a ExecStartPost=/etc/openvpn/server/add-bridge.sh' {appendFile}")

        cmd("sudo systemctl daemon-reload")
        cmd("sudo systemctl enable --now openvpn-server@server")
    except Exception as e:
        raise Exception(e)
    
# Creation of IP Table Rules
def createIptables():
    try:
        cmd('sudo iptables -A INPUT -j ACCEPT -i lo')
        cmd('sudo iptables -A INPUT -j ACCEPT -m conntrack --ctstate ESTABLISHED,RELATED')
        cmd('sudo iptables -A INPUT -j ACCEPT -p icmp')
        cmd(f'sudo iptables -A INPUT -j ACCEPT -p tcp --dport {sshPort}')
        cmd(f'sudo iptables -A INPUT -j ACCEPT -p udp --dport {openVPNPort}')
        cmd('sudo iptables -A INPUT -j ACCEPT -p tcp --dport 53')
        cmd('sudo iptables -A INPUT -j ACCEPT -p udp --dport 53')

        cmd('sudo iptables -A OUTPUT -j ACCEPT -o lo')
        cmd('sudo iptables -A OUTPUT -j ACCEPT -m conntrack --ctstate ESTABLISHED,RELATED')
        cmd('sudo iptables -A OUTPUT -j ACCEPT -p icmp')
        cmd('sudo iptables -A OUTPUT -j ACCEPT -p tcp --dport 53')
        cmd('sudo iptables -A OUTPUT -j ACCEPT -p udp --dport 53')
        cmd('sudo iptables -A OUTPUT -j ACCEPT -p udp --dport 123')
        cmd('sudo iptables -A OUTPUT -j ACCEPT -p tcp --dport 80')
        cmd('sudo iptables -A OUTPUT -j ACCEPT -p tcp --dport 443')
        cmd("sudo iptables -P INPUT DROP")
        cmd("sudo iptables -P OUTPUT DROP")

        try:
            subprocess.run(["sudo iptables-save > /etc/iptables/rules.v4"], shell=True, stdout=subprocess.PIPE, text=True, check=True)
        except subprocess.CalledProcessError as e:
            raise Exception(f"Error: {e}")
    except Exception as e:
        raise Exception(e)

# Setting up Fail2Ban
def createFail2Ban():
    try:
        with open("/etc/fail2ban/jail.local","w") as jail:
            jail.write("[default]\n")
            jail.write("maxretry = 3\n")
            jail.write("bantime = 60\n")
            jail.write("[sshd]\n")
            jail.write("enabled = true\n")
            jail.write(f"port = {sshPort}\n")
            jail.write("filter = sshd\n")
            jail.write("logpath = /var/log/auth.log\n\n")
            jail.write("[openvpn]\n")
            jail.write("enabled = true\n")
            jail.write(f"port = {openVPNPort}\n")
            jail.write("filter = openvpn\n")
            jail.write("logpath = /var/log/openvpn/openvpn.log\n\n")

        with open("/etc/fail2ban/filter.d/openvpn.conf","w") as openvpn:
            openvpn.write("[Definition]\n")
            openvpn.write("failregex = TLS Error: incoming packet authentication failed from \[AF_INET\]<HOST>:\d+\n")
            openvpn.write("ignoreregex = \n\n")

        cmd("sudo systemctl restart fail2ban ssh openvpn-server@server")

        try:
            subprocess.run("sudo fail2ban-client reload", shell=True, check=True)
        except subprocess.CalledProcessError as e:
            print(f"Fail2Ban Client is unable to be reloaded: {e}")
    except Exception as e:
        raise Exception(e)
    
# Building of Client Configurations
def buildClientConfig():
    try:
        name = str(input("Enter Client Name > "))
        
        if os.path.exists(f"/usr/share/easy-rsa/pki/issued/{name}.crt"):
            print("\nChoose another name.\n")
        else:
            ip = input("Enter IP Address of Server > ")
            clientOS = str(input("Enter Operating System of Client (Linux/Windows) > ").upper())
            # Enter 'yes' to confirm
            cd("/usr/share/easy-rsa")
            cmd(f"./easyrsa build-client-full {name} nopass")
            cd("/usr/share/easy-rsa/pki")

            if clientOS == "LINUX":
                nameWithExtension = f"{name}.conf"
            elif clientOS == "WINDOWS":
                nameWithExtension = f"{name}.ovpn"
            else:
                print("Enter a Valid Operating System!")

            configFile = nameWithExtension

            cmd(f"sudo cp /usr/share/doc/openvpn/examples/sample-config-files/client.conf {nameWithExtension}")
            cmd(f"sudo sed -i 's/remote my-server-1 1194/remote {ip} {openVPNPort}/' {configFile}")
            embedCertificate(f"/usr/share/easy-rsa/pki/issued/{name}.crt", configFile)
            embedCertificate("/usr/share/easy-rsa/pki/ca.crt", configFile)
            embedCertificate(f"/usr/share/easy-rsa/pki/private/{name}.key",configFile)
            embedCertificate("/usr/share/easy-rsa/pki/ta.key", configFile)
            cmd(f"sudo sed -i 's/cipher AES-256-CBC/cipher AES-256-GCM/' {configFile}")

            if (clientOS == "LINUX"):
                with open(configFile,"a") as conf:
                    conf.write("script-security 2\n")
                    conf.write("up /etc/openvpn/update-systemd-resolved\n")
                    conf.write("up-restart\n")
                    conf.write("down /etc/openvpn/update-systemd-resolved\n")
                    conf.write("down-pre\n")
                    conf.write("dhcp-option DOMAIN-ROUTE .\n")
            cmd(f"chmod 755 {nameWithExtension}")
            cmd(f"mv {nameWithExtension} /tmp")
            print(f"\n{nameWithExtension} has been moved to /tmp/{nameWithExtension}, it is ready for transfer.\n")
    except Exception as e:
        raise Exception(e)
    
# Revoke/Expire Certificates
def revokeCertificate():
    try:
        serverConfPath = "/etc/openvpn/server/server.conf"
        name = str(input("Enter Name of Client > "))
        if os.path.exists(f"/usr/share/easy-rsa/pki/issued/{name}.crt"):
            cd("/usr/share/easy-rsa")
            cmd(f"./easyrsa revoke {name}")
            cmd("./easyrsa gen-crl")

            lineExist = False
            with open(serverConfPath, "r") as file:
                for line in file:
                    if line.strip() == "crl-verify":
                        lineExist = True
                        break
            
            if not lineExist:
                with open(serverConfPath,'a') as config:
                    config.write("crl-verify /usr/share/easy-rsa/pki/crl.pem")

            cmd("sudo systemctl restart openvpn")
            print("CRL Status:")
            cmd("sudo openssl crl -in /usr/share/easy-rsa/pki/crl.pem -text")
            print(f"\n\n{name}'s certificate has been revoked.\n\n")
        else:
            print(f"\n\n{name}'s certificate does not exist on the system.\n\n")
        cmd("sudo systemctl restart openvpn-server@server")
        print("\n\n")
    except Exception as e:
        raise Exception(e)

# SSH Hardening
def hardenServer():
    try:
        sshConfPath = "/etc/ssh/sshd_config"
        cmd(f"sudo sed -i 's/#Port 22/Port {sshPort}/' {sshConfPath}")
        uncommentLines("#SyslogFacility AUTH", sshConfPath)
        uncommentLines("#LogLevel INFO", sshConfPath)
        uncommentLines("#PermitRootLogin prohibit-password", sshConfPath)
        cmd(f"sudo sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' {sshConfPath}")
        cmd(f"sudo sed -i 's/X11Forwarding yes/X11Forwarding no/' {sshConfPath}")

        cmd("sudo systemctl restart ssh")
    except Exception as e:
        raise Exception(e)

if __name__ == "__main__":
    try:
        operatingSystem = platform.system()
        sshPort = "2244"
        openVPNPort = "2876"
        if (operatingSystem == "Linux"):
            choice = 0
            while choice != 4:
                menu()
                try:
                    choice = int(input("Enter Your Choice > "))
                except KeyboardInterrupt:
                    choice = 4
                if choice == 1:
                    installPackages()
                    hardenServer()
                    commands()
                    createServerConfig()
                    createBridges()
                    createIptables()
                    createFail2Ban()

                    print("\n\nSERVER SUCCESSFULLY SET UP\n\n")

                elif choice == 2:
                    buildClientConfig()

                elif choice == 3:
                    revokeCertificate()

                elif choice == 4:
                    print("Exited Successfully.")
                    break
                else:
                    print("Enter the Correct Selection!")
                
        else:
            print("Other Operating Systems are currently not supported...")

    except Exception as e:
        print(e)
        print("\n\n PLEASE FIX THE ABOVE ERROR BEFORE CONTINUING\n\n")
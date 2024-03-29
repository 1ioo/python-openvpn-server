# OpenVPN Server Set Up in Python
This Python script automates the setup and management of an OpenVPN server on a Linux system.

# Table of Contents
1. [Part I: Usage](#part-i-usage)
2. [Part II: Menu](#part-ii-menu)
3. [Part III: Features](#part-iii-features)
4. [Part IIII: Connection](#part-iiii-connection)

## Part I: Usage
The script can be ran using:
```
python3 build-vpn-server.py
```

Prior to executing the script, it is highly encouraged to perform a system update and upgrade, ensuring that your system has the latest software versions. This proactive step not only saves time but also optimizes resource utilization for a smoother script execution. It's worth noting that the script itself will handle system update and upgrade if it hasn't been done already, making this step optional.

Run the following command to Update and Upgrade the System:
```
sudo apt update && sudo apt upgrade -y
```

## Part II: Menu 
The script incorporates a user-friendly interface, allowing users to make selections tailored to their specific needs or purposes.
```
#################################################################################
#################################################################################
##   ___                __     ______  _   _   ____                            ##
##  / _ \ _ __   ___ _ _\ \   / /  _ \| \ | | / ___|  ___ _ ____   _____ _ __  ##
## | | | | '_ \ / _ \ '_ \ \ / /| |_) |  \| | \___ \ / _ \ '__\ \ / / _ \ '__| ##
## | |_| | |_) |  __/ | | \ V / |  __/| |\  |  ___) |  __/ |   \ V /  __/ |    ##
##  \___/| .__/ \___|_| |_|\_/  |_|   |_| \_| |____/ \___|_|    \_/ \___|_|    ##
##       |_|                                                                   ##
#################################################################################
#################################################################################
1. Server Set Up
2. Client Certificate Creation
3. Revoke Client Certificates
4. Exit
=================================================================================
```
1. Server Set Up
    - [Updating and Upgrading of System](#1-update-and-upgrading-of-system)
    - [Installing Required Packages](#2-installing-required-packages)
    - [Set Up of OpenVPN Server](#3-set-up-of-openvpn-server)
    - [Hardening of Server](#4-hardening-of-server)
2. Client Certificate Creation
    - [Creation of Client Keys and Certificates](#5-creation-of-client-keys-and-certificates)
    - [Creation of Client Configuration](#6-creation-of-client-configuration)
3. Revoke Client Certificates
    - [Revoke Client Certificates](#7-revoke-client-certificates)
    - [Revoke Client access to OpenVPN Server](#8-revoke-client-access-to-openvpn-server)

## Part III: Features
### 1. Update and Upgrading of System
As the first step, the script initiates the updating and upgrading of the system. This essential process ensures that both the system and its package manager are brought up to the latest versions, providing improved security, bug fixes, and access to the latest features and enhancements.

### 2. Installing Required Packages
Necessary packages required for setting up the OpenVPN Server are installed.

List of Packages Installed by Script:
- easy-rsa
- openssh-server
- iptables
- iptables-persistent
- openvpn
- fail2ban
- python3-psutil
- rsyslog

**_NOTE:_**  The installation of `rsyslog` is included to revert back to using `/var/log/auth.log` on Linux systems (such as Debian) that utilize journalctl to store authorization information. If your system already uses `/var/log/auth.log` for authorization information, the installation of this package is not necessary.

### 3. Set Up of OpenVPN Server
The server is managed using `Easy-RSA`, which is employed to handle the server's Public Key Infrastructure (PKI). All key and certificate creation and revocation tasks are managed through Easy-RSA. After generating the required server certificates and keys through Easy-RSA, the script proceeds to craft an OpenVPN configuration file. This file is crucial for configuring and activating the OpenVPN server.

### 4. Hardening of Server
The server undergoes a robust hardening process, incorporating SSH Hardening, the establishment of IPTable Rules, and the implementation of Fail2Ban. These measures collectively enhance the security posture by fortifying the SSH configuration, defining strict IP filtering rules, and providing protection against potential security threats through the proactive monitoring and banning of suspicious activities using Fail2Ban.

**_NOTE_**: Port numbers of SSH and OpenVPN can be edited through the main function (lines 339 and 340) by editing the `sshPort` and `openVPNPort` variables.

### 5. Creation of Client Keys and Certificates
The script prompts the client for essential information to facilitate the creation of their keys and certificates. Leveraging Easy-RSA, these keys and certificates enable clients to securely access the OpenVPN Server and establish a connection to the VPN service

### 6. Creation of Client Configuration
After generating the client's keys and certificates, the script proceeds to craft a configuration file tailored for the client's connection to the OpenVPN Server. This configuration file will be named after the client. Subsequently, this file is relocated to the `/tmp` folder, facilitating easy retrieval by the client through transfer methods like using `scp`.

### 7. Revoke Client Certificates
Utilizing `Easy-RSA`, the script initiates the revocation of the selected client's certificate, relocating it to the `revoked` folder. This process invalidates the previously signed certificate, rendering it unusable for authentication. Upon certificate revocation, a `crl.pem` file is generated, serving as a certificate revocation list (CRL) that enumerates the revoked certificates.

### 8. Revoke Client access to OpenVPN Server
After `crl.pem` has been created, its location will be linked with the `crl-verify` parameter within the server's configuration file. If a client uses a certificate that is found within this file, the client would be denied access to the OpenVPN Server.

## Part IIII: Connection
Before connecting to the OpenVPN Server, it is best for the client to Update and Upgrade the System by Running:
```
sudo apt update && sudo apt upgrade -y
```

For Clients who are using Linux Systems, Run the Following:
```
sudo apt install openvpn-systemd-resolved
```

This allows the Client's System to directly update the DNS settings of a link through `systemd-resolved` and use the pushed DNS Servers given by the OpenVPN Server.

Clients can connect to the OpenVPN Server by running:
```
sudo openvpn <openvpn config file>
```

To enable OpenVPN to Connect at StartUp:
```
sudo systemctl enable --now openvpn-client@<clientname>
```

**_NOTE_**: Make sure that Client Configuration is stored within `/etc/openvpn/client`.
# Required : 

> Rocky Linux 8
> 2 servers
> Network with public ip address and internet access
> ssh access

# Sshd config : 

## Connect with password to the Server

## open ssh port permanently : 

`firewall-cmd --add-port=22/tcp --permanent`

## Create user folder for ssh : 

`mkdir -p ~/myname/.ssh`

## Create authorized_keys file for ssh : 

`cd myname/.ssh`
`nano authorized_keys`

## Copy Paste your public key inside : 

create your ssh key using `ssh-keygen -b 4096` if you don't have one already


copy your existing id_rsa.pub and paste it inside authorized_keys

## add permissions

`cd`
`chown yourusername:yourusername /myname/.ssh`
`chmod 700 /myname/.ssh`
`chmod 600 /myname/.ssh/authorized_keys`

## sshd file config

Use this config to connect without password and connect only via SSH

```
#       $OpenBSD: sshd_config,v 1.104 2021/07/02 05:11:21 dtucker Exp $

# This is the sshd server system-wide configuration file.  See
# sshd_config(5) for more information.

# This sshd was compiled with PATH=/usr/local/bin:/usr/bin:/usr/local/sbin:/usr/sbin

# The strategy used for options in the default sshd_config shipped with
# OpenSSH is to specify options with their default value where
# possible, but leave them commented.  Uncommented options override the
# default value.

# To modify the system-wide sshd configuration, create a  *.conf  file under
#  /etc/ssh/sshd_config.d/  which will be automatically included below
Include /etc/ssh/sshd_config.d/*.conf

# If you want to change the port on a SELinux system, you have to tell
# SELinux about this change.
# semanage port -a -t ssh_port_t -p tcp #PORTNUMBER
#
#Port 22
#AddressFamily any
#ListenAddress 0.0.0.0
#ListenAddress ::

#HostKey /etc/ssh/ssh_host_rsa_key
#HostKey /etc/ssh/ssh_host_ecdsa_key
#HostKey /etc/ssh/ssh_host_ed25519_key

# Ciphers and keying
#RekeyLimit default none

# Logging
#SyslogFacility AUTH
#LogLevel INFO

# Authentication:

#LoginGraceTime 2m
#PermitRootLogin prohibit-password
#StrictModes yes
#MaxAuthTries 6
#MaxSessions 10

#PubkeyAuthentication yes

# The default is to check both .ssh/authorized_keys and .ssh/authorized_keys2
# but this is overridden so installations will only check .ssh/authorized_keys
AuthorizedKeysFile      .ssh/authorized_keys

#AuthorizedPrincipalsFile none

#AuthorizedKeysCommand none
#AuthorizedKeysCommandUser nobody

# For this to work you will also need host keys in /etc/ssh/ssh_known_hosts
#HostbasedAuthentication no
# Change to yes if you don't trust ~/.ssh/known_hosts for
# HostbasedAuthentication
#IgnoreUserKnownHosts no
# Don't read the user's ~/.rhosts and ~/.shosts files
#IgnoreRhosts yes

# To disable tunneled clear text passwords, change to no here!
#PasswordAuthentication no
#PermitEmptyPasswords no

# Change to no to disable s/key passwords
#KbdInteractiveAuthentication yes

# Kerberos options
#KerberosAuthentication no
#KerberosOrLocalPasswd yes
#KerberosTicketCleanup yes
#KerberosGetAFSToken no
#KerberosUseKuserok yes

# GSSAPI options
#GSSAPIAuthentication no
#GSSAPICleanupCredentials yes
#GSSAPIStrictAcceptorCheck yes
#GSSAPIKeyExchange no
#GSSAPIEnablek5users no

# Set this to 'yes' to enable PAM authentication, account processing,
# and session processing. If this is enabled, PAM authentication will
# be allowed through the KbdInteractiveAuthentication and
# PasswordAuthentication.  Depending on your PAM configuration,
# PAM authentication via KbdInteractiveAuthentication may bypass
# the setting of "PermitRootLogin without-password".
# If you just want the PAM account and session checks to run without
# PAM authentication, then enable this but set PasswordAuthentication
# and KbdInteractiveAuthentication to 'no'.
# WARNING: 'UsePAM no' is not supported in RHEL and may cause several
# problems.
#UsePAM no

#AllowAgentForwarding yes
#AllowTcpForwarding yes
#GatewayPorts no
#X11Forwarding no
#X11DisplayOffset 10
#X11UseLocalhost yes
#PermitTTY yes
#PrintMotd yes
#PrintLastLog yes
#TCPKeepAlive yes
#PermitUserEnvironment no
#Compression delayed
#ClientAliveInterval 0
#ClientAliveCountMax 3
#UseDNS no
#PidFile /var/run/sshd.pid
#MaxStartups 10:30:100
#PermitTunnel no
#ChrootDirectory none
#VersionAddendum none

# no default banner path
#Banner none

# override default of no subsystems
Subsystem       sftp    /usr/libexec/openssh/sftp-server

# Example of overriding settings on a per-user basis
#Match User anoncvs
#       X11Forwarding no
#       AllowTcpForwarding no
#       PermitTTY no
#       ForceCommand cvs server
```


# Partie Erwan : 

```
des prérequis (de votre choix)
des instructions d'installation
des instructions d'accès
```
* Project Organisation ( give directory Tree):


* Scripts (add instructions): 

    * génération serveur : 
 
          # !/bin/bash
            # 21/04/2023
            # script pour installer et lancer un nouveau server minecraft
            pseudo=${1}
            port=${2}
            if [[ -z "${1}" || -z "${2}" ]]; then
                echo "veuillez entrez toutes les informations demander. nom             de l'utilisateur et le port du serveur"
                exit 1
            fi
            cd /srv/projetleo/minecraftserver/serveur_client/
            if [[ -d '/srv/projetleo/minecraftserver/serveur_client/server_de_'${pseudo}'/' ]]
            then
                    echo ""${pseudo}" possede deja un server"
                    exit 1
            fi
            mkdir server_de_${pseudo}
            cp -rp /srv/projetleo/minecraftserver/servermcbase/* /srv/projetleo/minecraftserver/serveur_client/server_de_${pseudo}
            sed -i '48s/server-port=25565/server-port='${port}'/' /srv/projetleo/minecraftserver/serveur_client/server_de_${pseudo}/server.properties


    * Backup : 
         


    ```
     #!/bin/bash
        DATE=$(date '+%Y-%m-%d')
        mkdir /srv/projetleo/minecraftserver/backup/$DATE
        cp -r /srv/projetleo/minecraftserver/serveur_client/*                       /srv/projetleo/minecraftserver/backup/$DATE
    ```
    
    * Run Minecraft Server on different screens

    ```
    # !/bin/bash
    # 5/5/2023
    # script pour lancer serveur mincraft dans un screen


    cd /srv/projetleo/minecraftserver/serveur_client/server_de_${1}

    screen -dmS serveur_de_${1}

    sleep 1

    screen -S serveur_de_${1} -X stuff "java -Xmx2G -Xms1G -jar server.jar nogui^M"

    sleep 5

    screen -ls serveur_de_${1}
    ```
* Proxy Setup (need explaination)
* server.properties file setup (need explaination)
* Domain Name Buying tutorial 



# Setup OpenVPN Server on Rocky Linux 8 on the vpn Server ( server 2) :

## Install EPEL Repository

The latest OpenVPN packages is provided by the EPEL repositories on Rocky Linux 8 and other similar derivatives. EPEL can be installed on Rocky Linux 8 by running the command below;
```
dnf install epel-release -y
```
## Install OpenVPN on Rocky Linux 8

Once the EPEL repos are in place, you can now install OpenVPN package on Rocky Linux 8 by executing the command below;

`dnf install openvpn`

## Install Easy-RSA CA Utility on Rocky Linux 8

Easy-RSA package is a shell based CA utility that is used to generate SSL key-pairs that is used to secure VPN connections.

`dnf install easy-rsa`

## Create OpenVPN Public Key Infrastructure

### Initialize the PKI

Easy-RSA is used for PKI management. The Easy-RSA scripts are installed under the `/usr/share/easy-rsa` directory.

To ensure that Easy-RSA any configuration made is not overwritten in case of an upgrade, copy the scripts to a different directory, preferably under /etc directory.

```
mkdir /etc/easy-rsa
cp -air /usr/share/easy-rsa/3/* /etc/easy-rsa/

```

Once the scripts are in place, navigate to the directory and initialize the PKI.

```
cd /etc/easy-rsa/
./easyrsa init-pki
```

the output: 

```
init-pki complete; you may now create a CA or requests.
Your newly created PKI dir is: /etc/easy-rsa/pki
```

### Generate the Certificate Authority (CA) Certificate and Key

Next, generate the CA certificate and key that will be used to sign certificates by running the commands below within the Easy-RSA directory above.

`./easyrsa build-ca`

The CA file is `/etc/easy-rsa/pki/ca.crt.`

### Generate Diffie Hellman Parameters

While within the same Easy-RSA directory as in above, execute the command below to generate Diffie-Hellman key file that can be used for key exchange during the TLS handshake with connecting clients.

`./easyrsa gen-dh`

The command will take sometime to complete. It then stores the DH parameters on the `/etc/easy-rsa/pki/dh.pem` file.

### Generate OpenVPN Server Certificate and Key

To generate a certificate and private key for the OpenVPN server, run the command below;

```
cd /etc/easy-rsa
./easyrsa build-server-full server nopass
```
When the command runs, you will be prompted to enter the CA key passphrase create above.

nopass disables the use of passphrase in the certificates.

output : 

```
Using SSL: openssl OpenSSL 1.1.1g FIPS  21 Apr 2020
Generating a RSA private key
.....+++++
...............................+++++
writing new private key to '/etc/easy-rsa/pki/easy-rsa-10170.VLZsfK/tmp.4TRoOP'
-----
Using configuration from /etc/easy-rsa/pki/easy-rsa-10170.VLZsfK/tmp.jTJJ7f
Enter pass phrase for /etc/easy-rsa/pki/private/ca.key:
Check that the request matches the signature
Signature ok
```

### Generate Hash-based Message Authentication Code (HMAC) key

To generate TLS/SSL pre-shared authentication key that will be used to add an additional HMAC signature to all SSL/TLS handshake packets, to avoid DoS attack and UDP port flooding, run the command below;

`openvpn --genkey --secret /etc/easy-rsa/pki/ta.key`

### Generate a Revocation Certificate

In order to invalidate a previously signed certificate, you need to generate a revocation certificate.

`./easyrsa gen-crl`

output : 

```
Using SSL: openssl OpenSSL 1.1.1g FIPS  21 Apr 2020
Using configuration from /etc/easy-rsa/pki/easy-rsa-10284.mSzk9F/tmp.qdix0A
Enter pass phrase for /etc/easy-rsa/pki/private/ca.key:

An updated CRL has been created.
CRL file: /etc/easy-rsa/pki/crl.pe
```

The Revocation certificate is stored as `/etc/easy-rsa/pki/crl.pem`

### Copy Server Certificates and Keys to Server Directory

Next, copy all generated certificates/keys to OpenVPN server configuration directory.
```
cp -rp /etc/easy-rsa/pki/{ca.crt,dh.pem,ta.key,crl.pem,issued,private} /etc/openvpn/server/
```
## Configure OpenVPN Server on Rocky Linux 8

Copy the conf file to `/etc/openvpn/server/` and modify it to suit your needs.

`cp /usr/share/doc/openvpn/sample/sample-config-files/server.conf /etc/openvpn/server/`

Open the config for modification.

`vim /etc/openvpn/server/server.conf`

The file is highly commented. No need of the comments ! ^^

In the most basic form, below are our configuration options, with no comments.

```
port 1194
proto udp4
dev tun
ca ca.crt
cert issued/server.crt
key private/server.key  # This file should be kept secret
dh dh.pem
topology subnet
server 10.8.0.0 255.255.255.0
ifconfig-pool-persist ipp.txt
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 208.67.222.222"
push "dhcp-option DNS 192.168.10.3"
client-to-client
keepalive 10 120
tls-auth ta.key 0 # This file is secret
cipher AES-256-CBC
comp-lzo
user nobody
group nobody
persist-key
persist-tun
status /var/log/openvpn/openvpn-status.log
log-append  /var/log/openvpn/openvpn.log
verb 3
explicit-exit-notify 1
auth SHA512
```

Create log directory;

`mkdir /var/log/openvpn/`
Explore the configuration and do further fine tuning to suit your needs.

## Configure OpenVPN Server Routing

To ensure that traffic from the client is routed through the servers IP address (helps masks the the client IP address), you need to enable IP forwarding on the OpenVPN server;

`echo "net.ipv4.ip_forward = 1" >> /etc/sysctl.conf`
Run the command below to effect the changes without rebooting the server.

`sysctl --system`

Allow OpenVPN service port through firewall

```
firewall-cmd --add-port=1194/udp --permanent
Activate IP Masquerading
```

`firewall-cmd --add-masquerade --permanent`

Forward traffic received on the specified OpenVPN subnet, for example, the 10.8.0.0/24 in our case, to an interface via which packets are going to be sent.

To find the interface via which packets are sent through by running the command below;

`ip route get 8.8.8.8`
output :
```
8.8.8.8 via 10.0.2.2 dev enp0s3 src 10.0.2.15 uid 0 
    cache
```
The interface name and the subnet defined maybe different for your case. Replace them accordingly.

`firewall-cmd --permanent --direct --passthrough ipv4 -t nat -A POSTROUTING -s 10.8.0.0/24 -o enp0s3 -j MASQUERADE`
Reload firewalld for the changes to take effect.

`firewall-cmd --reload`
Start and set OpenVPN run on system boot.

`systemctl enable openvpn-server@server`

`systemctl start openvpn-server@server`

When OpenVPN service runs, it will create a tunnelling interface, tun0;

`ip add s`

output :

```
4: tun0: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UNKNOWN group default qlen 100
    link/none 
    inet 10.8.0.1/24 brd 10.8.0.255 scope global tun0
       valid_lft forever preferred_lft forever
    inet6 fe80::afd7:17a6:57ee:7f3b/64 scope link stable-privacy 
       valid_lft forever preferred_lft forever
```

*check logs*

```
tail /var/log/openvpn/openvpn.log
```
output : 
```
/sbin/ip addr add dev tun0 10.8.0.1/24 broadcast 10.8.0.255
Socket Buffers: R=[212992->212992] S=[212992->212992]
UDPv4 link local (bound): [AF_INET][undef]:1194
UDPv4 link remote: [AF_UNSPEC]
GID set to nobody
UID set to nobody
MULTI: multi_init called, r=256 v=256
IFCONFIG POOL: base=10.8.0.2 size=252, ipv6=0
IFCONFIG POOL LIST
Initialization Sequence Completed
```
Your OpenVPN Server is now up and running. That brings us to the end of our guide on how to install and setup OpenVPN Server on Rocky Linux 8.

You can now proceed to configure OpenVPN clients and interconnect them through the vpn server.


# Configure OpenVPN Client on Rocky Linux 8 on the client server (server 1) ! 

To be able to connect to OpenVPN server, you need to create the client’s configuration containing the CA certificate, the client server certificate and the key.

### Generate OpenVPN Client Certificate and Key

To generate OpenVPN clients certificate and private key, run the command below;

```
cd /etc/easy-rsa
./easyrsa build-client-full gentoo nopass
```
Sample output;

```
Using SSL: openssl OpenSSL 1.1.1g FIPS  21 Apr 2020
Generating a RSA private key
........................+++++
.........................................................................................+++++
writing new private key to '/etc/easy-rsa/pki/easy-rsa-10316.rcXRdS/tmp.tauo7u'
-----
Using configuration from /etc/easy-rsa/pki/easy-rsa-10316.rcXRdS/tmp.RxlTaw
Enter pass phrase for /etc/easy-rsa/pki/private/ca.key:
Check that the request matches the signature
Signature ok
The Subject's Distinguished Name is as follows
commonName            :ASN.1 12:'gentoo'
Certificate is to be certified until Oct  3 18:05:23 2023 GMT (825 days)

Write out database with 1 new entries
Data Base Updated
```

where **gentoo** is the name of the client for which the certificate and keys are generated. Always use a unique common name for each client that you are generating certificate and keys for.

### Copy Client Certificates and Keys to Client Directory
Create a directory for each client on OpenVPN client’s directory

`mkdir /etc/openvpn/client/gentoo`

Next, copy all client generated certificates/keys and CA certificate to OpenVPN client configuration directory. You can

`cp -rp /etc/easy-rsa/pki/{ca.crt,issued/gentoo.crt,private/gentoo.key} /etc/openvpn/client/gentoo`

A homemade script to generate automatically the security files needed for the config file later build for a client. 

It takes one argument : the name of the client  : 

```
[clem@faytest /]$ sudo cat /etc/openvpn/client/generate2.sh
[sudo] password for clem:
#!/usr/bin/expect

cd /

# Set the passphrase
set passphrase "test"

# Change to the Easy-RSA directory
cd /etc/easy-rsa

# Build client configuration using easyrsa
spawn ./easyrsa build-client-full [lindex $argv 0] nopass

# Wait for the passphrase prompt and provide the passphrase
expect "Enter pass phrase for /etc/easy-rsa/pki/private/ca.key:"
send "$passphrase\r"

# Interact with the spawned process
interact

# Create directory for client configuration
exec mkdir -p /etc/openvpn/client/[lindex $argv 0]

# Copy client configuration files to the directory
exec cp -rp /etc/easy-rsa/pki/ca.crt /etc/openvpn/client/[lindex $argv 0]
exec cp -rp /etc/easy-rsa/pki/issued/[lindex $argv 0].crt /etc/openvpn/client/[lindex $argv 0]
exec cp -rp /etc/easy-rsa/pki/private/[lindex $argv 0].key /etc/openvpn/client/[lindex $argv 0]
```
## Create Client Configuration

Before testing a client, we need to create configuration files for the client we will use.

Create the configuration file : 

`nano /etc/openvpn/client/base.conf`

you can edit yourself cause it depends of your preferences and the server.conf file

here is an example : 

```
client
tls-client
dev tun
proto udp4
remote 192.168.60.19 1194
resolv-retry infinite
nobind
#user nobody
#group nogroup
persist-key
persist-tun
key-direction 1
remote-cert-tls server
auth-nocache
comp-lzo
verb 3
auth SHA512
```

next insert the following files at the end of the base.conf : 
```
ta.key
ca.crt
gentoo.crt
gentoo.key
```

here the complete example : 

```
client
tls-client
pull
dev tun
proto udp4
remote 192.168.60.19 1194
resolv-retry infinite
nobind
#user nobody
#group nogroup
persist-key
persist-tun
key-direction 1
remote-cert-tls server
auth-nocache
comp-lzo
verb 3
auth SHA512
<tls-auth>
-----BEGIN OpenVPN Static key V1-----
feb1af5407baa247d4e772c76aed6c75
...
-----END OpenVPN Static key V1-----
</tls-auth>
<ca>
-----BEGIN CERTIFICATE-----
MIIDTjCCAjagAwIBAgIUX0VQrHTgLDabUUIOAf7tD9cGp4YwDQYJKoZIhvcNAQEL
...
WA9BBk2shVWfR849Lmkep+GPyqHpU47dZAz37ARB2Gfu3w==
-----END CERTIFICATE-----
</ca>
<cert>
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
...
/7FvJaeLqmUHnvSs5eBlRZSgtOL19SCFkG0HXdnw3LtBaoHQXxgzOkDPW1+5
-----END CERTIFICATE-----
</cert>
<key>
-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC+DI7kg6MsRoCs
...
6WdLcNtWKAcU294xJEZoOA8/
-----END PRIVATE KEY-----
</key>
```


or I made a script to make the xxx.ovpn files automatically : 

```
#!/bin/bash

cd /

# First argument: Client identifier

SERVER_DIR=/etc/openvpn/server
OUTPUT_DIR=/etc/openvpn/client/${1}
BASE_CONFIG=/etc/openvpn/client/base.conf

cat ${BASE_CONFIG} \
    <(echo -e '<tls-auth>') \
    ${SERVER_DIR}/ta.key \
    <(echo -e '</tls-auth>\n<ca>') \
    ${SERVER_DIR}/ca.crt \
    <(echo -e '</ca>\n<cert>') \
    ${OUTPUT_DIR}/${1}.crt \
    <(echo -e '</cert>\n<key>') \
    ${OUTPUT_DIR}/${1}.key \
    <(echo -e '</key>\n') \
    > ${OUTPUT_DIR}/${1}.ovpn

```

here the complete go programm to make the config file available to download on the web server : 
```
package handle

import (
        "forum/forum"
        "net/http"
        "fmt"
        "os/exec"
)


func DlConfServeurVpn(w http.ResponseWriter, r *http.Request) {
        session, err := forum.Store.Get(r, "forum")
        if err != nil {
                http.Error(w, err.Error(), http.StatusInternalServerError)
                return
        }
        pseudo, ok := session.Values["pseudo"].(string)
        if !ok {
                http.Redirect(w, r, "/connexion", http.StatusSeeOther)
                return
        }
        fmt.Println(" your user : " + pseudo)
        cmd := exec.Command("/bin/expect", "/srv/projetleo/minecraftserver/script/generate.exp", pseudo)

        output, err := cmd.CombinedOutput()
        if err != nil {
                fmt.Printf("Script execution failed with error: %v\nOutput: %s\n", err, output)
        } else {
                fmt.Printf("Script output: %s\n", output)
        }
        cmd = exec.Command("/bin/sh", "/srv/projetleo/minecraftserver/script/transferkey.sh", pseudo)
        output, err = cmd.CombinedOutput()
        if err != nil {
                fmt.Printf("Script execution failed with error: %v\nOutput:  %s\n", err, output)
        } else {
                fmt.Printf("Script output: %s\n", output)
        }
        cmd = exec.Command("/bin/sh", "/srv/projetleo/minecraftserver/script/make_config.sh", pseudo)
        output, err = cmd.CombinedOutput()
        if err != nil {
                fmt.Printf("Script execution failed with error: %v\nOutput:  %s\n", err, output)
        } else {
                fmt.Printf("Script output: %s\n", output)
        }
        referer := r.Header.Get("Referer")
        filePath := "/etc/openvpn/client/" + pseudo + "/" + pseudo + ".ovpn"
        fmt.Println("your filepath" + filePath)
        w.Header().Set("Content-Disposition", "attachment; filename="+pseudo+".ovpn")
        http.ServeFile(w, r, filePath)
        http.Redirect(w, r, referer, http.StatusFound)
}
```


## Connect to OpenVPN on Command Line 

### On Linux

`sudo openvpn client-config.ovpn`

or

`sudo openvpn --config client-config.ovpn`

Where client-config is the client’s openvpn configuration file, like gentoo.ovpn file above.

If the connection to the OpenVPN server is successful, you should see an Initialization Sequence Completed. 

```
Wed Jun 30 15:27:16 2021 OpenVPN 2.4.11 x86_64-redhat-linux-gnu [SSL (OpenSSL)] [LZO] [LZ4] [EPOLL] [PKCS11] [MH/PKTINFO] [AEAD] built on Apr 21 2021
Wed Jun 30 15:27:16 2021 library versions: OpenSSL 1.1.1g FIPS  21 Apr 2020, LZO 2.08
Wed Jun 30 15:27:16 2021 Outgoing Control Channel Authentication: Using 512 bit message hash 'SHA512' for HMAC authentication
Wed Jun 30 15:27:16 2021 Incoming Control Channel Authentication: Using 512 bit message hash 'SHA512' for HMAC authentication
Wed Jun 30 15:27:16 2021 TCP/UDP: Preserving recently used remote address: [AF_INET]192.168.60.19:1194
Wed Jun 30 15:27:16 2021 Socket Buffers: R=[212992->212992] S=[212992->212992]
Wed Jun 30 15:27:16 2021 UDPv4 link local: (not bound)
Wed Jun 30 15:27:16 2021 UDPv4 link remote: [AF_INET]192.168.60.19:1194
Wed Jun 30 15:27:16 2021 TLS: Initial packet from [AF_INET]192.168.60.19:1194, sid=7ec70642 fdcdad40
Wed Jun 30 15:27:16 2021 VERIFY OK: depth=1, CN=Kifarunix-demo CA
Wed Jun 30 15:27:16 2021 VERIFY KU OK
Wed Jun 30 15:27:16 2021 Validating certificate extended key usage
Wed Jun 30 15:27:16 2021 ++ Certificate has EKU (str) TLS Web Server Authentication, expects TLS Web Server Authentication
Wed Jun 30 15:27:16 2021 VERIFY EKU OK
Wed Jun 30 15:27:16 2021 VERIFY OK: depth=0, CN=server
Wed Jun 30 15:27:16 2021 WARNING: 'link-mtu' is used inconsistently, local='link-mtu 1586', remote='link-mtu 1602'
Wed Jun 30 15:27:16 2021 WARNING: 'cipher' is used inconsistently, local='cipher BF-CBC', remote='cipher AES-256-CBC'
Wed Jun 30 15:27:16 2021 WARNING: 'keysize' is used inconsistently, local='keysize 128', remote='keysize 256'
Wed Jun 30 15:27:16 2021 Control Channel: TLSv1.3, cipher TLSv1.3 TLS_AES_256_GCM_SHA384, 2048 bit RSA
Wed Jun 30 15:27:16 2021 [server] Peer Connection Initiated with [AF_INET]192.168.60.19:1194
Wed Jun 30 15:27:17 2021 SENT CONTROL [server]: 'PUSH_REQUEST' (status=1)
Wed Jun 30 15:27:17 2021 PUSH: Received control message: 'PUSH_REPLY,redirect-gateway def1 bypass-dhcp,dhcp-option DNS 208.67.222.222,dhcp-option DNS 192.168.10.3,route-gateway 10.8.0.1,topology subnet,ping 10,ping-restart 120,ifconfig 10.8.0.2 255.255.255.0,peer-id 0,cipher AES-256-GCM'
Wed Jun 30 15:27:17 2021 OPTIONS IMPORT: timers and/or timeouts modified
Wed Jun 30 15:27:17 2021 OPTIONS IMPORT: --ifconfig/up options modified
Wed Jun 30 15:27:17 2021 OPTIONS IMPORT: route options modified
Wed Jun 30 15:27:17 2021 OPTIONS IMPORT: route-related options modified
Wed Jun 30 15:27:17 2021 OPTIONS IMPORT: --ip-win32 and/or --dhcp-option options modified
Wed Jun 30 15:27:17 2021 OPTIONS IMPORT: peer-id set
Wed Jun 30 15:27:17 2021 OPTIONS IMPORT: adjusting link_mtu to 1625
Wed Jun 30 15:27:17 2021 OPTIONS IMPORT: data channel crypto options modified
Wed Jun 30 15:27:17 2021 Data Channel: using negotiated cipher 'AES-256-GCM'
Wed Jun 30 15:27:17 2021 Outgoing Data Channel: Cipher 'AES-256-GCM' initialized with 256 bit key
Wed Jun 30 15:27:17 2021 Incoming Data Channel: Cipher 'AES-256-GCM' initialized with 256 bit key
Wed Jun 30 15:27:17 2021 ROUTE_GATEWAY 10.0.2.2/255.255.255.0 IFACE=enp0s3 HWADDR=08:00:27:98:30:73
Wed Jun 30 15:27:17 2021 TUN/TAP device tun0 opened
Wed Jun 30 15:27:17 2021 TUN/TAP TX queue length set to 100
Wed Jun 30 15:27:17 2021 /sbin/ip link set dev tun0 up mtu 1500
Wed Jun 30 15:27:17 2021 /sbin/ip addr add dev tun0 10.8.0.2/24 broadcast 10.8.0.255
Wed Jun 30 15:27:17 2021 /sbin/ip route add 192.168.60.19/32 via 10.0.2.2
Wed Jun 30 15:27:17 2021 /sbin/ip route add 0.0.0.0/1 via 10.8.0.1
Wed Jun 30 15:27:17 2021 /sbin/ip route add 128.0.0.0/1 via 10.8.0.1
Wed Jun 30 15:27:17 2021 Initialization Sequence Completed
```
### On Windows : 

1. Download and Install OpenVpn Client Connect :

    from this link : :three_button_mouse: 

    https://openvpn.net/downloads/openvpn-connect-v3-windows.msi

    from access official website and click 'Download' button :three_button_mouse: : 

    https://openvpn.net/client-connect-vpn-for-windows/

2. Download your configuration file from our website :three_button_mouse: 


3. Open OpenVpn Client Connect : 

    *  click on the white cross in the bottom left corner   to create a new Vpn Client Profile :three_button_mouse: 
    *  click "File" option :three_button_mouse: 
    ![](https://i.imgur.com/3qjSeid.png)
    * click "Browse" button :three_button_mouse:
    * Find the config file you previously downloaded in your downloads folder and click to load it :open_file_folder: 
    * click "Connect" button (informations in picture are for testing only):three_button_mouse: 
    ![](https://i.imgur.com/Fy4me4f.png)
    * The connection with the VPN will be established wait for the loading :information_source: 
    * Now You're Connected :wink: 
![](https://i.imgur.com/HKmqubY.png)

## To check the IP addresses;

`ip add show tun0`

```
9: tun0: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UNKNOWN group default qlen 100
    link/none 
    inet 10.8.0.2/24 brd 10.8.0.255 scope global tun0
       valid_lft forever preferred_lft forever
    inet6 fe80::697:ce38:b852:540c/64 scope link stable-privacy 
       valid_lft forever preferred_lft forever

```

## Test connectivity to the VPN server

`ping 10.8.0.1 -c 3`

```
PING 10.8.0.1 (10.8.0.1) 56(84) bytes of data.
64 bytes from 10.8.0.1: icmp_seq=1 ttl=64 time=2.71 ms
64 bytes from 10.8.0.1: icmp_seq=2 ttl=64 time=2.42 ms
64 bytes from 10.8.0.1: icmp_seq=3 ttl=64 time=1.95 ms

--- 10.8.0.1 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 46ms
rtt min/avg/max/mdev = 1.952/2.362/2.713/0.316 ms
```

You should also be able to get internet access depending on your server routes setup.

## Running OpenVPN Client as Service



In order to establish connections automatically whenever the server reboots, you can enable OpenVPN client systemd service.

Before you can do this, change the extension of your VPN config file from .ovpn to .conf. Replace the file names accordingly.

```
cp gentoo.{ovpn,conf}

mv gentoo.conf /etc/openvpn/client
```

Next, disable SELinux (I dont recommend this though, -:));

`setenforce 0 && sed -i 's/=enforcing/=permissive/' /etc/selinux/config`

Start OpenVPN client systemd service. Replace the name gentoo with the name of your .conf configuration file.

`systemctl start openvpn-client@gentoo`

To check the status;

`systemctl status openvpn-client@gentoo`
-o :

```
● openvpn-client@gentoo.service - OpenVPN tunnel for gentoo
   Loaded: loaded (/usr/lib/systemd/system/openvpn-client@.service; disabled; vendor preset: disabled)
   Active: active (running) since Wed 2021-06-30 15:48:47 EDT; 12s ago
     Docs: man:openvpn(8)

https://community.openvpn.net/openvpn/wiki/Openvpn24ManPage
   https://community.openvpn.net/openvpn/wiki/HOWTO
Main PID: 39782 (openvpn)
Status: "Initialization Sequence Completed"
Tasks: 1 (limit: 11272)
Memory: 1.6M
CGroup: /system.slice/system-openvpn\x2dclient.slice/openvpn-client@gentoo.service
   └─39782 /usr/sbin/openvpn --suppress-timestamps --nobind --config gentoo.conf

Jun 30 15:48:48 localhost.localdomain openvpn[39782]: Incoming Data Channel: Cipher 'AES-256-GCM' initialized with 256 bit key
Jun 30 15:48:48 localhost.localdomain openvpn[39782]: ROUTE_GATEWAY 10.0.2.2/255.255.255.0 IFACE=enp0s3 HWADDR=08:00:27:98:30:73
Jun 30 15:48:48 localhost.localdomain openvpn[39782]: TUN/TAP device tun0 opened
Jun 30 15:48:48 localhost.localdomain openvpn[39782]: TUN/TAP TX queue length set to 100
Jun 30 15:48:48 localhost.localdomain openvpn[39782]: /sbin/ip link set dev tun0 up mtu 1500
Jun 30 15:48:48 localhost.localdomain openvpn[39782]: /sbin/ip addr add dev tun0 10.8.0.2/24 broadcast 10.8.0.255
Jun 30 15:48:48 localhost.localdomain openvpn[39782]: /sbin/ip route add 192.168.60.19/32 via 10.0.2.2
Jun 30 15:48:48 localhost.localdomain openvpn[39782]: /sbin/ip route add 0.0.0.0/1 via 10.8.0.1
Jun 30 15:48:48 localhost.localdomain openvpn[39782]: /sbin/ip route add 128.0.0.0/1 via 10.8.0.1
Jun 30 15:48:48 localhost.localdomain openvpn[39782]: Initialization Sequence Completed
```
To enable it to run on system boot;

`systemctl enable openvpn-client@gentoo`

You have successfully installed and setup OpenVPN client Rocky Linux 8.

That brings us to the end of our tutorial on how to install and configure OpenVPN Client on Rocky Linux 8.

# Setup Webserver
## Nginx
allows to launch the process and configure nginx

```sudo dnf install nginx```

```sudo nano conf.d```

### HTTP server block (port 80)
server {
    listen 80;
    server_name erwan.fun www.erwan.fun;

    location / {
        proxy_pass http://localhost:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}

### HTTPS server block (port 443)
server {
    listen 443 ssl;
    server_name erwan.fun www.erwan.fun;

    ssl_certificate /etc/letsencrypt/live/erwan.fun/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/erwan.fun/privkey.pem;

    location / {
        proxy_pass http://localhost:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}

```sudo systemctl restart nginx```

## Running web server permanently : 

### Creating a Systemd Unit File

In this step, you will create a systemd unit file to keep your application running in the background even when a user logs out of the server. This will make your application persistent, bringing you one step closer to a production-grade deployment.


```mkdir $GOPATH/go-web```

```cd ~/go-web```

```git clone https://github.com/erxide/sandboxlinux.git```

```go build server.go```


```sudo nano /lib/systemd/system/goweb.service```

```
[Unit]
Description=goweb

[Service]
Type=simple
Restart=always
RestartSec=5s
User = minecraft
Group = minecraft
WorkingDirectory=/srv/projetleo/webserver/sandboxlinux
ExecStart=/srv/projetleo/webserver/sandboxlinux/server

[Install]
WantedBy=multi-user.target
```

## Solve se linux problems to make the service work

```sudo chcon -t bin_t /srv/projetleo/webserver/sandboxlinux/server```



## allows you to have a security certificate for the website

 ```sudo certbot --standalone certonly -d erwan.fun```

`ssl_certificate /etc/letsencrypt/live/erwan.fun/fullchain.pem;
ssl_certificate_key /etc/letsencrypt/live/erwan.fun/privkey.pem;`

## Allows you to open the ports necessary for the operation of the site

```sudo firewall-cmd --add-port=443/tcp --permanent```

```sudo firewall-cmd --add-port=80/tcp --permanent```

```sudo firewall-cmd --reload```

## allows secure authentication of user accounts (fail2ban)

```sudo nano /etc/fail2ban/jail.d/nginx-http-auth.conf```

```
[nginx-http-auth]
enabled = true
banaction = firewallcmd-ipset
maxretry = 3
findtime = 60
bantime = 600
filter = nginx-http-auth
logpath = /var/log/nginx/*error.log
port = https
```

```sudo systemctl restart fail2ban```

here are the tutorials to use

Chatgpt

https://www.digitalocean.com/community/tutorials/how-to-deploy-a-go-web-application-using-nginx-on-ubuntu-18-04

https://www.digitalocean.com/community/tutorials/how-to-secure-nginx-with-let-s-encrypt-on-ubuntu-18-04

Tutorial OpenVpn : 

https://kifarunix.com/install-and-configure-openvpn-client-on-rocky-linux-8/
https://kifarunix.com/setup-openvpn-server-on-rocky-linux-8/
https://www.howtoforge.com/how-to-install-and-configure-openvpn-server-on-rocky-linux-9/#step-7---generate-a-client-certificate-and-key-pair






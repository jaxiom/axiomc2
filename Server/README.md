
### Server Basic Usage

```bat
.\run-server.bat
```

This will start the Server on 127.0.0.1:5000

### CLI Basic Usage

```bat
.\run-cli.bat
```

```raw
> help

help    : print this info
agents  : agents information
quit    : exit from the console

> agents

agents > list

--------------------------------------------------
                No agents
--------------------------------------------------
agents > help

list    : list all agents
use     : connect to a specific agent
help    : print this info
back    : go back to the main menu
quit    : same as back

```

To interact with an Agent use the following:

```raw
agents > use [agent_id]
```

Then you can type help and provide the Agent commands to run.
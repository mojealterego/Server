#!/usr/bin/env python3
"""OMEGA-X local offline environment audit; no privileged commands or benchmarks."""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import platform
import shutil
import socket
import sys


def memory_available_mb()->int|None:
    try:
        for line in Path('/proc/meminfo').read_text().splitlines():
            if line.startswith('MemAvailable:'):
                return int(line.split()[1])//1024
    except (OSError,ValueError,IndexError):pass
    return None


def doctor(model_dir:Path)->dict:
    android=Path('/system/build.prop').exists() or os.environ.get('PREFIX','').startswith('/data/data/com.termux')
    tools={name:shutil.which(name) for name in ('python3','rclone','ssh-keygen','htpasswd','llama-server','flock','ffprobe')}
    dirs={}
    for name,path in {'model_store':model_dir,'node_state':Path.home()/'omega-node',
                      'hmac_state':Path.home()/'.omega-x'}.items():
        dirs[name]={'path':str(path),'exists':path.is_dir(),'is_symlink':path.is_symlink(),
                    'readable':os.access(path,os.R_OK) if path.exists() else False}
    files=[]
    if model_dir.is_dir() and not model_dir.is_symlink():
        for p in sorted(model_dir.iterdir(),key=lambda x:x.name.casefold()):
            if p.is_file() and not p.is_symlink() and p.suffix.lower() in {'.gguf','.safetensors','.onnx','.task'}:
                files.append({'name':p.name,'size_bytes':p.stat().st_size})
    free=None
    try:free=shutil.disk_usage(model_dir if model_dir.is_dir() else Path.home()).free
    except OSError:pass
    affinity=sorted(os.sched_getaffinity(0)) if hasattr(os,'sched_getaffinity') else None
    listening={}
    for service,port in {'sftp':2022,'webdav':8081,'llm':8082}.items():
        with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as s:
            s.settimeout(.25)
            listening[service]=(s.connect_ex(('127.0.0.1',port))==0)
    return {'schema':'omega.doctor.v2','environment':'ANDROID_TERMUX' if android else 'LINUX_HOST_OR_SIMULATOR',
            'machine':platform.machine(),'python':platform.python_version(),'binaries':tools,
            'storage':dirs,'available_memory_mb':memory_available_mb(),
            'free_storage_bytes':free,'process_allowed_cpus':affinity,
            'models':files,'listening_ports_only':listening,
            'limitations':['Port listening is not authentication E2E','Model names are not proof of model identity',
                           'CPU affinity indices are device-specific','No GPU/NPU inference or filesystem performance is benchmarked']}


def main()->int:
    p=argparse.ArgumentParser()
    p.add_argument('--model-dir',type=Path,default=Path(os.environ.get('OMEGA_MODEL_DIR',str(Path.home()/'storage/shared/1.GGUF-UNCENSORED'))))
    p.add_argument('--json-out',type=Path)
    p.add_argument('--strict',action='store_true',help='Return nonzero if rclone or SSH keygen missing')
    a=p.parse_args()
    result=doctor(a.model_dir)
    data=json.dumps(result,indent=2,ensure_ascii=False)+'\n'
    if a.json_out:
        a.json_out.parent.mkdir(parents=True,exist_ok=True)
        a.json_out.write_text(data,encoding='utf-8')
    print(data,end='')
    if a.strict and (not result['binaries']['rclone'] or not result['binaries']['ssh-keygen']):return 2
    return 0

if __name__=='__main__':sys.exit(main())

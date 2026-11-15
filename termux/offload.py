#!/usr/bin/env python3
"""Submit a model-specific media job to the VPS queue using pinned-host-key Rclone SFTP.

Does not execute a model locally, upload model weights, or expose an HTTP endpoint.
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys

JOB_ID=re.compile(r'^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$')
REMOTE=re.compile(r'^[A-Za-z][A-Za-z0-9_-]*:[A-Za-z0-9_./-]+$')
SLOTS={'wan':('diffusion_model','t5xxl','vae'),
       'ltx2':('diffusion_model','llm','embeddings_connectors','vae')}
MODEL_EXT={'.safetensors','.gguf','.sft'}


def validate_submission(job:dict)->str:
    if not isinstance(job,dict) or not JOB_ID.fullmatch(str(job.get('id',''))):
        raise ValueError('Invalid media job id')
    slots=SLOTS.get(job.get('engine'))
    if slots is None:raise ValueError('Unsupported media engine')
    prompt=job.get('prompt')
    if not isinstance(prompt,str) or not (1<=len(prompt)<=4096):
        raise ValueError('Invalid prompt length')
    for field in slots:
        name=job.get(field)
        if not isinstance(name,str) or Path(name).name!=name or name in ('','.','..') or '\\' in name or '\n' in name or Path(name).suffix.lower() not in MODEL_EXT:
            raise ValueError('Invalid model filename in '+field)
    keys={'id','engine','prompt','steps','width','height','frames','fps','audio_vae',*slots}
    if set(job)-keys:raise ValueError('Unsupported job fields')
    if job.get('audio_vae') is not None and job['engine']!='ltx2':raise ValueError('audio_vae only for ltx2')
    for field,(low,high) in {'steps':(1,100),'width':(64,2048),'height':(64,2048),'frames':(2,257),'fps':(1,60)}.items():
        if field in job and (type(job[field]) is not int or not low<=job[field]<=high):
            raise ValueError('Invalid '+field)
    if any(job.get(x,512)%16 for x in ('width','height')):raise ValueError('Dimensions must be multiples of 16')
    return job['id']


def validate_remote(remote:str)->str:
    if not REMOTE.fullmatch(remote) or '..' in remote:
        raise ValueError('Use named VPS SFTP remote and safe subdirectory')
    return remote


def submit(job_path:Path, remote:str, *,rclone:str='rclone',timeout:int=120)->str:
    if job_path.is_symlink() or not job_path.is_file() or job_path.stat().st_size>64*1024:
        raise ValueError('Job JSON missing, symlink or oversized')
    job=json.loads(job_path.read_text(encoding='utf-8'))
    jobid=validate_submission(job)
    remote=validate_remote(remote)
    if not shutil.which(rclone):raise RuntimeError('rclone missing')
    name=remote.split(':',1)[0]
    result=subprocess.run([rclone,'config','show',name],capture_output=True,text=True,timeout=15)
    if result.returncode!=0:raise RuntimeError('Rclone named remote not configured')
    config=result.stdout
    if not re.search(r'^type\s*=\s*sftp\s*$',config,re.MULTILINE):
        raise RuntimeError('Only a direct SFTP queue remote is accepted')
    if not re.search(r'^(known_hosts_file|host_keys)\s*=\s*\S+',config,re.MULTILINE):
        raise RuntimeError('SFTP host key pinning missing (known_hosts_file or host_keys)')
    dst=remote.rstrip('/')+'/'+jobid+'.json'
    result=subprocess.run([rclone,'copyto',str(job_path),dst,'--immutable'],
                          capture_output=True,text=True,timeout=timeout)
    if result.returncode!=0:raise RuntimeError('SFTP job submission failed; remote state must be inspected')
    return dst


def main()->int:
    p=argparse.ArgumentParser(description='OMEGA-X authenticated remote video queue submission')
    p.add_argument('job',type=Path)
    p.add_argument('--remote',required=True,help='e.g. vps-sftp:queue/pending')
    p.add_argument('--timeout',type=int,default=120)
    a=p.parse_args()
    try:
        if not 1<=a.timeout<=3600:raise ValueError('Timeout must be 1..3600 seconds')
        print('SUBMITTED_TO_SFTP_QUEUE '+submit(a.job,a.remote,timeout=a.timeout))
        return 0
    except (ValueError,RuntimeError,OSError,json.JSONDecodeError,subprocess.SubprocessError) as exc:
        print('OFFLOAD FAILED: '+str(exc),file=sys.stderr)
        return 1

if __name__=='__main__':sys.exit(main())

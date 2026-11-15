#!/usr/bin/env python3
"""OMEGA-X media queue worker for an installed stable-diffusion.cpp `sd-cli`.

No simulated successes: only marks jobs completed if sd-cli exits successfully
and writes a nonempty artifact. Optional ffprobe validates decodability.
Models/binaries are supplied externally; no GPU is assumed to exist on VPS.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time
from typing import Any

ID_RE=re.compile(r'^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$')
MODEL_EXTS={'.gguf','.safetensors','.sft'}
ENGINE_SLOTS={
    'wan':('diffusion_model','t5xxl','vae'),
    'ltx2':('diffusion_model','llm','embeddings_connectors','vae'),
}
CLI_FLAGS={'diffusion_model':'--diffusion-model','t5xxl':'--t5xxl',
           'vae':'--vae','llm':'--llm','embeddings_connectors':'--embeddings-connectors',
           'audio_vae':'--audio-vae'}


def _model_path(root:Path, name:str)->Path:
    if not isinstance(name,str) or '/' in name or '\\' in name or name in ('','.','..'):
        raise ValueError('Model reference must be a single safe filename')
    path=root/name
    if path.suffix.lower() not in MODEL_EXTS or path.is_symlink() or not path.is_file():
        raise ValueError(f'Missing or unsafe model file: {name}')
    if not path.resolve().is_relative_to(root.resolve()):
        raise ValueError('Model path traversal')
    return path


def validate_job(job:dict[str,Any],models:Path)->dict[str,Any]:
    if not isinstance(job,dict) or not ID_RE.fullmatch(str(job.get('id',''))):
        raise ValueError('Invalid job id')
    allowed={'id','engine','prompt','steps','width','height','frames','fps',
             'diffusion_model','t5xxl','vae','llm','embeddings_connectors','audio_vae'}
    extras=set(job)-allowed
    if extras:
        raise ValueError('Unsupported job fields: '+', '.join(sorted(extras)))
    engine=job.get('engine')
    if engine not in ENGINE_SLOTS:
        raise ValueError('Unsupported engine (wan/ltx2)')
    prompt=job.get('prompt')
    if not isinstance(prompt,str) or not (1<=len(prompt)<=4096):
        raise ValueError('Prompt must be 1..4096 characters')
    vals={}
    for key in ENGINE_SLOTS[engine]:
        vals[key]=_model_path(models,job.get(key))
    if engine=='ltx2' and 'audio_vae' in job:
        vals['audio_vae']=_model_path(models,job['audio_vae'])
    numeric={'steps':(1,100,20),'width':(64,2048,512),'height':(64,2048,512),
             'frames':(2,257,17),'fps':(1,60,24)}
    params={}
    for k,(lo,hi,default) in numeric.items():
        val=job.get(k,default)
        if type(val) is not int or not lo<=val<=hi:
            raise ValueError(f'Invalid {k}: expected integer {lo}..{hi}')
        params[k]=val
    if params['width']%16 or params['height']%16:
        raise ValueError('Width and height must be multiples of 16')
    return {'id':job['id'],'engine':engine,'prompt':prompt,'models':vals,'params':params}


def build_command(sd_cli:Path, validated:dict,output:Path,backend:str='cpu')->list[str]:
    if backend not in {'cpu','cuda0','vulkan0','hip0'}:
        raise ValueError('Unsupported backend selection')
    params=validated['params']
    cmd=[str(sd_cli)]
    for key,model in validated['models'].items():
        cmd += [CLI_FLAGS[key],str(model)]
    cmd += ['--mode','vid_gen','-p',validated['prompt'],'--steps',str(params['steps']),
            '-W',str(params['width']),'-H',str(params['height']),
            '--video-frames',str(params['frames']),'--fps',str(params['fps']),
            '--backend',backend,'-o',str(output)]
    return cmd


def enqueue(queue:Path,job:dict)->Path:
    """Durable job submission; ID reservation survives worker crash/restart.

    Reservation files intentionally remain after completion: idempotency keys are
    never re-used implicitly. Operations are scoped to a trusted local queue FS.
    """
    queue=Path(queue)
    if not isinstance(job,dict) or not ID_RE.fullmatch(str(job.get('id',''))):
        raise ValueError('Invalid job id')
    encoded=(json.dumps(job,ensure_ascii=False,sort_keys=True,separators=(',',':'))+'\n').encode('utf-8')
    if len(encoded)>64*1024:
        raise ValueError('Job payload exceeds 64 KiB')
    for folder in ('pending','running','failed','completed','outputs','staging','ids'):
        directory=queue/folder
        if directory.is_symlink():raise ValueError('Unsafe queue directory')
        directory.mkdir(parents=True,exist_ok=True)
    if len(list((queue/'pending').glob('*.json'))) >= 64:
        raise RuntimeError('Queue capacity reached (64 pending jobs)')
    jobid=job['id']
    # Guard migration from older queues that predate durable ID reservations.
    for folder in ('pending','running','failed','completed'):
        if (queue/folder/f'{jobid}.json').exists():
            raise FileExistsError('Job identifier exists in a legacy queue state')
    # Atomic O_EXCL is the idempotency barrier, including between workers.
    reserve=queue/'ids'/jobid
    fd=os.open(reserve,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600)
    try:
        with os.fdopen(fd,'wb') as handle:
            handle.write(hashlib.sha256(encoded).hexdigest().encode('ascii'))
            handle.flush();os.fsync(handle.fileno())
        staging=queue/'pending'
        fd,tmp=tempfile.mkstemp(prefix='.job-',dir=staging)
        try:
            with os.fdopen(fd,'wb') as handle:
                os.fchmod(handle.fileno(),0o600)
                handle.write(encoded)
                handle.flush();os.fsync(handle.fileno())
            final=staging/f'{jobid}.json'
            os.link(tmp,final)
            dirfd=os.open(staging,os.O_RDONLY|os.O_DIRECTORY)
            try:os.fsync(dirfd)
            finally:os.close(dirfd)
            return final
        finally:
            Path(tmp).unlink(missing_ok=True)
    except Exception:
        # Preserve ID reservation on crash/uncertainty; manual recovery only.
        raise


def recover_interrupted(queue:Path)->int:
    """Fail-closed restart recovery; do not re-run costly jobs without approval."""
    queue=Path(queue)
    for folder in ('running','failed','outputs'):
        (queue/folder).mkdir(parents=True,exist_ok=True)
    count=0
    for path in sorted((queue/'running').glob('*.json')):
        if not ID_RE.fullmatch(path.stem) or path.is_symlink():
            continue
        final=queue/'failed'/path.name
        if final.exists():
            continue
        status={'id':path.stem,'state':'FAILED_INTERRUPTED',
                'error':'Worker exited before writing completion; manual retry with a new job id required'}
        _write_record(queue/'outputs'/f'{path.stem}.status.json',status)
        path.rename(final)
        count+=1
    return count


def _write_record(path:Path,record:dict):
    fd,tmp=tempfile.mkstemp(prefix='.record-',dir=path.parent)
    try:
        with os.fdopen(fd,'w',encoding='utf-8') as file:
            os.fchmod(file.fileno(),0o600)
            file.write(json.dumps(record,ensure_ascii=False,sort_keys=True,indent=2)+'\n')
            file.flush();os.fsync(file.fileno())
        Path(tmp).replace(path)
        parentfd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY)
        try:os.fsync(parentfd)
        finally:os.close(parentfd)
    finally:Path(tmp).unlink(missing_ok=True)


def _probe_video(path:Path)->bool:
    ffprobe=shutil.which('ffprobe')
    if not ffprobe:
        return False
    try:
        result=subprocess.run([ffprobe,'-v','error','-select_streams','v:0',
                               '-show_entries','stream=codec_name','-of','default=nw=1',str(path)],
                              capture_output=True,text=True,timeout=30,check=False)
        return result.returncode==0 and 'codec_name=' in result.stdout
    except (OSError,subprocess.SubprocessError):
        return False


def run_once(queue:Path,models:Path,sd_cli:Path,*,timeout:int=3600,
             backend:str='cpu',verify_media:bool=False)->dict[str,Any]|None:
    queue=Path(queue)
    for folder in ('pending','running','completed','failed','outputs','staging'):
        (queue/folder).mkdir(parents=True,exist_ok=True)
    files=sorted((queue/'pending').glob('*.json'))
    if not files:
        return None
    source=files[0]
    if source.is_symlink() or source.stat().st_size>64*1024:
        # Never parse an untrusted symlink or oversized JSON file.
        raise ValueError('Unsafe or oversized pending job file')
    if not ID_RE.fullmatch(source.stem):
        raise ValueError('Invalid pending job filename')
    running=queue/'running'/source.name
    if running.exists() or running.is_symlink():
        raise FileExistsError('Running job already exists')
    try:
        source.rename(running)
    except FileNotFoundError:
        return None
    id=running.stem
    record={'id':id,'started_utc':int(time.time()),'state':'RUNNING'}
    output=queue/'outputs'/f'{id}.avi'
    staging=queue/'staging'/f'{id}.avi' 
    try:
        if output.exists() or output.is_symlink() or staging.exists() or staging.is_symlink():
            raise ValueError('Output or staging path already exists: refusing overwrite')
        job=json.loads(running.read_text(encoding='utf-8'))
        if job.get('id')!=id:
            raise ValueError('Job ID mismatch to filename')
        valid=validate_job(job,Path(models))
        if not Path(sd_cli).is_file() or not os.access(sd_cli,os.X_OK):
            raise RuntimeError('sd-cli missing or not executable; install backend first')
        command=build_command(sd_cli,valid,staging,backend)
        log_path=queue/'outputs'/f'{id}.log'
        with log_path.open('wb') as log:
            result=subprocess.run(command,stdin=subprocess.DEVNULL,
                                  stdout=log,stderr=subprocess.STDOUT,
                                  timeout=timeout,check=False)
        if result.returncode!=0:
            raise RuntimeError(f'sd-cli returned status {result.returncode}; see {log_path.name}')
        if not staging.is_file() or staging.stat().st_size==0 or staging.is_symlink():
            raise RuntimeError('sd-cli did not create a nonempty media artifact')
        verified=_probe_video(staging)
        if verify_media and not verified:
            raise RuntimeError('ffprobe video-stream validation failed or unavailable')
        size=staging.stat().st_size
        digest=_hash_file(staging)
        # Publish only the fully validated output from a staging location on the same FS.
        staging.replace(output)
        record.update(output=str(output),size_bytes=size,
                      sha256=digest,media_verified=verified)
        record['state']='COMPLETED'
        target=queue/'completed'/running.name
    except (ValueError,OSError,RuntimeError,subprocess.SubprocessError,KeyError) as exc:
        record['state']='FAILED'
        record['error']=str(exc)[:500]
        target=queue/'failed'/running.name
    # Preserve any failed partially-rendered artifact under staging, never as final output.
    record['finished_utc']=int(time.time())
    _write_record(queue/'outputs'/f'{id}.status.json',record)
    running.rename(target)
    return record


def _hash_file(path:Path)->str:
    digest=hashlib.sha256()
    with path.open('rb') as src:
        for block in iter(lambda:src.read(1024*1024),b''):
            digest.update(block)
    return digest.hexdigest()


def main()->int:
    parser=argparse.ArgumentParser()
    sub=parser.add_subparsers(dest='cmd',required=True)
    run=sub.add_parser('serve')
    run.add_argument('--queue',type=Path,default=Path('/data/queue'))
    run.add_argument('--models',type=Path,default=Path('/models'))
    run.add_argument('--sd-cli',type=Path,default=Path('/engine/sd-cli'))
    run.add_argument('--backend',default='cpu')
    run.add_argument('--timeout',type=int,default=3600)
    run.add_argument('--poll',type=float,default=3.0)
    run.add_argument('--verify-media',action='store_true')
    enqueue_cmd=sub.add_parser('enqueue')
    enqueue_cmd.add_argument('json_file',type=Path)
    enqueue_cmd.add_argument('--queue',type=Path,default=Path('/data/queue'))
    args=parser.parse_args()
    if args.cmd=='enqueue':
        if args.json_file.stat().st_size>64*1024:
            raise ValueError('Job file too large')
        print(enqueue(args.queue,json.loads(args.json_file.read_text())))
        return 0
    if args.timeout<=0 or not 0.1<=args.poll<=120:
        parser.error('Invalid timeout/poll')
    if not args.sd_cli.is_file() or not os.access(args.sd_cli,os.X_OK):
        print(f'FATAL: real sd-cli is missing/not executable: {args.sd_cli}',file=sys.stderr)
        return 3
    if not args.models.is_dir():
        print(f'FATAL: model directory not mounted: {args.models}',file=sys.stderr)
        return 3
    import fcntl
    lock_path=args.queue/'.worker.lock'
    lock_path.parent.mkdir(parents=True,exist_ok=True)
    lock=lock_path.open('a+')
    try:
        fcntl.flock(lock.fileno(),fcntl.LOCK_EX|fcntl.LOCK_NB)
    except BlockingIOError:
        print('FATAL: another worker owns this queue',file=sys.stderr)
        return 4
    recovered=recover_interrupted(args.queue)
    print(f'OMEGA media worker running; real backend checked; interrupted jobs={recovered}',flush=True)
    while True:
        result=run_once(args.queue,args.models,args.sd_cli,timeout=args.timeout,
                        backend=args.backend,verify_media=args.verify_media)
        if result:
            print(json.dumps(result,ensure_ascii=False),flush=True)
        else:
            time.sleep(args.poll)

if __name__=='__main__':
    try:sys.exit(main())
    except KeyboardInterrupt:sys.exit(130)

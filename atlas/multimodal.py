"""Typed, single-host PHASESHIFT recipes and verified CAS handoffs.

Operator supplies trusted recipes and deployment. No generated commands or
implicit network export. Profile support is not proof of model compatibility.
"""
from __future__ import annotations
import hashlib
from fractions import Fraction
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time
from .artifacts import ArtifactStore, _open_regular, _check_unchanged, _check_digest, _private_dir

ROOT = Path(__file__).resolve().parents[1]
KINDS = {'qwen_text': '.txt', 'flux1': '.png', 'wan_t2v': '.avi', 'wan_i2v': '.avi', 'ltx2': '.avi'}
SLOTS = {'flux1': {'diffusion_model':'image_dit','clip_l':'clip_l','t5xxl':'t5xxl','vae':'vae'},
         'wan_t2v': {'diffusion_model':'video_dit','t5xxl':'t5xxl','vae':'vae'},
         'wan_i2v': {'diffusion_model':'video_dit','t5xxl':'t5xxl','vae':'vae'},
         'ltx2': {'diffusion_model':'video_dit','llm':'llm','embeddings_connectors':'embeddings_connectors','vae':'vae'}}
FLAGS = {'diffusion_model':'--diffusion-model','clip_l':'--clip_l','t5xxl':'--t5xxl',
         'vae':'--vae','llm':'--llm','embeddings_connectors':'--embeddings-connectors','audio_vae':'--audio-vae'}
FAMILY = {'flux1':'flux1','wan_t2v':'wan','wan_i2v':'wan','ltx2':'ltx2'}
ID = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z')
MAX_OUTPUT = 16*1024**3

class PipelineError(ValueError):
    pass


def require(ok, message):
    if not ok: raise PipelineError(message)


def bounded_int(n,low,high): return type(n) is int and low<=n<=high


def prompt_text(s,media=False):
    require(isinstance(s,str) and 1<=len(s)<=(4096 if media else 8192) and '\x00' not in s and s.strip(), 'Invalid prompt')
    if media: require(not s.lstrip().startswith('-'), 'Option-like media prompt refused')
    return s


def dimensions(r,kind):
    require(bounded_int(r.get('width'),64,2048) and bounded_int(r.get('height'),64,2048) and r['width']%16==r['height']%16==0,'Invalid media dimensions')
    require(bounded_int(r.get('steps'),1,100),'Invalid steps')
    if kind!='flux1':
        require(bounded_int(r.get('frames'),2,257) and bounded_int(r.get('fps'),1,60),'Invalid video parameters')


def validate_recipes(tasks,catalog,assignments,*,allow_cross_node=False):
    """Validate the complete recipe DAG before any engine runs.

    LeaseStore separately verifies the PHASESHIFT certificate. Local dispatch
    explicitly refuses cross-node edges, even when remote data looks available.
    """
    require(isinstance(tasks,list) and 1<=len(tasks)<=24,'Invalid task count')
    by_id={};visiting=set();seen=set();ordered=[]
    for t in tasks:
        require(isinstance(t,dict) and isinstance(t.get('id'),str) and ID.fullmatch(t['id']) and t['id'] not in by_id,'Invalid or duplicate task ID')
        by_id[t['id']]=t
    require(set(assignments)==set(by_id),'Incomplete assignments')
    for t in tasks:
        r=t.get('recipe');require(isinstance(r,dict) and r.get('kind') in KINDS,'Unsupported recipe')
        kind=r['kind']; media=kind!='qwen_text'
        allowed={'kind','prompt','prompt_from'} | ({'slots','width','height','steps'} if media else {'runtime_model','max_tokens'})
        if kind in ('wan_t2v','wan_i2v','ltx2'): allowed|={'frames','fps'}
        if kind=='wan_i2v': allowed.add('image_from')
        require(set(r)<=allowed,'Unexpected recipe fields')
        require(('prompt' in r)!=('prompt_from' in r),'Exactly one prompt source required')
        if 'prompt' in r:prompt_text(r['prompt'],media)
        deps=t.get('depends_on',[])
        require(isinstance(deps,list) and all(isinstance(x,str) and x in by_id for x in deps) and len(set(deps))==len(deps),'Invalid dependencies')
        inputs=set()
        for name,suffix in [('prompt_from','.txt'),('image_from','.png')]:
            if name in r:
                ref=r[name];require(isinstance(ref,str) and ref in deps and ref!=t['id'],'Input must be a declared dependency')
                upstream=by_id[ref].get('recipe',{});require(isinstance(upstream,dict) and KINDS.get(upstream.get('kind'))==suffix,'Incompatible dependency modality')
                inputs.add(ref)
        require(set(deps)==inputs,'Unused dependency refused')
        require(allow_cross_node or all(assignments[d]['node']==assignments[t['id']]['node'] for d in deps),'Cross-node handoff requires distributed dispatch, not this local runner')
        require(bounded_int(t.get('output_bytes'),1,MAX_OUTPUT),'Invalid output budget')
        models=t.get('models');require(isinstance(models,list) and models and all(isinstance(x,str) and x in catalog for x in models) and len(models)==len(set(models)),'Invalid model list')
        if not media:
            require(t['engine']=='llama' and len(models)==1,'Qwen text requires one llama model')
            key=r.get('runtime_model');require(isinstance(key,str) and 1<=len(key)<=256 and not any(ord(c)<32 for c in key),'Invalid runtime model ID')
            bindings=t.get('runtime_model_ids');require(isinstance(bindings,dict) and bindings.get(key)==models[0],'Missing runtime model binding')
            require(catalog[models[0]].get('family')=='qwen' and catalog[models[0]].get('role') in ('llm','vlm'),'Not a declared Qwen language model')
            require(bounded_int(r.get('max_tokens',256),1,2048),'Invalid max_tokens')
        else:
            require(t['engine']=='sd-cli','Media task requires sd-cli engine')
            dimensions(r,kind)
            require(kind!='wan_i2v' or 'image_from' in r,'Wan I2V requires an image dependency')
            roles=dict(SLOTS[kind]);slots=r.get('slots')
            require(isinstance(slots,dict),'Missing media slots')
            if kind=='ltx2' and 'audio_vae' in slots:roles['audio_vae']='audio_vae'
            require(set(slots)==set(roles),'Missing or unsupported model slots')
            require(all(isinstance(v,str) for v in slots.values()) and len(set(slots.values()))==len(roles) and set(slots.values())==set(models),'Slots must match planned models exactly')
            for slot,mid in slots.items():
                c=catalog[mid];require(c.get('family')==FAMILY[kind] and c.get('role')==roles[slot] and c.get('lineage_verified') is True,'Unverified or incompatible model family/role: '+mid)
                require(c.get('format') in ('gguf','safetensors','sft') and bounded_int(c.get('bytes'),1,MAX_OUTPUT),'Invalid model format/size: '+mid)
                require(isinstance(c.get('bundle'),str) and ID.fullmatch(c['bundle']),'Missing verified bundle ID: '+mid)
                require(c['bundle']==catalog[slots['diffusion_model']].get('bundle'),'Model bundle mismatch: '+mid)
                if slot=='diffusion_model':require(isinstance(c.get('profiles'),list) and kind in c['profiles'],'Backbone generation mode not enrolled')
                _check_digest(c.get('sha256'))
    def visit(tid):
        require(tid not in visiting,'Dependency cycle')
        if tid in seen:return
        visiting.add(tid);t=by_id[tid]
        for dep in t.get('depends_on',[]):visit(dep)
        visiting.remove(tid);seen.add(tid);ordered.append(t)
    for t in tasks:visit(t['id'])
    return ordered


def absolute_file(s,*,executable=False):
    require(isinstance(s,str),'File path required');p=Path(s)
    require(p.is_absolute() and not p.is_symlink() and p.is_file() and (not executable or os.access(p,os.X_OK)),'Missing/unsafe local file')
    return str(p)


def verify_weights(entries):
    for e in entries:
        path=absolute_file(e['path']);_check_digest(e['sha256']);fd,before=_open_regular(Path(path))
        try:
            require(before.st_size==e['bytes'],'Model size mismatch')
            h=hashlib.sha256();size=0
            with os.fdopen(os.dup(fd),'rb') as src:
                while data:=src.read(1024*1024):
                    size+=len(data);require(size<=e['bytes'],'Model grew during verification');h.update(data)
            _check_unchanged(fd,before,size)
            require(h.hexdigest()==e['sha256'],'Model SHA-256 mismatch')
        finally:os.close(fd)


def read_text(path,limit=32768):
    fd,before=_open_regular(Path(path))
    try:
        require(0<before.st_size<=limit,'Invalid text size')
        with os.fdopen(os.dup(fd),'rb') as src:data=src.read(limit+1)
        _check_unchanged(fd,before,len(data));require(len(data)<=limit,'Oversized text')
        try:s=data.decode('utf-8')
        except UnicodeError as exc:raise PipelineError('Invalid UTF-8') from exc
        require(s.strip() and '\x00' not in s,'Invalid text content');return s
    finally:os.close(fd)


def media_command(spec,prompt,output):
    prompt_text(prompt,True);kind=spec['kind'];require(kind in SLOTS,'Invalid media kind')
    dimensions(spec,kind);require(spec['backend'] in ('cpu','cuda0','vulkan0','hip0'),'Invalid backend')
    roles=set(SLOTS[kind]);slots=spec['slots']
    if kind=='ltx2' and 'audio_vae' in slots:roles.add('audio_vae')
    require(set(slots)==roles,'Invalid slots')
    cmd=[spec['sd_cli'],'--mode','img_gen' if kind=='flux1' else 'vid_gen']
    for slot in sorted(slots):cmd.extend([FLAGS[slot],slots[slot]['path']])
    cmd.extend(['-p',prompt,'--steps',str(spec['steps']),'-W',str(spec['width']),'-H',str(spec['height']),'--backend',spec['backend']])
    if kind=='flux1':cmd.extend(['--cfg-scale','1.0','--sampling-method','euler'])
    else:cmd.extend(['--video-frames',str(spec['frames']),'--fps',str(spec['fps'])])
    if kind=='wan_i2v':cmd.extend(['-i',spec['image']])
    cmd.extend(['-o',str(output)]);return cmd


def probe_output(path,kind,recipe,deployment):
    """Validate contents before the worker returns success, not by extension."""
    if kind=='qwen_text':read_text(path,2*1024*1024);return
    p=Path(path);fd,st=_open_regular(p);os.close(fd)
    require(0<st.st_size<=MAX_OUTPUT,'Invalid media output size')
    ffprobe=absolute_file(deployment['ffprobe'],executable=True);ffmpeg=absolute_file(deployment['ffmpeg'],executable=True)
    try:
        fmt='png_pipe' if kind=='flux1' else 'avi'
        with p.open('rb') as f:head=f.read(12)
        require(head.startswith(b'\x89PNG\r\n\x1a\n') if kind=='flux1' else head[:4]==b'RIFF' and head[8:12]==b'AVI ','Media signature mismatch')
        r=subprocess.run([ffprobe,'-v','error','-protocol_whitelist','file','-f',fmt,'-select_streams','v:0','-count_frames','-show_entries','stream=codec_name,width,height,nb_read_frames,avg_frame_rate:format=format_name','-of','json',str(p)],check=True,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=120)
        require(len(r.stdout)<=65536,'Media probe failed');d=json.loads(r.stdout);stream,=d['streams']
        require(stream.get('width')==recipe['width'] and stream.get('height')==recipe['height'],'Output dimensions mismatch')
        frames=int(stream['nb_read_frames'])
        if kind=='flux1':require(stream['codec_name']=='png' and frames==1 and 'png_pipe' in d['format']['format_name'],'Expected one PNG frame')
        else:
            require(d['format']['format_name']=='avi' and frames==recipe['frames'],'Expected AVI with requested frame count')
            rate=stream.get('avg_frame_rate');require(isinstance(rate,str) and len(rate)<=32 and Fraction(rate)==recipe['fps'],'Output frame rate mismatch')
        subprocess.run([ffmpeg,'-nostdin','-v','error','-xerror','-threads','1','-protocol_whitelist','file','-f',fmt,'-i',str(p),'-map','0:v:0','-f','null','-'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=120)
        require(p.stat().st_size==st.st_size and p.stat().st_mtime_ns==st.st_mtime_ns,'Output changed during validation')
    except (OSError,subprocess.SubprocessError,KeyError,TypeError,ValueError,ZeroDivisionError) as exc:raise PipelineError('Media verification failed: '+str(exc)) from exc


def media_job(spec,output):
    """Trusted private spec produced by run_node; all outputs checked pre-CAS."""
    kind=spec['kind'];require(kind in SLOTS,'Unknown media profile')
    output=Path(output);require(output.is_absolute() and not output.exists() and not output.is_symlink(),'Unsafe media output')
    absolute_file(spec['sd_cli'],executable=True);verify_weights(spec['slots'].values())
    prompt=read_text(spec['prompt']);prompt_text(prompt,True)
    if kind=='wan_i2v':absolute_file(spec['image'])
    cmd=media_command(spec,prompt,output)
    try:subprocess.run(cmd,stdin=subprocess.DEVNULL,check=True,shell=False)
    except (OSError,subprocess.SubprocessError) as exc:raise PipelineError('Media engine failed') from exc
    require(output.is_file() and not output.is_symlink() and output.stat().st_size<=spec['output_bytes'],'Media output missing or over budget')
    probe_output(output,kind,spec,spec)


def text_job(spec,output):
    """Reuse the existing loopback llama adapter and enforce typed output pre-CAS."""
    output=Path(output);require(output.is_absolute() and not output.exists() and not output.is_symlink(),'Unsafe text output')
    prompt_text(read_text(spec['prompt']))
    argv=[sys.executable,'-I',str(ROOT/'tools'/'llama_job.py'),'--endpoint',spec['endpoint'],'--model',spec['runtime_model'],'--prompt-file',spec['prompt'],'--max-tokens',str(spec.get('max_tokens',256)),'--output',str(output)]
    try:subprocess.run(argv,stdin=subprocess.DEVNULL,check=True,shell=False)
    except (OSError,subprocess.SubprocessError) as exc:raise PipelineError('Text engine failed') from exc
    read_text(output,min(2*1024*1024,spec['output_bytes']))


def run_node(lease,cas:ArtifactStore,executor,node,deployment,*,retry_failed=False,timeout=600,gate_factory=None):
    require(isinstance(deployment,dict) and deployment.get('node')==node,'Deployment node mismatch')
    ordered=validate_recipes(lease.task_list,lease.catalog,lease.assignments)
    local=[t for t in ordered if lease.assignments[t['id']]['node']==node]
    require(local,'No tasks assigned to this node');work=Path(executor.root).resolve();_private_dir(work)
    # Preflight all local engine bindings and paths before the first side effect.
    for task in local:
        kind=task['recipe']['kind']
        if kind=='qwen_text':
            require(isinstance(deployment.get('llama_endpoint'),str) and re.fullmatch(r'http://127\.0\.0\.1:[0-9]{1,5}',deployment['llama_endpoint']) and 1<=int(deployment['llama_endpoint'].rsplit(':',1)[1])<=65535,'Literal loopback llama endpoint required')
        else:
            for key in ('sd_cli','ffprobe','ffmpeg'):absolute_file(deployment[key],executable=True)
            require(deployment.get('backend') in ('cpu','cuda0','vulkan0','hip0'),'Backend not allowed')
            paths=[absolute_file(deployment['model_paths'][mid]) for mid in task['models']]
            require(len(set(paths))==len(paths),'Duplicate weight paths in bundle')
    records=[]
    def completed(t,status):
        sha=status.get('output_sha256');cas.verify(sha);path=cas._path(sha)
        require(path.stat().st_size<=t['output_bytes'],'Checkpoint exceeds plan budget')
        probe_output(path,t['recipe']['kind'],t['recipe'],deployment);return sha
    for task in local:
        tid=task['id'];r=task['recipe'];kind=r['kind'];state=lease.status(tid)
        if state['state']=='COMPLETED':
            records.append({'task':tid,'status':'REUSED','sha256':completed(task,state)});continue
        if state['state']!='PENDING' and not (retry_failed and (state['state']=='FAILED' or state['state']=='LEASED' and state['expires_at']<=time.time())):
            return {'status':'BLOCKED','node':node,'task':tid,'reason':state['state'],'stages':records}
        with tempfile.TemporaryDirectory(prefix='pipeline-',dir=work) as td:
            private=Path(td);prompt=private/'prompt.txt'
            if 'prompt_from' in r:
                orig=lease.tasks[r['prompt_from']];up=lease.status(orig['id']);require(up['state']=='COMPLETED','Prompt dependency incomplete')
                sha=completed(orig,up);cas.restore(sha,prompt)
                prompt_text(read_text(prompt),kind!='qwen_text')
            else:prompt.write_text(prompt_text(r['prompt'],kind!='qwen_text'),encoding='utf-8')
            if kind=='qwen_text':
                spec={**r,'prompt':str(prompt),'endpoint':deployment['llama_endpoint'],'output_bytes':task['output_bytes']}
            else:
                spec={**r,'prompt':str(prompt),'output_bytes':task['output_bytes'],**{k:deployment[k] for k in ('sd_cli','ffmpeg','ffprobe','backend')}}
                spec['slots']={slot:{'path':deployment['model_paths'][mid],'sha256':lease.catalog[mid]['sha256'],'bytes':lease.catalog[mid]['bytes']} for slot,mid in r['slots'].items()}
                if kind=='wan_i2v':
                    orig=lease.tasks[r['image_from']];up=lease.status(orig['id']);require(up['state']=='COMPLETED','Image dependency incomplete')
                    image=private/'input.png';cas.restore(completed(orig,up),image);spec['image']=str(image)
            spec_file=private/'spec.json';spec_file.write_text(json.dumps(spec,ensure_ascii=False,allow_nan=False));spec_file.chmod(0o600)
            argv=[sys.executable,'-I',str(ROOT/'tools'/'multimodal_job.py'),'--spec',str(spec_file),'--output','{output}']
            gate=gate_factory(task) if gate_factory else None
            result=executor.run(tid,node,argv,suffix=KINDS[kind],timeout_seconds=timeout,runtime_gate=gate)
            state=lease.status(tid);require(result['status']=='COMPLETED' and state['state']=='COMPLETED' and result['sha256']==state['output_sha256'] and result['epoch']==state['epoch'],'Execution receipt mismatch')
            records.append({'task':tid,'status':'COMPLETED','sha256':completed(task,state)})
    return {'status':'COMPLETED','scope':'LOCAL_ASSIGNED_TASKS','node':node,'stages':records}

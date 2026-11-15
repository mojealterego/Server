#!/usr/bin/env python3
"""OMEGA-X model inventory: bounded GGUF / Safetensors metadata reader.

Reads only model headers, never copies weights. Hashing is optional and reads
all bytes; no time-to-inspect or RSS guarantees are claimed on Android FUSE.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import struct
import sys
from typing import Any

GGUF_TYPES = {0:'B',1:'b',2:'H',3:'h',4:'I',5:'i',6:'f',7:'?',10:'Q',11:'q',12:'d'}
GGUF_FILE_TYPES = {
    0:'F32', 1:'F16', 2:'Q4_0', 3:'Q4_1', 7:'Q8_0', 8:'Q5_0', 9:'Q5_1',
    10:'Q2_K',11:'Q3_K_S',12:'Q3_K_M',13:'Q3_K_L',14:'Q4_K_S',15:'Q4_K_M',
    16:'Q5_K_S',17:'Q5_K_M',18:'Q6_K',19:'IQ2_XXS',20:'IQ2_XS',
}
MAX_HEADER = 64*1024*1024
MAX_KV = 200000
EXTS = {'.gguf','.safetensors','.onnx','.task'}


def resolve_default_model_dir() -> Path:
    env = os.environ.get('OMEGA_MODEL_DIR')
    if env:
        return Path(env).expanduser()
    candidates = [Path.home()/'storage/shared/1.GGUF-UNCENSORED',
                  Path('/storage/emulated/0/1.GGUF-UNCENSORED'),
                  Path.home()/'storage/shared/---GGUF-UNCENSORED---']
    return next((x for x in candidates if x.is_dir()), candidates[0])


class Reader:
    def __init__(self, stream, size: int, budget: int = MAX_HEADER):
        self.stream, self.size, self.budget = stream, size, min(budget, size)
        self.pos = 0

    def raw(self, count: int) -> bytes:
        if count < 0 or count > self.budget-self.pos:
            raise ValueError('Model header exceeds file or safety size limit')
        data = self.stream.read(count)
        if len(data) != count:
            raise ValueError('Truncated model header')
        self.pos += count
        return data

    def skip(self, count: int) -> None:
        if count < 0 or count > self.budget-self.pos:
            raise ValueError('GGUF metadata exceeds safe header size')
        self.stream.seek(count, os.SEEK_CUR)
        self.pos += count

    def unpack(self, fmt: str):
        return struct.unpack('<'+fmt, self.raw(struct.calcsize('<'+fmt)))[0]

    def string(self) -> str:
        size = self.unpack('Q')
        return self.raw(size).decode('utf-8', errors='strict')

    def value(self, kind: int, depth: int = 0):
        if depth > 2:
            raise ValueError('GGUF metadata nesting too deep')
        if kind in GGUF_TYPES:
            return self.unpack(GGUF_TYPES[kind])
        if kind == 8:
            return self.string()
        if kind == 9:
            element_type = self.unpack('I')
            count = self.unpack('Q')
            if count > MAX_KV*100:
                raise ValueError('Oversized GGUF array')
            if element_type in GGUF_TYPES:
                width = struct.calcsize('<'+GGUF_TYPES[element_type])
                if count <= 16:
                    return [self.unpack(GGUF_TYPES[element_type]) for _ in range(count)]
                self.skip(width*count)
                return {'type':element_type,'count':count, 'elided':True}
            if element_type == 8:
                if count > 4096:
                    raise ValueError('Oversized string array')
                vals = []
                for i in range(count):
                    s = self.string()
                    if i < 16:
                        vals.append(s)
                return vals if count <= 16 else {'type':8,'count':count,'sample':vals}
            raise ValueError('Unsupported GGUF array element type')
        raise ValueError(f'Unsupported GGUF metadata type: {kind}')


def _gguf(stream, size: int) -> dict[str,Any]:
    r = Reader(stream, size)
    if r.raw(4) != b'GGUF':
        raise ValueError('Invalid GGUF magic')
    version = r.unpack('I')
    if version not in (2,3):
        raise ValueError(f'Unsupported GGUF version: {version}')
    tensor_count = r.unpack('Q')
    kv_count = r.unpack('Q')
    if kv_count > MAX_KV:
        raise ValueError('GGUF metadata count too large')
    metadata = {}
    for _ in range(kv_count):
        key = r.string()
        kind = r.unpack('I')
        metadata[key] = r.value(kind)
    arch = str(metadata.get('general.architecture','unknown')).lower()
    ftype = metadata.get('general.file_type')
    return {'format':'gguf','version':version,'architecture':arch,
            'tensor_count':tensor_count,'kv_count':kv_count,
            'quantization':GGUF_FILE_TYPES.get(ftype, f'UNKNOWN({ftype})'),
            'metadata':metadata,'header_read_bytes':r.pos}


def _no_duplicate_pairs(pairs):
    result={}
    for key, value in pairs:
        if key in result:
            raise ValueError(f'Duplicate Safetensors header key: {key}')
        result[key]=value
    return result


def _safetensors(stream, size:int) -> dict[str,Any]:
    length_bytes=stream.read(8)
    if len(length_bytes)!=8:
        raise ValueError('Truncated Safetensors header length')
    n=struct.unpack('<Q', length_bytes)[0]
    if not 2<=n<=MAX_HEADER or 8+n>size:
        raise ValueError('Invalid Safetensors header size')
    raw=stream.read(n)
    if len(raw)!=n or not raw.startswith(b'{'):
        raise ValueError('Safetensors header must start with JSON object')
    obj=json.loads(raw.decode('utf-8'), object_pairs_hook=_no_duplicate_pairs)
    if not isinstance(obj,dict):
        raise ValueError('Safetensors header must be a map')
    meta=obj.get('__metadata__',{})
    if not isinstance(meta,dict) or any(not isinstance(x,str) for x in meta.values()):
        raise ValueError('Invalid Safetensors metadata')
    tensor_data_size=size-8-n
    # Known Safetensors dtypes; validate shape->byte-range without reading tensor weights.
    dtype_width = {
        'BOOL':1,'U8':1,'I8':1,'F8_E4M3':1,'F8_E5M2':1,
        'F8_E4M3FN':1,'F8_E4M3FNUZ':1,'F8_E5M2FNUZ':1,
        'U16':2,'I16':2,'F16':2,'BF16':2,
        'U32':4,'I32':4,'F32':4,
        'U64':8,'I64':8,'F64':8,
    }
    types=set()
    ranges=[]
    for key, item in obj.items():
        if key=='__metadata__':
            continue
        if not isinstance(item,dict):
            raise ValueError('Invalid Safetensors tensor record')
        offsets=item.get('data_offsets')
        if not isinstance(offsets,list) or len(offsets)!=2 or any(type(x) is not int for x in offsets):
            raise ValueError('Invalid Safetensors tensor offsets')
        if not 0<=offsets[0]<=offsets[1]<=tensor_data_size:
            raise ValueError('Safetensors tensor references bytes outside file')
        shape=item.get('shape')
        dtype=item.get('dtype')
        if not isinstance(shape,list) or not isinstance(dtype,str):
            raise ValueError('Invalid Safetensors tensor shape or dtype')
        if any(type(dim) is not int or dim < 0 for dim in shape):
            raise ValueError('Invalid Safetensors tensor dimension')
        if dtype not in dtype_width:
            raise ValueError(f'Unknown Safetensors dtype: {dtype}')
        expected=dtype_width[dtype]
        for dim in shape:
            expected *= dim
            if expected > tensor_data_size:
                raise ValueError('Safetensors tensor byte size exceeds data section')
        if offsets[1]-offsets[0] != expected:
            raise ValueError('Safetensors tensor byte size inconsistent with shape and dtype')
        if expected:
            ranges.append((offsets[0],offsets[1]))
        types.add(dtype)
    ranges.sort()
    for previous, current in zip(ranges,ranges[1:]):
        if previous[1] > current[0]:
            raise ValueError('Safetensors tensor ranges overlap')
    if ranges:
        if ranges[0][0] != 0 or ranges[-1][1] != tensor_data_size:
            raise ValueError('Safetensors data section contains a hole')
        for previous, current in zip(ranges,ranges[1:]):
            if previous[1] != current[0]:
                raise ValueError('Safetensors data section contains a hole')
    elif tensor_data_size != 0:
        raise ValueError('Safetensors unindexed data section')
    return {'format':'safetensors','version':1,
            'architecture':str(meta.get('modelspec.architecture','unknown')).lower(),
            'tensor_count':len(obj)-('__metadata__' in obj), 'kv_count':len(meta),
            'quantization':'/'.join(sorted(types)) if types else 'UNKNOWN',
            'metadata':meta,'sample_tensors':[k for k in obj if k!='__metadata__'][:8],
            'header_read_bytes':8+n}


def inspect_binary_header(path: Path) -> dict[str,Any]:
    path=Path(path)
    if not path.is_file() or path.is_symlink():
        raise ValueError('Model file missing, symbolic link or not a regular file')
    size=path.stat().st_size
    with path.open('rb') as stream:
        if path.suffix.lower()=='.gguf':
            return _gguf(stream,size)
        if path.suffix.lower()=='.safetensors':
            return _safetensors(stream,size)
    raise ValueError('Not a GGUF or Safetensors file')


def category(filename: str) -> str:
    low=filename.lower()
    if low.endswith('.onnx'):return 'onnx'
    if low.endswith('.task'):return 'mediapipe-task'
    if 'mmproj' in low:return 'projector'
    if 'vae' in low:return 'vae'
    if 'umt5' in low or 'text_encoder' in low:return 'encoder'
    if 'ltx' in low or 'wan_' in low:return 'video'
    if low.endswith('.gguf'):return 'llm'
    return 'other-safetensors'


def _classify(path:Path, header:dict[str,Any]) -> tuple[str,str,str]:
    arch=header['architecture']
    name=path.name.lower()
    fmt=header['format']
    if arch=='clip' or 'mmproj' in name:
        return 'mmproj_vision_projector','llama.cpp multimodal','INFERRED'
    if 'vae' in name:
        return 'video_vae','sd-cli / ComfyUI','INFERRED'
    if arch in ('ltxv','ltx2','ltx') or 'ltx' in name:
        return 'video_dit_ltx','sd-cli / ComfyUI','INFERRED'
    if arch.startswith('wan') or 'wan' in name:
        return 'video_dit_wan','sd-cli / ComfyUI','INFERRED'
    if arch in ('t5','t5encoder','umt5') or 'umt5' in name:
        return 'video_text_encoder','sd-cli / ComfyUI','INFERRED'
    if fmt=='gguf' and arch not in ('unknown',''):
        return 'llm_backbone','llama-server','INFERRED'
    return 'unclassified','manual review','UNVERIFIED'


def digest(path: Path) -> str:
    h=hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda:f.read(4*1024*1024),b''):
            h.update(chunk)
    return h.hexdigest()


def scan_inventory(directory:Path, compute_hashes:bool=False)->dict[str,Any]:
    directory=Path(directory).expanduser()
    if not directory.is_dir():
        return {'status':'DIRECTORY_NOT_FOUND','model_dir':str(directory),'models':[],'total_files':0}
    items=[]
    for p in sorted(directory.iterdir(),key=lambda p:p.name.casefold()):
        if p.is_symlink() or not p.is_file() or p.suffix.lower() not in EXTS:
            continue
        entry={'filename':p.name,'name':p.name,'path':str(p),
               'size_bytes':p.stat().st_size,'category':category(p.name)}
        if p.suffix.lower() in ('.gguf','.safetensors'):
            try:
                hdr=inspect_binary_header(p)
                role,engine,confidence=_classify(p,hdr)
                entry.update(hdr)
                entry.update(role=role,engine=engine,classification_confidence=confidence)
            except (ValueError,OSError,OverflowError,UnicodeError,RecursionError) as exc:
                entry.update(role='unrecognized_or_corrupt',engine='manual review',error=str(exc))
        else:
            entry.update(role='onnx_model' if p.suffix.lower()=='.onnx' else 'mediapipe_task',
                         engine='external runtime',classification_confidence='UNVERIFIED')
        if compute_hashes:
            entry['sha256']=digest(p)
        items.append(entry)
    projectors=[i for i in items if i.get('role')=='mmproj_vision_projector']
    for llm in (i for i in items if i.get('role')=='llm_backbone'):
        key=f"{llm['architecture']}.embedding_length"
        edim=llm['metadata'].get(key)
        matches=[]
        for p in projectors:
            pdim=p['metadata'].get('clip.vision.projection_dim',p['metadata'].get('clip.projection_dim'))
            if edim is not None and pdim is not None and edim==pdim:
                matches.append(p['filename'])
        llm['mmproj_compatibility']={
            'status':'DIMENSION_MATCH_UNVERIFIED_LINEAGE' if matches else 'NOT_VERIFIED',
            'candidates':matches,
            'explanation':'Matching dimensions alone do not prove compatible image encoder, weights, or model lineage.'}
    return {'status':'OK','model_dir':str(directory),'total_files':len(items),'models':items}


def scan(directory:Path, *, hash_files:bool=False)->list[dict]:
    report=scan_inventory(directory,compute_hashes=hash_files)
    if report['status']!='OK':
        raise ValueError(f'Model directory does not exist: {directory}')
    return report['models']


def main(argv:list[str]|None=None)->int:
    parser=argparse.ArgumentParser(description='OMEGA-X v1 model header inventory')
    parser.add_argument('directory',nargs='?',type=Path)
    parser.add_argument('--dir',dest='model_dir',type=Path)
    parser.add_argument('--sha256',action='store_true')
    parser.add_argument('--write-manifest',type=Path)
    parser.add_argument('--json-out','--output',dest='output',type=Path)
    a=parser.parse_args(argv)
    report=scan_inventory(a.model_dir or a.directory or resolve_default_model_dir(),compute_hashes=a.sha256 or bool(a.write_manifest))
    if a.write_manifest and report['status']=='OK':
        a.write_manifest.parent.mkdir(parents=True,exist_ok=True)
        # absolute paths for sha256sum; escape newline filenames via GNU sha256sum rules not required
        # here: fail closed on exceptional filenames rather than create ambiguous records.
        lines=[]
        for x in report['models']:
            if '\n' in x['path'] or '\r' in x['path']:
                raise ValueError('Newline in model path unsupported for checksum manifest')
            lines.append(f"{x['sha256']}  {x['path']}")
        tmp=a.write_manifest.with_name(a.write_manifest.name+'.tmp')
        tmp.write_text('\n'.join(lines)+'\n',encoding='utf-8')
        tmp.replace(a.write_manifest)
    result=json.dumps(report,ensure_ascii=False,indent=2,default=str)+'\n'
    if a.output:
        a.output.parent.mkdir(parents=True,exist_ok=True)
        a.output.write_text(result,encoding='utf-8')
    else:
        print(result,end='')
    return 0 if report['status']=='OK' else 2

if __name__=='__main__':sys.exit(main())

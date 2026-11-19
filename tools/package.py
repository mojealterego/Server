#!/usr/bin/env python3
"""Allowlist-based, reproducible ZIP built from verified code and no secrets.

The package is byte-identical for identical source files and reports.
A fresh verification changes its timestamp, therefore changes ZIP inputs.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import zipfile

ROOT=Path(__file__).resolve().parents[1]
OUTPUT=ROOT.parent/(ROOT.name+'.zip')
ALLOWED_TOP={'README.md','.gitignore'}
ALLOWED_DIRS={
    'cloud':{'.sh'}, 'docs':{'.md'}, 'reports':{'.txt','.json'},
    'samples':{'.onnx'}, 'termux':{'.py','.sh'}, 'tests':{'.py'},
    'tools':{'.py','.sh'}, 'atlas':{'.py'}, 'catalog':{'.json'}, 'examples':{'.json'},
}
VPS_ALLOWED={
    'compose.yaml','.dockerignore','init.sh','media_worker.py',
    'ftps/Dockerfile','ftps/entrypoint.sh','ftps/proftpd.conf.template',
    'sftp/Dockerfile','sftp/entrypoint.sh','sftp/sshd_config',
    'media/Dockerfile',
    'compose.smb.yaml','smb/Dockerfile','smb/entrypoint.sh','smb/smb.conf',
}

def allowed(path:Path)->bool:
    rel=path.relative_to(ROOT)
    if not path.is_file() or path.is_symlink() or not rel.parts:return False
    if len(rel.parts)==1:
        return rel.name in ALLOWED_TOP
    if rel.parts[0]=='vps':
        return rel.as_posix().removeprefix('vps/') in VPS_ALLOWED
    if any(part.startswith('.') for part in rel.parts[1:]):return False
    suffixes=ALLOWED_DIRS.get(rel.parts[0])
    if not suffixes or len(rel.parts)!=2 or path.suffix.lower() not in suffixes:
        return False
    if rel.parts[0]=='tests' and not rel.name.startswith('test_'):
        return False
    if rel.parts[0]=='reports' and rel.name not in {'verification.json','verification.txt','unittest.txt','green-mobile.txt','red.txt','phaseshift_benchmark.json'}:
        return False
    return True


def main(argv=None)->int:
    p=argparse.ArgumentParser()
    p.add_argument('--skip-verify',action='store_true',help='Repack previously verified, unchanged sources for reproducibility tests')
    args=p.parse_args(argv)
    if not args.skip_verify:
        subprocess.run([sys.executable,str(ROOT/'tools/verify.py')],check=True,cwd=ROOT)
    report=json.loads((ROOT/'reports/verification.json').read_text(encoding='utf-8'))
    checks=report.get('local',{})
    suite=checks.get('unittest',{})
    if not (checks.get('status')=='PASS' and suite.get('executed',0)>0 and
            suite.get('failures')==0 and suite.get('errors')==0 and suite.get('skipped')==0):
        raise SystemExit('Refusing to package failed, missing or skipped local tests')
    files=sorted((x for x in ROOT.rglob('*') if allowed(x)),key=lambda x:x.relative_to(ROOT).as_posix())
    sums=[f'{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.relative_to(ROOT).as_posix()}' for path in files]
    manifest=ROOT/'SHA256SUMS'
    manifest.write_text('\n'.join(sums)+'\n',encoding='utf-8')
    files.append(manifest)
    with zipfile.ZipFile(OUTPUT,'w',zipfile.ZIP_DEFLATED,compresslevel=9) as z:
        for path in sorted(files,key=lambda x:x.relative_to(ROOT).as_posix()):
            rel=ROOT.name+'/'+path.relative_to(ROOT).as_posix()
            mode=0o755 if path.suffix in {'.sh','.py'} else 0o644
            zi=zipfile.ZipInfo(rel,date_time=(2026,11,15,8,0,0))
            zi.create_system=3
            zi.external_attr=((0o100000|mode)<<16)
            zi.compress_type=zipfile.ZIP_DEFLATED
            z.writestr(zi,path.read_bytes(),compress_type=zipfile.ZIP_DEFLATED,compresslevel=9)
    with zipfile.ZipFile(OUTPUT) as z:
        if z.testzip() is not None:raise RuntimeError('ZIP CRC verification failed')
        members={m.filename.removeprefix(ROOT.name+'/'):m for m in z.infolist()}
        for entry in sums:
            digest,rel=entry.split('  ',1)
            if hashlib.sha256(z.read(members[rel])).hexdigest()!=digest:
                raise RuntimeError('ZIP SHA-256 verification failed: '+rel)
    print('ZIP:',OUTPUT)
    print('FILES:',len(files))
    print('SIZE:',OUTPUT.stat().st_size)
    print('SHA256:',hashlib.sha256(OUTPUT.read_bytes()).hexdigest())
    return 0

if __name__=='__main__':sys.exit(main())

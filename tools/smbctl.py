#!/usr/bin/env python3
"""Prepare and operate isolated SMB2/3 shares on a rootful Linux Docker host."""
from __future__ import annotations
import argparse
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import sys
import tempfile

VPS = Path(__file__).resolve().parents[1] / 'vps'
PRIVATE = tuple(ipaddress.IPv4Network(x) for x in ('10.0.0.0/8','172.16.0.0/12','192.168.0.0/16','100.64.0.0/10'))

class SmbError(ValueError):
    pass


def binding(address,port,allow_network=False):
    try: ip=ipaddress.IPv4Address(address)
    except (ValueError,TypeError) as exc: raise SmbError('Literal IPv4 address required') from exc
    if type(port) is not int or not 1<=port<=65535: raise SmbError('Invalid port')
    if not ip.is_loopback and not (allow_network and any(ip in n for n in PRIVATE)):
        raise SmbError('Only loopback or explicitly authorized private IPv4 bind')
    return str(ip)


def directory(path,uid,gid,mode):
    try: path.mkdir(mode=mode)
    except FileExistsError: pass
    else:
        if (uid,gid)!=(os.geteuid(),os.getegid()): os.chown(path,uid,gid)
        os.chmod(path,mode)
    st=path.lstat()
    if not stat.S_ISDIR(st.st_mode) or (st.st_uid,st.st_gid,stat.S_IMODE(st.st_mode))!=(uid,gid,mode):
        raise SmbError('Unsafe directory or ownership: '+str(path))


def password(path,uid,gid):
    try: fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    except FileExistsError: pass
    else:
        with os.fdopen(fd,'wb') as out:
            out.write((secrets.token_hex(32)+'\n').encode());out.flush();os.fsync(out.fileno())
    st=path.lstat()
    if not stat.S_ISREG(st.st_mode) or st.st_nlink!=1 or (st.st_uid,st.st_gid,stat.S_IMODE(st.st_mode))!=(uid,gid,0o600):
        raise SmbError('Unsafe credential file: '+str(path))
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as src: raw=src.read(66)
    if not re.fullmatch(rb'[a-f0-9]{64}\n',raw): raise SmbError('Invalid credential file: '+str(path))


def prepare_layout(root,owner,compat,secure):
    root=Path(root);st=root.lstat()
    if not stat.S_ISDIR(st.st_mode) or st.st_mode&0o022: raise SmbError('Use a trusted non-writable-by-others VPS directory')
    directory(root/'smb-secrets',*owner,0o700)
    directory(root/'smb-data',*owner,0o755)
    directory(root/'smb-data'/'compat',*compat,0o700)
    directory(root/'smb-data'/'secure',*secure,0o700)
    directory(root/'smb-models',*secure,0o700)
    for name in ('compat','secure'):password(root/'smb-secrets'/(name+'_password'),*owner)
    if (root/'smb-secrets'/'compat_password').read_bytes()==(root/'smb-secrets'/'secure_password').read_bytes():
        raise SmbError('Credentials must be distinct')


def prepare(root=VPS):
    if os.geteuid()!=0: raise SmbError('Preparation requires root on the VPS (not Android)')
    prepare_layout(root,(0,0),(10002,10002),(10003,10003))


def compose(action,address,port,allow_network):
    if action not in ('up','stop'):raise SmbError('Unknown compose action')
    addr=binding(address,port,allow_network)
    env={**os.environ,'SMB_BIND_ADDRESS':addr,'SMB_PORT':str(port)}
    argv=['docker','compose','-f',str(VPS/'compose.yaml'),'-f',str(VPS/'compose.smb.yaml'),'--profile','smb']
    argv+=['up','-d','--build','smb'] if action=='up' else ['stop','smb']
    subprocess.run(argv,env=env,check=True)


def probe(root,address,port):
    """Explicit live acceptance matrix. Never pass passwords as argv or print them."""
    addr=binding(address,port,True);root=Path(root)
    with tempfile.TemporaryDirectory(prefix='omega-smb-probe-') as temp:
        work=Path(temp);auth={}
        for name in ('compat','secure'):
            dest=work/(name+'.auth');source=root/'smb-secrets'/(name+'_password')
            st=source.lstat()
            if not stat.S_ISREG(st.st_mode) or st.st_nlink!=1 or st.st_uid!=os.geteuid() or stat.S_IMODE(st.st_mode)!=0o600:
                raise SmbError('Unsafe credential file')
            fd=os.open(source,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
            with os.fdopen(fd,'rb') as inp: raw=inp.read(66)
            if not re.fullmatch(rb'[a-f0-9]{64}\n',raw):raise SmbError('Invalid credential file')
            fd=os.open(dest,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
            with os.fdopen(fd,'wb') as out:out.write(('username = omega-'+name+'\npassword = ').encode()+raw)
            auth[name]=dest
        def call(share,account,version,protection,command):
            argv=['smbclient','//'+addr+'/'+share,'-p',str(port),'-A',str(auth[account]),'-m',version,
                  '--option=client min protocol='+version,'--client-protection='+protection,'--use-kerberos=off','-c',command]
            return subprocess.run(argv,cwd=work,stdin=subprocess.DEVNULL,capture_output=True,timeout=30)
        def expect(share,account,version,protection,command,ok=True):
            r=call(share,account,version,protection,command)
            if ok and r.returncode!=0: raise SmbError('Live probe failed: '+share+' '+version+' '+command.split()[0])
            if not ok:
                if r.returncode==0:
                    if command.startswith('put '):call(share,account,version,protection,'del '+command.split()[2])
                    raise SmbError('Forbidden operation succeeded: '+share+' '+version)
                if not any(code in r.stdout+r.stderr for code in (b'NT_STATUS_ACCESS_DENIED',b'NT_STATUS_NOT_SUPPORTED',b'NT_STATUS_INVALID_NETWORK_RESPONSE',b'NT_STATUS_CONNECTION_DISCONNECTED',b'NT_STATUS_LOGON_FAILURE')):
                    raise SmbError('Negative probe inconclusive: '+share+' '+version)
        for share,account,version,protection in [('omega-compat','compat','SMB2_10','sign'),('omega-secure','secure','SMB3_11','encrypt')]:
            payload=secrets.token_bytes(1024);(work/'send.bin').write_bytes(payload);(work/'recv.bin').unlink(missing_ok=True)
            name='omega-probe-'+secrets.token_hex(16)+'.bin'
            try:
                expect(share,account,version,protection,'put send.bin '+name)
                expect(share,account,version,protection,'get '+name+' recv.bin')
                if not (work/'recv.bin').is_file() or (work/'recv.bin').read_bytes()!=payload:raise SmbError('SMB read-back mismatch')
            finally:expect(share,account,version,protection,'del '+name)
        expect('omega-models','secure','SMB3_11','encrypt','ls')
        expect('omega-secure','secure','SMB2_10','sign','ls',False)
        expect('omega-secure','compat','SMB3_11','encrypt','ls',False)
        expect('omega-models','secure','SMB3_11','encrypt','put send.bin omega-probe-'+secrets.token_hex(16)+'.bin',False)
        expect('omega-compat','compat','NT1','sign','ls',False)
        expect('omega-secure','secure','SMB3_11','encrypt','ls')
        return {'status':'PASS','positive':['SMB2_10 signed write/read/delete','SMB3_11 encrypted write/read/delete','encrypted model listing'],
                'negative':['SMB2 secure share','wrong account','model write','SMB1 request']}


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('action',choices=('prepare','up','stop','probe'))
    p.add_argument('--bind',default='127.0.0.1');p.add_argument('--port',type=int,default=445)
    p.add_argument('--allow-network',action='store_true')
    a=p.parse_args(argv)
    try:
        if a.action=='prepare':prepare();print('SMB directories and credentials prepared; secrets not printed.')
        elif a.action=='probe':print(json.dumps(probe(VPS,binding(a.bind,a.port,a.allow_network),a.port),sort_keys=True))
        else:compose(a.action,a.bind,a.port,a.allow_network)
        return 0
    except (SmbError,OSError,subprocess.SubprocessError) as exc:
        print('SMB ERROR: '+str(exc),file=sys.stderr);return 1

if __name__=='__main__':sys.exit(main())

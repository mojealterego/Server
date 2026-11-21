"""E18a reproducible public-model hydration with strict source and SHA pinning.

This does not create physical capacity. Avoids keeping duplicate public weights,
by re-fetching only when needed. License/audience are operator assertions;
no network or economic eligibility is implied by this module.
"""
from __future__ import annotations

from contextlib import closing
import hashlib
import http.client
import ipaddress
import os
from pathlib import Path
import re
import secrets
import ssl
import stat
import time
import urllib.error
import urllib.parse
import urllib.request

SCHEMA='omega.virtual-model.v1'
HEX64=re.compile(r'[a-f0-9]{64}\Z',re.ASCII)
REV40=re.compile(r'[a-f0-9]{40}\Z',re.ASCII)
SEG=re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z',re.ASCII)
MAX_BYTES=64*1024**3
CHUNK=1024**2


class VirtualModelError(ValueError):
    pass


def require(condition,msg):
    if not condition: raise VirtualModelError(msg)


def _parts(url,*,origin):
    require(type(url) is str and len(url)<=4096, 'Invalid source URL')
    try:
        p=urllib.parse.urlsplit(url)
        port=p.port
    except ValueError:raise VirtualModelError('Malformed source URL') from None
    require(p.scheme=='https' and p.username is None and p.password is None
            and port in (None,443) and not p.fragment and p.hostname is not None,
            'Only authorized HTTPS sources are accepted')
    host=p.hostname.lower()
    try:ipaddress.ip_address(host)
    except ValueError:pass
    else:raise VirtualModelError('IP literals are forbidden')
    if origin:
        require(host=='huggingface.co' and p.port is None and not p.query,
                'Only pinned public Hugging Face origins are enrolled')
        require('%' not in p.path and '\\' not in p.path,'Ambiguous path encoding')
    else:
        require(host=='huggingface.co' or host.endswith('.hf.co') or
                host.endswith('.xethub.hf.co'), 'Redirect host not enrolled')
    return p


def validate_reference(ref:dict)->dict:
    require(type(ref) is dict and set(ref)=={'schema','url','revision','sha256',
            'size_bytes','license'} and ref['schema']==SCHEMA,'Invalid model reference')
    require(type(ref['size_bytes']) is int and 1<=ref['size_bytes']<=MAX_BYTES
            and type(ref['sha256']) is str and HEX64.fullmatch(ref['sha256']) is not None,
            'Invalid model size/hash')
    require(type(ref['revision']) is str and REV40.fullmatch(ref['revision']) is not None,
            'Model revision must be a pinned commit')
    require(type(ref['license']) is str and 1<=len(ref['license'])<=100 and
            re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.-]*',ref['license']) is not None,
            'Operator must provide license identifier')
    p=_parts(ref['url'],origin=True)
    tokens=p.path.strip('/').split('/')
    require(len(tokens)>=5 and tokens[2]=='resolve' and tokens[3]==ref['revision']
            and all(SEG.fullmatch(x) is not None and x not in ('.','..') for x in tokens)
            and tokens[-1].lower().endswith(('.gguf','.safetensors','.onnx')),
            'Invalid pinned model artifact URL')
    return ref


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


def public_https_stream(ref:dict):
    """Authorized origin and bounded HTTPS redirects; never follows arbitrary hosts.

    HTTP responses are verified byte-for-byte by `rehydrate`. No proxy env
    is consulted, avoiding implicit requests through user-supplied proxies.
    """
    url=ref['url']
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),
        urllib.request.HTTPSHandler(context=ssl.create_default_context()),_NoRedirect())
    for hops in range(4):
        _parts(url,origin=(hops==0))
        req=urllib.request.Request(url,method='GET',headers={'Accept-Encoding':'identity'})
        try:
            response=opener.open(req,timeout=30)
        except urllib.error.HTTPError as exc:
            if exc.code not in (301,302,303,307,308) or hops==3:
                exc.close();raise VirtualModelError('Remote HTTP request rejected') from None
            target=exc.headers.get('Location')
            exc.close()
            require(type(target) is str and target,'Remote redirect without target')
            url=urllib.parse.urljoin(url,target)
            _parts(url,origin=False)
            continue
        require(response.status==200,'Unexpected HTTP status')
        length=response.headers.get('Content-Length')
        if length is not None:
            try:count=int(length)
            except ValueError:response.close();raise VirtualModelError('Malformed content length') from None
            if count!=ref['size_bytes']:
                response.close();raise VirtualModelError('Remote content size differs from pinned size')
        return response
    raise VirtualModelError('Too many redirects')


def _hash_fd(fd,size):
    h=hashlib.sha256()
    count=0
    with os.fdopen(os.dup(fd),'rb') as reader:
        while data:=reader.read(CHUNK):
            count+=len(data)
            require(count<=size,'Cached object exceeded pinned size')
            h.update(data)
    require(count==size,'Cached object truncated')
    return h.hexdigest()


def _sync_directory(p):
    fd=os.open(p,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(fd)
    finally:os.close(fd)


def rehydrate(ref:dict,destination:Path,*,open_source=None,max_seconds:int=3600)->dict:
    validate_reference(ref)
    require(type(max_seconds) is int and 1<=max_seconds<=14400,'Invalid transfer deadline')
    destination=Path(destination)
    parent=destination.parent
    require(parent.is_dir() and not parent.is_symlink() and
            parent.stat().st_uid==os.getuid() and not parent.stat().st_mode&0o077,
            'Cache directory must be private')
    require(not destination.is_symlink(),'Symlink destination refused')
    if destination.exists():
        fd=os.open(destination,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        try:
            st=os.fstat(fd)
            require(stat.S_ISREG(st.st_mode) and st.st_size==ref['size_bytes'],
                    'Existing cache object is not a correct regular file')
            require(_hash_fd(fd,ref['size_bytes'])==ref['sha256'],
                    'Existing cache object failed integrity check')
        finally:os.close(fd)
        return {'status':'ALREADY_VERIFIED','sha256':ref['sha256'],
                'size_bytes':ref['size_bytes'],'path':str(destination)}
    temp=parent/('.omega-hydrate-'+secrets.token_hex(20))
    fd=os.open(temp,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600)
    began=time.monotonic()
    try:
        try:
            provider=open_source or public_https_stream
            with os.fdopen(fd,'wb') as output, closing(provider(ref)) as source:
                count=0;h=hashlib.sha256()
                while True:
                    require(time.monotonic()-began<=max_seconds,'Hydration deadline exceeded')
                    data=source.read(CHUNK)
                    require(type(data) is bytes,'Transport returned nonbinary content')
                    if not data:break
                    count+=len(data)
                    require(count<=ref['size_bytes'],'Download exceeded pinned size')
                    output.write(data);h.update(data)
                require(count==ref['size_bytes'] and h.hexdigest()==ref['sha256'],
                        'Pinned model digest or size mismatch')
                output.flush();os.fsync(output.fileno())
            os.chmod(temp,0o400)
            os.link(temp,destination,follow_symlinks=False)
            _sync_directory(parent)
            return {'status':'HYDRATED_VERIFIED','sha256':ref['sha256'],
                    'size_bytes':count,'path':str(destination)}
        except (OSError,urllib.error.URLError,ssl.SSLError) as exc:
            raise VirtualModelError('Authenticated model transfer failed') from exc
    finally:
        temp.unlink(missing_ok=True)


def main(argv=None)->int:
    import argparse
    import json
    import sys
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--reference',type=Path,required=True)
    parser.add_argument('--destination',type=Path,required=True)
    parser.add_argument('--max-seconds',type=int,default=3600)
    a=parser.parse_args(argv)
    try:
        require(a.reference.is_file() and not a.reference.is_symlink(),
                'Reference must be an ordinary file')
        with a.reference.open('rb') as source:
            raw=source.read(16385)
        require(len(raw)<=16384,'Reference metadata too large')
        def unique(pairs):
            obj={}
            for key,val in pairs:
                require(key not in obj,'Duplicate reference field')
                obj[key]=val
            return obj
        doc=json.loads(raw,object_pairs_hook=unique,parse_constant=lambda x: (_ for _ in ()).throw(VirtualModelError('Nonfinite reference')))
        result=rehydrate(doc,a.destination,max_seconds=a.max_seconds)
        print(json.dumps(result,sort_keys=True));return 0
    except (VirtualModelError,OSError,ValueError,TypeError) as exc:
        print('VIRTUAL MODEL ERROR: '+str(exc),file=sys.stderr);return 1


if __name__=='__main__':
    raise SystemExit(main())

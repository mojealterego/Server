"""Operator-fenced cross-host authority registry using etcd v3 transactions.
No automatic expiry or live state replication. A grant is not physical fencing.
"""
from __future__ import annotations
import argparse
import base64
from dataclasses import asdict, dataclass
import http.client
import json
import re
import secrets
import ssl
import sys
from urllib.parse import urlsplit

IDENT=re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z')
HEX=re.compile(r'[0-9a-f]{64}\Z')
MAX_RESPONSE=65536

class AuthorityError(ValueError): pass

def require(condition, message):
    if not condition: raise AuthorityError(message)

def b64(data:bytes)->str: return base64.b64encode(data).decode('ascii')

def number(value, minimum=1, maximum=2**63-1):
    require(type(value) in (str,int) and re.fullmatch(r'[0-9]{1,20}',str(value)), 'Invalid etcd integer')
    n=int(value); require(minimum<=n<=maximum,'Invalid etcd integer'); return n

class TLSGateway:
    """Direct HTTPS (no proxy or redirects), explicit CA and client identity."""
    def __init__(self, endpoint, ca, cert, key, *, timeout=5):
        try: url=urlsplit(endpoint); port=url.port
        except ValueError as exc: raise AuthorityError('Invalid endpoint') from exc
        require(url.scheme=='https' and url.hostname and not url.username and not url.password and url.path in ('','/') and not url.query and not url.fragment,'Expected HTTPS origin')
        require(type(timeout) is int and 1<=timeout<=30,'Invalid timeout')
        self.host=url.hostname; self.port=port or 2379; self.timeout=timeout
        self.context=ssl.create_default_context(cafile=ca); self.context.minimum_version=ssl.TLSVersion.TLSv1_2
        self.context.load_cert_chain(cert,key)
    def __call__(self,path,body):
        require(path in ('/v3/kv/range','/v3/kv/txn'),'Unsupported etcd RPC')
        conn=http.client.HTTPSConnection(self.host,self.port,context=self.context,timeout=self.timeout)
        try:
            conn.request('POST',path,json.dumps(body,separators=(',',':')).encode(),{'Content-Type':'application/json','Connection':'close'})
            response=conn.getresponse(); require(response.status==200,'etcd RPC rejected')
            data=response.read(MAX_RESPONSE+1); require(len(data)<=MAX_RESPONSE,'Oversized etcd response')
            return json.loads(data)
        except (OSError,http.client.HTTPException,ValueError) as exc: raise AuthorityError('etcd RPC failed; outcome may be unknown') from exc
        finally: conn.close()

@dataclass(frozen=True)
class Grant:
    node:str
    checkpoint_sha256:str
    nonce:str
    revision:int

class Authority:
    def __init__(self, rpc, namespace, cluster_id):
        require(isinstance(namespace,str) and IDENT.fullmatch(namespace),'Invalid namespace')
        self.rpc=rpc; self.key=b64(('/omega/authority/v1/'+namespace).encode()); self.cluster_id=number(cluster_id,maximum=2**64-1)
    def _call(self,path,body):
        try:
            out=self.rpc(path,body)
            require(isinstance(out,dict) and isinstance(out.get('header'),dict),'Invalid etcd response')
            require(number(out['header'].get('cluster_id'),maximum=2**64-1)==self.cluster_id,'Unexpected etcd cluster')
            require(not out.get('error') and not out.get('code'),'etcd error')
            return out
        except (OSError,RuntimeError,TypeError,KeyError,ValueError) as exc: raise AuthorityError('Authority operation rejected or outcome unknown') from exc
    @staticmethod
    def _record(node,pin,nonce):
        require(isinstance(node,str) and IDENT.fullmatch(node),'Invalid node identity')
        require(isinstance(pin,str) and HEX.fullmatch(pin),'Invalid checkpoint pin')
        require(isinstance(nonce,str) and HEX.fullmatch(nonce),'Invalid grant nonce')
        return {'schema':'omega.authority.v1','node':node,'checkpoint_sha256':pin,'nonce':nonce}
    def current(self):
        out=self._call('/v3/kv/range',{'key':self.key,'serializable':False})
        rows=out.get('kvs',[]); require(isinstance(rows,list) and len(rows)<=1,'Invalid authority response')
        if not rows:return None
        try:
            row=rows[0];require(row['key']==self.key and number(row.get('lease','0'),0)==0,'Authority must not expire')
            raw=base64.b64decode(row['value'],validate=True); require(len(raw)<=4096,'Oversized authority record')
            doc=json.loads(raw); require(isinstance(doc,dict) and set(doc)=={'schema','node','checkpoint_sha256','nonce'} and doc['schema']=='omega.authority.v1','Invalid record')
            self._record(doc['node'],doc['checkpoint_sha256'],doc['nonce'])
            return Grant(doc['node'],doc['checkpoint_sha256'],doc['nonce'],number(row['mod_revision']))
        except (ValueError,TypeError,KeyError) as exc: raise AuthorityError('Invalid persisted authority record') from exc
    def _write(self,node,pin,compare):
        doc=self._record(node,pin,secrets.token_hex(32))
        # Read the enrolled cluster before any mutation, then require the same cluster in its reply.
        self.current()
        request={'compare':[{'key':self.key,'result':'EQUAL',**compare}], 'success':[{'request_put':{'key':self.key,'value':b64(json.dumps(doc,sort_keys=True,separators=(',',':')).encode())}}]}
        response=self._call('/v3/kv/txn',request)
        require(response.get('succeeded') is True,'Authority changed or already initialized')
        revision=number(response['header'].get('revision'))
        return Grant(node,pin,doc['nonce'],revision)
    def bootstrap(self,node,pin,*,confirm_empty=False):
        require(confirm_empty is True,'Confirm a new, empty authority namespace and no existing coordinator')
        return self._write(node,pin,{'target':'VERSION','version':'0'})
    def transfer(self,revision,node,pin,*,confirm_fenced=False,confirm_latest=False):
        require(confirm_fenced is True and confirm_latest is True,'Require old coordinator fencing and latest-state confirmation')
        revision=number(revision)
        old=self.current(); require(old is not None and old.revision==revision,'Stale or absent authority')
        return self._write(node,pin,{'target':'MOD','mod_revision':str(revision)})

class AuthorityGuard:
    """Fresh, linearizable admission check. NOT a distributed side-effect fence."""
    def __init__(self,authority:Authority,expected:Grant):
        self.authority=authority;self.expected=expected
    def check(self):
        require(self.authority.current()==self.expected,'Coordinator grant is stale or absent')
    @classmethod
    def from_config(cls,doc):
        fields={'endpoint','ca','cert','key','namespace','cluster_id','grant'}
        require(isinstance(doc,dict) and set(doc)==fields,'Invalid distributed authority config')
        require(all(isinstance(doc[k],str) and 0<len(doc[k])<=4096 for k in fields-{'grant','cluster_id'}),'Invalid authority configuration')
        grant=doc['grant'];require(isinstance(grant,dict) and set(grant)=={'node','checkpoint_sha256','nonce','revision'},'Invalid expected grant')
        Authority._record(grant['node'],grant['checkpoint_sha256'],grant['nonce'])
        expected=Grant(grant['node'],grant['checkpoint_sha256'],grant['nonce'],number(grant['revision']))
        rpc=TLSGateway(doc['endpoint'],doc['ca'],doc['cert'],doc['key'])
        return cls(Authority(rpc,doc['namespace'],doc['cluster_id']),expected)

class GuardedCoordinator:
    """Close dispatch admission when the optional registry check fails."""
    def __init__(self,coordinator,guard:AuthorityGuard):
        self.coordinator=coordinator;self.guard=guard
        self.policy=coordinator.policy;self.replay=coordinator.replay
    def handle(self,ident,request):
        self.guard.check()
        return self.coordinator.handle(ident,request)

def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('endpoint','ca','cert','key','cluster-id','namespace'):p.add_argument('--'+name,required=True)
    sub=p.add_subparsers(dest='cmd',required=True); sub.add_parser('status')
    for name in ('bootstrap','transfer'):
        q=sub.add_parser(name);q.add_argument('--node',required=True);q.add_argument('--checkpoint-sha256',required=True)
        if name=='bootstrap':q.add_argument('--confirm-empty',action='store_true',required=True)
        else:
            q.add_argument('--revision',type=int,required=True);q.add_argument('--confirm-fenced',action='store_true',required=True);q.add_argument('--confirm-latest',action='store_true',required=True)
    a=p.parse_args(argv)
    try:
        authority=Authority(TLSGateway(a.endpoint,a.ca,a.cert,a.key),a.namespace,a.cluster_id)
        if a.cmd=='status':grant=authority.current()
        elif a.cmd=='bootstrap':grant=authority.bootstrap(a.node,a.checkpoint_sha256,confirm_empty=a.confirm_empty)
        else:grant=authority.transfer(a.revision,a.node,a.checkpoint_sha256,confirm_fenced=a.confirm_fenced,confirm_latest=a.confirm_latest)
        print(json.dumps(asdict(grant) if grant else None,sort_keys=True));return 0
    except (ValueError,OSError,ssl.SSLError) as exc:print('AUTHORITY ERROR: '+str(exc),file=sys.stderr);return 1

if __name__=='__main__':sys.exit(main())

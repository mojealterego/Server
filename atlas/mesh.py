"""Bounded TLS 1.3 capability admission gateway; no remote command execution."""
from __future__ import annotations
import argparse
import copy
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import socketserver
import sqlite3
import ssl
import stat
import struct
import sys
import threading
import time
from tools.capctl import admit, read_json, canonical, SAFE, integer

MAX_FRAME = 256*1024
HEX = re.compile(r'[a-f0-9]{64}\Z')

class MeshError(ValueError):
    pass


def fingerprint(cert: Path) -> str:
    return hashlib.sha256(ssl.PEM_cert_to_DER_cert(Path(cert).read_text())).hexdigest()


def _context(ca, cert, key, *, server):
    st=Path(key).lstat()
    if not stat.S_ISREG(st.st_mode) or st.st_uid!=os.getuid() or st.st_mode & 0o077:
        raise MeshError('TLS private key must be owner-only regular file')
    ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER if server else ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version=ssl.TLSVersion.TLSv1_3
    ctx.verify_mode=ssl.CERT_REQUIRED
    ctx.load_verify_locations(cafile=str(ca))
    ctx.load_cert_chain(str(cert),str(key),password='')
    if server:
        ctx.num_tickets=0
    else:
        ctx.check_hostname=True
        ctx.hostname_checks_common_name=False
    return ctx


def server_context(ca,cert,key):return _context(ca,cert,key,server=True)
def client_context(ca,cert,key):return _context(ca,cert,key,server=False)


def _remaining(sock,deadline):
    remain=deadline-time.monotonic()
    if remain<=0:raise MeshError('Frame deadline exceeded')
    sock.settimeout(remain)


def _read_exact(sock,n,deadline):
    data=bytearray()
    while len(data)<n:
        _remaining(sock,deadline)
        part=sock.recv(min(65536,n-len(data)))
        if not part:raise MeshError('Incomplete frame')
        data.extend(part)
    return bytes(data)


def recv_frame(sock,deadline):
    n,=struct.unpack('!I',_read_exact(sock,4,deadline))
    if not 1<=n<=MAX_FRAME:raise MeshError('Invalid frame size')
    def unique(pairs):
        out={}
        for k,v in pairs:
            if k in out:raise MeshError('Duplicate JSON key')
            out[k]=v
        return out
    def invalid(_):raise MeshError('Nonfinite JSON number')
    return json.loads(_read_exact(sock,n,deadline).decode('utf-8'),object_pairs_hook=unique,parse_constant=invalid)


def send_frame(sock,obj,deadline):
    data=canonical(obj)
    if not 1<=len(data)<=MAX_FRAME:raise MeshError('Invalid frame size')
    _remaining(sock,deadline)
    sock.sendall(struct.pack('!I',len(data))+data)


def _peer_pin(sock):
    cert=sock.getpeercert(binary_form=True)
    if not cert:raise MeshError('Missing peer certificate')
    return hashlib.sha256(cert).hexdigest()


def submit(host,port,ctx,server_pin,envelope,*,timeout=10):
    if not isinstance(server_pin,str) or not HEX.fullmatch(server_pin):raise MeshError('Invalid server certificate pin')
    if not integer(port,1,65535) or not integer(timeout,1,60):raise MeshError('Invalid port/timeout')
    if ctx.verify_mode!=ssl.CERT_REQUIRED or not ctx.check_hostname or ctx.minimum_version<ssl.TLSVersion.TLSv1_2:
        raise MeshError('Unsafe TLS client context')
    deadline=time.monotonic()+timeout
    try:
        with socket.create_connection((host,port),timeout=timeout) as raw:
            _remaining(raw,deadline)
            with ctx.wrap_socket(raw,server_hostname=host) as peer:
                if peer.version()!='TLSv1.3' or _peer_pin(peer)!=server_pin:raise MeshError('Unpinned TLS server')
                send_frame(peer,{'op':'admit','envelope':envelope},deadline)
                reply=recv_frame(peer,deadline)
                if not isinstance(reply,dict) or reply.get('status')!='ADMITTED':raise MeshError('Admission rejected')
                if set(reply)!={'status','node','issued_ns'} or reply['issued_ns']!=envelope['issued_ns'] or reply['node'].get('id')!=envelope['node']['id']:
                    raise MeshError('Receipt binding mismatch')
                return reply
    except (OSError,ValueError,KeyError,TypeError,AttributeError,RecursionError) as exc:
        raise MeshError('Mesh request failed: '+str(exc)) from exc


class MeshServer(socketserver.ThreadingTCPServer):
    daemon_threads=True
    allow_reuse_address=True
    request_queue_size=16
    def __init__(self,address,ctx,policy,pins,db,*,timeout=10,ttl=120,max_clients=8,allow_network=False):
        bind,port=address
        ip=ipaddress.IPv4Address(bind)
        if not ip.is_loopback and (not allow_network or ip.is_unspecified or ip.is_multicast):
            raise MeshError('Explicit non-wildcard IPv4 bind and network opt-in required')
        if ctx.verify_mode!=ssl.CERT_REQUIRED or ctx.minimum_version!=ssl.TLSVersion.TLSv1_3:
            raise MeshError('Unsafe server TLS context')
        if not integer(timeout,1,60) or not integer(ttl,1,300) or not integer(max_clients,1,32):raise MeshError('Invalid server limits')
        if not isinstance(policy,dict) or not isinstance(pins,dict) or not 1<=len(pins)<=256 or len(set(pins.values()))!=len(pins):raise MeshError('Invalid certificate registry')
        if any(not isinstance(k,str) or not HEX.fullmatch(k) or not isinstance(v,str) or v not in policy or not SAFE.fullmatch(v) for k,v in pins.items()):raise MeshError('Invalid certificate enrollment')
        self.ctx=ctx;self.policy=copy.deepcopy(policy);self.pins=dict(pins);self.db=Path(db)
        self.timeout=timeout;self.ttl=ttl;self.slots=threading.BoundedSemaphore(max_clients)
        super().__init__(address,MeshHandler)

    def process_request(self,request,address):
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request);return
        try:super().process_request(request,address)
        except BaseException:
            self.slots.release();raise

    def process_request_thread(self,request,address):
        try:super().process_request_thread(request,address)
        finally:self.slots.release()


class MeshHandler(socketserver.BaseRequestHandler):
    def handle(self):
        server=self.server;deadline=time.monotonic()+server.timeout
        try:
            _remaining(self.request,deadline)
            with server.ctx.wrap_socket(self.request,server_side=True) as peer:
                if peer.version()!='TLSv1.3':return
                ident=server.pins.get(_peer_pin(peer))
                if ident is None:return
                try:
                    req=recv_frame(peer,deadline)
                    if not isinstance(req,dict) or set(req)!={'op','envelope'} or req['op']!='admit':raise MeshError('Unsupported request')
                    envelope=req['envelope']
                    if envelope['node']['id']!=ident:raise MeshError('Certificate does not own node')
                    node,=admit([envelope],server.policy,server.db,ttl=server.ttl)
                    out={'status':'ADMITTED','node':node,'issued_ns':envelope['issued_ns']}
                except (ValueError,OSError,KeyError,TypeError,AttributeError,sqlite3.Error,RecursionError):
                    out={'status':'REJECTED'}
                send_frame(peer,out,deadline)
        except (OSError,ValueError,RecursionError):
            return


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    sub=p.add_subparsers(dest='cmd',required=True)
    s=sub.add_parser('serve');c=sub.add_parser('submit');f=sub.add_parser('fingerprint');f.add_argument('cert',type=Path)
    for q in (s,c):
        for name in ('ca','cert','key'):q.add_argument('--'+name,type=Path,required=True)
        q.add_argument('--port',type=int,default=8443);q.add_argument('--timeout',type=int,default=10)
    s.add_argument('--bind',default='127.0.0.1');s.add_argument('--allow-network',action='store_true')
    for name in ('policy','pins','db'):s.add_argument('--'+name,type=Path,required=True)
    s.add_argument('--ttl',type=int,default=120);s.add_argument('--max-clients',type=int,default=8)
    c.add_argument('--host',required=True);c.add_argument('--server-pin',required=True);c.add_argument('--envelope',type=Path,required=True)
    a=p.parse_args(argv)
    try:
        if a.cmd=='fingerprint':print(fingerprint(a.cert))
        elif a.cmd=='serve':
            ctx=server_context(a.ca,a.cert,a.key)
            with MeshServer((a.bind,a.port),ctx,read_json(a.policy),read_json(a.pins),a.db,timeout=a.timeout,ttl=a.ttl,max_clients=a.max_clients,allow_network=a.allow_network) as server:
                print('Mesh listening on '+str(server.server_address),file=sys.stderr,flush=True)
                server.serve_forever()
        else:
            ctx=client_context(a.ca,a.cert,a.key)
            print(json.dumps(submit(a.host,a.port,ctx,a.server_pin,read_json(a.envelope),timeout=a.timeout),sort_keys=True))
        return 0
    except KeyboardInterrupt:return 130
    except (ValueError,OSError,KeyError,TypeError,sqlite3.Error,RecursionError) as exc:
        print('MESH ERROR: '+str(exc),file=sys.stderr);return 1

if __name__=='__main__':sys.exit(main())

"""Real TLS sockets and client-certificate authentication; etcd RPC fixture."""
import http.server
import json
from pathlib import Path
import shutil
import ssl
import subprocess
import tempfile
import threading
import unittest
from atlas.distributed_authority import Authority, AuthorityError, TLSGateway
from test_distributed_authority import TxnFixture

@unittest.skipUnless(shutil.which('openssl'),'OpenSSL required for TLS fixture')
class GatewayTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp=tempfile.TemporaryDirectory(); cls.addClassCleanup(cls.tmp.cleanup)
        cls.root=Path(cls.tmp.name)
        def openssl(*args):
            subprocess.run(['openssl',*args],cwd=cls.root,check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=15)
        openssl('req','-x509','-newkey','rsa:2048','-nodes','-days','2','-subj','/CN=OMEGA-test-CA','-addext','basicConstraints=critical,CA:TRUE','-addext','keyUsage=critical,keyCertSign,cRLSign','-keyout','ca.key','-out','ca.pem')
        for name,usage,extra in [('server','serverAuth','subjectAltName=IP:127.0.0.1\n'),('client','clientAuth','')]:
            (cls.root/(name+'.ext')).write_text('basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage='+usage+'\n'+extra)
            openssl('req','-new','-newkey','rsa:2048','-nodes','-subj','/CN='+name,'-keyout',name+'.key','-out',name+'.csr')
            openssl('x509','-req','-in',name+'.csr','-CA','ca.pem','-CAkey','ca.key','-CAcreateserial','-days','2','-extfile',name+'.ext','-out',name+'.pem')
        openssl('req','-x509','-newkey','rsa:2048','-nodes','-days','2','-subj','/CN=untrusted','-keyout','bad.key','-out','bad.pem')
    def setUp(self):
        self.fixture=TxnFixture(); self.mode='normal'; self.requests=0; test=self
        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self,*args): pass
            def do_POST(self):
                test.requests+=1
                body=json.loads(self.rfile.read(int(self.headers['Content-Length'])))
                if test.mode=='redirect':
                    self.send_response(302);self.send_header('Location','https://127.0.0.1:1/');self.end_headers();return
                if test.mode=='oversize':raw=b' '*65537
                else:raw=json.dumps(test.fixture(self.path,body)).encode()
                self.send_response(200);self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw)
        self.server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler)
        ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);ctx.load_cert_chain(self.root/'server.pem',self.root/'server.key');ctx.load_verify_locations(self.root/'ca.pem');ctx.verify_mode=ssl.CERT_REQUIRED
        self.server.socket=ctx.wrap_socket(self.server.socket,server_side=True)
        self.thread=threading.Thread(target=self.server.serve_forever,daemon=True);self.thread.start()
        self.addCleanup(self.thread.join,2);self.addCleanup(self.server.server_close);self.addCleanup(self.server.shutdown)
    def gateway(self,host='127.0.0.1',client='client'):
        return TLSGateway(f'https://{host}:{self.server.server_port}',self.root/'ca.pem',self.root/(client+'.pem'),self.root/(client+'.key'))
    def test_real_mtls_and_transfer(self):
        a=Authority(self.gateway(),'omega','42');grant=a.bootstrap('node1','a'*64,confirm_empty=True)
        self.assertEqual(a.current(),grant)
        self.assertEqual(a.transfer(grant.revision,'node2','b'*64,confirm_fenced=True,confirm_latest=True).node,'node2')
    def test_untrusted_certificate_rejected(self):
        with self.assertRaises(AuthorityError):Authority(self.gateway(client='bad'),'omega','42').current()
        self.assertEqual(self.requests,0)
    def test_wrong_hostname_rejected(self):
        with self.assertRaises(AuthorityError):Authority(self.gateway(host='localhost'),'omega','42').current()
        self.assertEqual(self.requests,0)
    def test_redirect_rejected(self):
        self.mode='redirect'
        with self.assertRaises(AuthorityError):Authority(self.gateway(),'omega','42').current()
        self.assertEqual(self.requests,1)
    def test_oversize_body_rejected(self):
        self.mode='oversize'
        with self.assertRaises(AuthorityError):Authority(self.gateway(),'omega','42').current()
    def test_wrong_cluster_cannot_mutate(self):
        with self.assertRaises(AuthorityError):Authority(self.gateway(),'omega','43').bootstrap('node1','a'*64,confirm_empty=True)
        self.assertIsNone(self.fixture.row);self.assertEqual(self.requests,1)

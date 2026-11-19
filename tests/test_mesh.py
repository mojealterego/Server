import json,socket,ssl,struct,subprocess,sys,tempfile,threading,time,unittest
from pathlib import Path
from atlas.mesh import MeshServer, client_context, server_context, submit, MeshError, fingerprint, send_frame, recv_frame, MAX_FRAME
from tools.capctl import sign

class MeshTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp=tempfile.TemporaryDirectory();cls.root=Path(cls.tmp.name)
        cls.addClassCleanup(cls.tmp.cleanup)
        def cmd(*args):subprocess.run(['openssl',*map(str,args)],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        for ca in ('ca','alien'):
            cmd('req','-x509','-newkey','ec','-pkeyopt','ec_paramgen_curve:P-256','-nodes','-days','2','-subj','/CN='+ca,'-keyout',cls.root/(ca+'.key'),'-out',cls.root/(ca+'.pem'))
        for name,ca,usage in [('server','ca','serverAuth'),('node','ca','clientAuth'),('unknown','ca','clientAuth'),('alien','alien','clientAuth')]:
            # Keep alien CA and client certificate paths distinct.
            if name=='alien': name='foreign'
            key=cls.root/(name+'.key');csr=cls.root/(name+'.csr');cert=cls.root/(name+'.pem');ext=cls.root/(name+'.ext')
            cmd('req','-new','-newkey','ec','-pkeyopt','ec_paramgen_curve:P-256','-nodes','-subj','/CN='+name,'-keyout',key,'-out',csr)
            key.chmod(0o600);ext.write_text('basicConstraints=CA:FALSE\nextendedKeyUsage='+usage+'\nsubjectAltName=IP:127.0.0.1\n')
            cmd('x509','-req','-in',csr,'-CA',cls.root/(ca+'.pem'),'-CAkey',cls.root/(ca+'.key'),'-CAcreateserial','-days','1','-extfile',ext,'-out',cert)
        cls.signkey=cls.root/'sign.pem';cmd('genpkey','-algorithm','ED25519','-out',cls.signkey);cls.signkey.chmod(0o600)
        cls.node={'id':'phone','ram_available_mb':1000,'ram_headroom_mb':128,'disk_free_bytes':5000,'thermal_c':31,'capabilities':['llama'],'models':['m']}
        env=sign(cls.node,cls.signkey)
        cls.policy={'phone':{'public_key':env['public_key'],'trust':'local','priority':1,'max_ram_mb':2000,'min_headroom_mb':128,'max_disk_bytes':10000,'capabilities':['llama'],'models':['m']}}
        cls.pin=fingerprint(cls.root/'server.pem');cls.nodepin=fingerprint(cls.root/'node.pem')
    def setUp(self):
        tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup);self.db=Path(tmp.name)/'replay.db'
        self.server=MeshServer(('127.0.0.1',0),server_context(self.root/'ca.pem',self.root/'server.pem',self.root/'server.key'),self.policy,{self.nodepin:'phone'},self.db,timeout=2)
        self.thread=threading.Thread(target=self.server.serve_forever,kwargs={'poll_interval':.02},daemon=True);self.thread.start()
        self.addCleanup(self.stop)
    def stop(self):self.server.shutdown();self.server.server_close();self.thread.join(3)
    def context(self,name='node',ca='ca'):
        return client_context(self.root/(ca+'.pem'),self.root/(name+'.pem'),self.root/(name+'.key'))
    def call(self,env=None,ctx=None,pin=None):
        return submit('127.0.0.1',self.server.server_address[1],ctx or self.context(),pin or self.pin,env or sign(self.node,self.signkey),timeout=3)
    def raw(self,ctx=None):
        return (ctx or self.context()).wrap_socket(socket.create_connection(self.server.server_address,timeout=2),server_hostname='127.0.0.1')
    def test_real_tls_and_replay(self):
        env=sign(self.node,self.signkey);r=self.call(env)
        self.assertEqual(r['node']['id'],'phone');self.assertEqual(r['status'],'ADMITTED');self.assertEqual(r['issued_ns'],env['issued_ns'])
        with self.assertRaises(MeshError):self.call(env)
    def test_wrong_server_pin_does_not_consume(self):
        env=sign(self.node,self.signkey)
        with self.assertRaises(MeshError):self.call(env,pin='0'*64)
        self.assertEqual(self.call(env)['status'],'ADMITTED')
    def test_trusted_ca_but_unenrolled_cert(self):
        env=sign(self.node,self.signkey)
        with self.assertRaises(MeshError):self.call(env,ctx=self.context('unknown'))
        self.assertEqual(self.call(env)['status'],'ADMITTED')
    def test_untrusted_client_certificate(self):
        with self.assertRaises(MeshError):self.call(ctx=self.context('foreign'))
    def test_missing_client_certificate(self):
        ctx=ssl.create_default_context(cafile=str(self.root/'ca.pem'));ctx.minimum_version=ssl.TLSVersion.TLSv1_3
        with self.assertRaises(MeshError):self.call(ctx=ctx)
    def test_signed_identity_mismatch_and_tamper(self):
        with self.assertRaises(MeshError):self.call(sign({**self.node,'id':'other'},self.signkey))
        env=sign(self.node,self.signkey);env['node']['thermal_c']=30
        with self.assertRaises(MeshError):self.call(env)
    def test_frame_limit_and_duplicate_json(self):
        with self.raw() as s:
            s.sendall(struct.pack('!I',MAX_FRAME+1));self.assertEqual(recv_frame(s,time.monotonic()+2)['status'],'REJECTED')
        with self.raw() as s:
            b=b'{"op":"admit","op":"other"}';s.sendall(struct.pack('!I',len(b))+b);self.assertEqual(recv_frame(s,time.monotonic()+2)['status'],'REJECTED')
    def test_unsupported_operation(self):
        with self.raw() as s:
            send_frame(s,{'op':'execute'},time.monotonic()+2);self.assertEqual(recv_frame(s,time.monotonic()+2)['status'],'REJECTED')
    def test_expired_declaration(self):
        with self.assertRaises(MeshError):self.call(sign(self.node,self.signkey,time.time_ns()-400*10**9))
    def test_hostname_validation(self):
        with self.assertRaises(MeshError):submit('localhost',self.server.server_address[1],self.context(),self.pin,sign(self.node,self.signkey),timeout=3)
    def test_concurrent_duplicates(self):
        from concurrent.futures import ThreadPoolExecutor
        env=sign(self.node,self.signkey)
        def attempt(_):
            try:self.call(env);return True
            except MeshError:return False
        with ThreadPoolExecutor(max_workers=4) as ex:self.assertEqual(sum(ex.map(attempt,range(4))),1)
    def test_tls12_refused(self):
        ctx=self.context();ctx.minimum_version=ssl.TLSVersion.TLSv1_2;ctx.maximum_version=ssl.TLSVersion.TLSv1_2
        with self.assertRaises(MeshError):self.call(ctx=ctx)
    def test_idle_client_cannot_hold_slot_indefinitely(self):
        # Exhaust active slots with handshakes that never finish.
        sockets=[socket.create_connection(self.server.server_address,timeout=2) for _ in range(8)]
        try:
            end=time.monotonic()+1
            while self.server.slots._value and time.monotonic()<end:time.sleep(.01)
            self.assertEqual(self.server.slots._value,0)
            with self.assertRaises(MeshError):self.call()
            end=time.monotonic()+4
            while self.server.slots._value<8 and time.monotonic()<end:time.sleep(.02)
            self.assertEqual(self.server.slots._value,8)
            self.assertEqual(self.call()['status'],'ADMITTED')
        finally:
            for s in sockets:s.close()
    def test_wildcard_listen_rejected(self):
        ctx=server_context(self.root/'ca.pem',self.root/'server.pem',self.root/'server.key')
        with self.assertRaises(MeshError):
            MeshServer(('0.0.0.0',0),ctx,self.policy,{self.nodepin:'phone'},self.db,allow_network=True)
    def test_cli_separate_client_and_server(self):
        policy=self.db.parent/'policy.json';policy.write_text(json.dumps(self.policy))
        pins=self.db.parent/'pins.json';pins.write_text(json.dumps({self.nodepin:'phone'}))
        env=self.db.parent/'env.json';env.write_text(json.dumps(sign(self.node,self.signkey)))
        proc=subprocess.Popen([sys.executable,'-m','atlas.mesh','serve','--port','0','--ca',str(self.root/'ca.pem'),'--cert',str(self.root/'server.pem'),'--key',str(self.root/'server.key'),'--policy',str(policy),'--pins',str(pins),'--db',str(self.db.parent/'cli.db')],stderr=subprocess.PIPE,text=True)
        try:
            import select,ast
            self.assertTrue(select.select([proc.stderr],[],[],5)[0])
            line=proc.stderr.readline();self.assertTrue(line.startswith('Mesh listening on '),line)
            _,port=ast.literal_eval(line.removeprefix('Mesh listening on '))
            result=subprocess.run([sys.executable,'-m','atlas.mesh','submit','--host','127.0.0.1','--port',str(port),'--ca',str(self.root/'ca.pem'),'--cert',str(self.root/'node.pem'),'--key',str(self.root/'node.key'),'--server-pin',self.pin,'--envelope',str(env)],capture_output=True,text=True,timeout=10)
            self.assertEqual(result.returncode,0,result.stderr);self.assertEqual(json.loads(result.stdout)['status'],'ADMITTED')
        finally:
            proc.terminate();proc.wait(timeout=5);proc.stderr.close()
    def test_key_permissions(self):
        with tempfile.TemporaryDirectory() as t:
            key=Path(t)/'bad.key';key.write_bytes((self.root/'node.key').read_bytes());key.chmod(0o644)
            with self.assertRaises(MeshError):client_context(self.root/'ca.pem',self.root/'node.pem',key)

if __name__=='__main__':unittest.main()

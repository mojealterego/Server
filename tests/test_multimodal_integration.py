"""Actual PHASESHIFT, LeaseStore, guardian, CAS, HTTP and FFmpeg; synthetic engines."""
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
from atlas.artifacts import ArtifactStore
from atlas.phaselease import LeaseStore
from atlas.phaseshift import compile_workflow
from tools.capctl import sign

ROOT=Path(__file__).resolve().parents[1]

class ModelHandler(BaseHTTPRequestHandler):
    def reply(self,obj):
        data=json.dumps(obj).encode();self.send_response(200);self.send_header('Content-Length',str(len(data)));self.end_headers();self.wfile.write(data)
    def do_GET(self):
        if self.path=='/health':self.reply({'status':'ok'})
        elif self.path=='/v1/models':self.reply({'data':[{'id':'qwen-test'}]})
        else:self.send_error(404)
    def do_POST(self):
        if self.path!='/v1/chat/completions':self.send_error(404);return
        body=json.loads(self.rfile.read(int(self.headers['Content-Length'])));self.server.requests.append(body)
        self.reply({'choices':[{'message':{'content':self.server.answer}}]})
    def log_message(self,*_):pass

class PipelineIntegration(unittest.TestCase):
    def setUp(self):
        t=tempfile.TemporaryDirectory();self.addCleanup(t.cleanup);self.root=Path(t.name)
        self.http=ThreadingHTTPServer(('127.0.0.1',0),ModelHandler);self.http.requests=[];self.http.answer='red square'
        self.thread=threading.Thread(target=self.http.serve_forever,kwargs={'poll_interval':.05},daemon=True);self.thread.start();self.addCleanup(self.close_server)
        self.c={};paths={}
        for mid,fam,role in [('q','qwen','llm'),('f','flux1','image_dit'),('c','flux1','clip_l'),('t','flux1','t5xxl'),('v','flux1','vae'),('w','wan','video_dit'),('wt','wan','t5xxl'),('wv','wan','vae')]:
            file=self.root/(mid+'.gguf');file.write_bytes(mid.encode());paths[mid]=str(file)
            self.c[mid]={'bytes':len(mid),'format':'gguf','role':role,'family':fam,'bundle':fam+'-test','profiles':{'flux1':['flux1'],'wan':['wan_i2v']}.get(fam,[]),'lineage_verified':True,'sha256':hashlib.sha256(mid.encode()).hexdigest()}
        def task(id,engine,models,recipe,deps=()):return {'id':id,'engine':engine,'models':models,'recipe':recipe,'depends_on':list(deps),'privacy':'local_only','ram_mb':16,'output_bytes':1024*1024}
        self.tasks=[task('prompt','llama',['q'],{'kind':'qwen_text','prompt':'Create a short description','runtime_model':'qwen-test'}),task('image','sd-cli',['f','c','t','v'],{'kind':'flux1','prompt_from':'prompt','slots':{'diffusion_model':'f','clip_l':'c','t5xxl':'t','vae':'v'},'width':64,'height':64,'steps':4},['prompt']),task('video','sd-cli',['w','wt','wv'],{'kind':'wan_i2v','prompt_from':'prompt','image_from':'image','slots':{'diffusion_model':'w','t5xxl':'wt','vae':'wv'},'width':64,'height':64,'steps':4,'frames':5,'fps':5},['prompt','image'])]
        self.tasks[0]['runtime_model_ids']={'qwen-test':'q'}
        self.nodes=[{'id':'phone','trust':'local','capabilities':['llama','sd-cli'],'models':list(self.c),'ram_available_mb':1000,'ram_headroom_mb':100,'disk_free_bytes':10*1024*1024,'thermal_c':30,'priority':1}]
        self.plan=compile_workflow(self.tasks,self.nodes,self.c)
        self.marker=self.root/'bad-video';self.trace=self.root/'trace'
        self.ffmpeg=str(Path(shutil.which('ffmpeg')).resolve());ffprobe=str(Path(shutil.which('ffprobe')).resolve())
        fake=self.root/'sd-cli';fake.write_text(f'#!{sys.executable}\n'+f'''import sys, subprocess
from pathlib import Path
argv=sys.argv[1:]; value=lambda flag:argv[argv.index(flag)+1]
assert value('-p')=='red square'
video=value('--mode')=='vid_gen'
if video and '-i' in argv:assert Path(value('-i')).read_bytes().startswith(b'\\x89PNG')
with Path({str(self.trace)!r}).open('a') as log:log.write(('video' if video else 'image')+'\\n')
output=Path(value('-o'))
if video and Path({str(self.marker)!r}).exists():output.write_bytes(b'corrupt media');sys.exit(0)
subprocess.run([{self.ffmpeg!r},'-v','error','-f','lavfi','-i','color=red:s=64x64:r=5','-frames:v','5' if video else '1','-threads','1',str(output)],check=True)
''');fake.chmod(0o700)
        self.deploy={'node':'phone','llama_endpoint':f'http://127.0.0.1:{self.http.server_port}','sd_cli':str(fake),'ffprobe':ffprobe,'ffmpeg':self.ffmpeg,'backend':'cpu','model_paths':paths}
        for name,value in [('tasks',self.tasks),('nodes',self.nodes),('catalog',self.c),('plan',self.plan),('deployment',self.deploy)]:self.write(name,value)
    def close_server(self):self.http.shutdown();self.http.server_close();self.thread.join(2)
    def write(self,name,value):
        p=self.root/(name+'.json');p.write_text(json.dumps(value));return p
    def invoke(self,*args):
        argv=[sys.executable,str(ROOT/'tools'/'multictl.py'),'--node','phone','--timeout','15']
        for name in ('tasks','nodes','catalog','plan','deployment'):argv+=['--'+name,str(self.root/(name+'.json'))]
        for name in ('db','cas','work'):argv+=['--'+name,str(self.root/name)]
        return subprocess.run(argv+list(args),capture_output=True,text=True,timeout=45)
    def state(self,tid):
        with LeaseStore(self.root/'db',self.plan,self.tasks,self.nodes,self.c,artifacts=ArtifactStore(self.root/'cas')) as lease:return lease.status(tid)
    def test_real_stack_and_resume(self):
        result=self.invoke();self.assertEqual(result.returncode,0,result.stderr);report=json.loads(result.stdout)
        self.assertEqual(len(report['stages']),3);self.assertEqual(self.trace.read_text(),'image\nvideo\n');self.assertEqual(len(self.http.requests),1)
        cas=ArtifactStore(self.root/'cas')
        for row in report['stages']:self.assertTrue(cas.verify(row['sha256']));self.assertEqual(self.state(row['task'])['state'],'COMPLETED')
        result=self.invoke();self.assertEqual(result.returncode,0,result.stderr)
        self.assertTrue(all(x['status']=='REUSED' for x in json.loads(result.stdout)['stages']));self.assertEqual(self.trace.read_text(),'image\nvideo\n');self.assertEqual(len(self.http.requests),1)
    def setup_video_variant(self,kind):
        t=self.tasks[2];self.tasks[:]=[self.tasks[0],t];t['depends_on']=['prompt'];r=t['recipe'];r.pop('image_from');r['kind']=kind
        if kind=='wan_t2v':self.c['w']['profiles'].append(kind)
        else:
            r['slots']={'diffusion_model':'w','llm':'wt','embeddings_connectors':'lc','vae':'wv'};t['models']=['w','wt','lc','wv']
            self.c['w']['profiles']=[kind];self.c['wt']['role']='llm'
            extra=self.root/'lc.gguf';extra.write_bytes(b'lc');self.deploy['model_paths']['lc']=str(extra)
            self.c['lc']={'bytes':2,'format':'gguf','role':'embeddings_connectors','lineage_verified':True,'sha256':hashlib.sha256(b'lc').hexdigest()}
            for m in t['models']:self.c[m].update(family='ltx2',bundle='ltx2-test')
            self.nodes[0]['models']=list(self.c)
        self.plan=compile_workflow(self.tasks,self.nodes,self.c)
        for n,x in [('tasks',self.tasks),('nodes',self.nodes),('plan',self.plan),('catalog',self.c),('deployment',self.deploy)]:self.write(n,x)
    def test_wan_text_video_pipeline(self):
        self.setup_video_variant('wan_t2v');result=self.invoke();self.assertEqual(result.returncode,0,result.stderr);self.assertEqual(self.trace.read_text(),'video\n');self.assertEqual(self.state('video')['state'],'COMPLETED')
    def test_ltx_text_video_pipeline(self):
        self.setup_video_variant('ltx2');result=self.invoke();self.assertEqual(result.returncode,0,result.stderr);self.assertEqual(self.trace.read_text(),'video\n');self.assertEqual(self.state('video')['state'],'COMPLETED')
    def test_corrupt_video_fails_before_cas_then_explicit_retry(self):
        self.marker.touch();result=self.invoke();self.assertNotEqual(result.returncode,0,result.stdout)
        self.assertEqual(self.state('video')['state'],'FAILED');self.assertEqual(len(list((self.root/'cas'/'objects').iterdir())),2)
        self.marker.unlink();result=self.invoke();self.assertEqual(result.returncode,2,result.stderr);self.assertEqual(self.trace.read_text(),'image\nvideo\n')
        result=self.invoke('--retry-failed');self.assertEqual(result.returncode,0,result.stderr);self.assertEqual(self.state('video')['epoch'],2)
        self.assertEqual(self.trace.read_text(),'image\nvideo\nvideo\n');self.assertEqual(len(self.http.requests),1)
    def test_malformed_text_never_published(self):
        self.http.answer='\x00 invalid';result=self.invoke();self.assertNotEqual(result.returncode,0)
        self.assertEqual(self.state('prompt')['state'],'FAILED');self.assertEqual(self.state('image')['state'],'PENDING');self.assertFalse(list((self.root/'cas'/'objects').iterdir()));self.assertFalse(self.trace.exists())
    def test_plan_tamper_no_execution(self):
        self.tasks[0]['recipe']['prompt']='tampered';self.write('tasks',self.tasks)
        result=self.invoke();self.assertNotEqual(result.returncode,0);self.assertIn('fingerprint',result.stderr);self.assertFalse(self.trace.exists());self.assertFalse(self.http.requests)
    def test_runtime_guard_actually_blocks(self):
        key=self.root/'cap.pem';subprocess.run(['openssl','genpkey','-algorithm','ED25519','-out',str(key)],check=True);key.chmod(0o600)
        env=sign({k:v for k,v in self.nodes[0].items() if k not in ('trust','priority')},key)
        policy={'phone':{'public_key':env['public_key'],'trust':'local','priority':1,'max_ram_mb':2000,'min_headroom_mb':100,'max_disk_bytes':20*1024*1024,'capabilities':['llama','sd-cli'],'models':list(self.c)}}
        self.write('policy',policy);envdir=self.root/'envelopes';envdir.mkdir(mode=0o700);(envdir/'prompt.json').write_text(json.dumps(env))
        sensor=self.root/'thermal';sensor.write_text('44000')
        result=self.invoke('--runtime-envelope-dir',str(envdir),'--runtime-policy',str(self.root/'policy.json'),'--runtime-db',str(self.root/'runtime.db'),'--thermal-file',str(sensor))
        self.assertNotEqual(result.returncode,0);self.assertIn('RUNTIME_GUARD',result.stderr);self.assertEqual(self.state('prompt')['state'],'PENDING');self.assertFalse(self.http.requests)

if __name__=='__main__':unittest.main()

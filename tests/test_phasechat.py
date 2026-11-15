"""Real localhost HTTP, subprocess, SQLite and CAS integration checks for PHASECHAT."""
from __future__ import annotations
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest

from atlas.phaseshift import compile_workflow

ROOT=Path(__file__).resolve().parents[1]

class FakeLlamaHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path=='/health':
            self.server.health_calls+=1
            if self.server.health_calls<=self.server.unready_count:
                self.reply(503,{'error':{'message':'Loading model'}})
            else:
                self.reply(200,{'status':'ok'})
        elif self.path=='/v1/models':
            self.reply(200,{'data':[{'id':'qwen-local'}]})
        elif self.path=='/redirect':
            self.send_response(302);self.send_header('Location','http://example.com');self.end_headers()
        else:self.reply(404,{'error':'missing'})
    def do_POST(self):
        if self.path!='/v1/chat/completions':self.reply(404,{'error':'missing'});return
        self.server.posts+=1
        n=int(self.headers.get('Content-Length','0'))
        payload=json.loads(self.rfile.read(n))
        self.server.payload=payload
        if self.server.return_invalid:self.reply(200,{'choices':[]})
        else:self.reply(200,{'choices':[{'message':{'content':'Model zwrócił prawdziwy wynik'}}]})
    def reply(self,status,payload):
        body=json.dumps(payload).encode()
        self.send_response(status);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(body)))
        self.end_headers();self.wfile.write(body)
    def log_message(self,*args):pass

class LlamaPhaseIntegration(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.root=Path(self.temp.name)
        self.server=ThreadingHTTPServer(('127.0.0.1',0),FakeLlamaHandler)
        self.server.unready_count=0;self.server.health_calls=0;self.server.posts=0
        self.server.return_invalid=False;self.server.payload={}
        self.server_thread=threading.Thread(target=self.server.serve_forever,daemon=True)
        self.server_thread.start()
        self.endpoint=f'http://127.0.0.1:{self.server.server_port}'
        self.prompt=self.root/'prompt.txt';self.prompt.write_text('Co widzisz na zdjęciu?',encoding='utf-8')
        tasks=[{'id':'describe','engine':'llama','models':['qwen'],'ram_mb':64,'duration_slots':1,'output_bytes':2048,'privacy':'local_only','runtime_model_ids':{'qwen-local':'qwen'}}]
        nodes=[{'id':'s24','trust':'local','capabilities':['llama'],'models':['qwen'],'ram_available_mb':1024,'ram_headroom_mb':128,'disk_free_bytes':10000,'thermal_c':30,'priority':0}]
        catalog={'qwen':{'bytes':10,'format':'gguf','role':'llm','lineage_verified':True}}
        plan=compile_workflow(tasks,nodes,catalog)
        for name,value in [('tasks',tasks),('nodes',nodes),('catalog',catalog),('plan',plan)]:
            (self.root/f'{name}.json').write_text(json.dumps(value),encoding='utf-8')
    def tearDown(self):
        self.server.shutdown();self.server.server_close();self.server_thread.join(timeout=2);self.temp.cleanup()
    def args(self,**options):
        argv=[sys.executable,str(ROOT/'tools/phasechat.py'),
              '--tasks',str(self.root/'tasks.json'),'--nodes',str(self.root/'nodes.json'),
              '--catalog',str(self.root/'catalog.json'),'--plan',str(self.root/'plan.json'),
              '--db',str(self.root/'leases.db'),'--cas',str(self.root/'cas'),
              '--work',str(self.root/'work'),'--task','describe','--node','s24',
              '--endpoint',options.get('endpoint',self.endpoint),'--model',options.get('model','qwen-local'),
              '--prompt-file',str(options.get('prompt',self.prompt)),
              '--ready-timeout','3','--request-timeout','3','--timeout','8']
        return argv
    def call(self,**kw):
        return subprocess.run(self.args(**kw),capture_output=True,text=True,timeout=15)
    def test_e2e_real_http_process_and_cas_receipt(self):
        self.server.unready_count=2
        result=self.call()
        self.assertEqual(result.returncode,0,result.stderr)
        info=json.loads(result.stdout)
        self.assertEqual(info['status'],'COMPLETED')
        expected='Model zwrócił prawdziwy wynik'.encode()
        sha=hashlib.sha256(expected).hexdigest()
        self.assertEqual(info['sha256'],sha)
        self.assertEqual((self.root/'cas'/'objects'/sha).read_bytes(),expected)
        self.assertEqual(self.server.health_calls,3)
        self.assertEqual(self.server.posts,1)
        self.assertEqual(self.server.payload['model'],'qwen-local')
        self.assertEqual(self.server.payload['messages'][0]['content'],'Co widzisz na zdjęciu?')
        self.assertFalse(list((self.root/'work').glob('*.txt')))
    def test_mismatched_model_fails_without_post(self):
        result=self.call(model='not-here')
        self.assertNotEqual(result.returncode,0)
        self.assertEqual(self.server.posts,0)
        self.assertFalse((self.root/'cas'/'objects').exists())
    def test_external_endpoint_blocked_before_claim(self):
        result=self.call(endpoint='http://169.254.169.254:80')
        self.assertNotEqual(result.returncode,0)
        self.assertEqual(self.server.posts,0)
    def test_invalid_response_cannot_be_published(self):
        self.server.return_invalid=True
        result=self.call()
        self.assertNotEqual(result.returncode,0)
        self.assertEqual(self.server.posts,1)
        self.assertFalse(list((self.root/'cas'/'objects').iterdir()))
    def test_prompt_symlink_refused(self):
        link=self.root/'prompt-link.txt';link.symlink_to(self.prompt)
        result=self.call(prompt=link)
        self.assertNotEqual(result.returncode,0)
        self.assertEqual(self.server.posts,0)
    def test_prompt_exceeds_limit_refused(self):
        self.prompt.write_text('A'*32769)
        result=self.call()
        self.assertNotEqual(result.returncode,0)
        self.assertEqual(self.server.posts,0)
    def test_unready_server_times_out_without_post(self):
        self.server.unready_count=10000
        args=self.args()
        idx=args.index('--ready-timeout')
        args[idx+1]='1'
        result=subprocess.run(args,capture_output=True,text=True,timeout=12)
        self.assertNotEqual(result.returncode,0)
        self.assertEqual(self.server.posts,0)
        self.assertFalse(list((self.root/'cas'/'objects').iterdir()))
    def test_model_binding_is_required_before_claim(self):
        tasks=json.loads((self.root/'tasks.json').read_text())
        tasks[0].pop('runtime_model_ids')
        (self.root/'tasks.json').write_text(json.dumps(tasks))
        result=self.call()
        self.assertNotEqual(result.returncode,0)
        self.assertIn('runtime-model binding',result.stderr)
        self.assertFalse((self.root/'leases.db').exists())
    def test_duplicate_execution_not_repeated(self):
        self.assertEqual(self.call().returncode,0)
        self.assertNotEqual(self.call().returncode,0)
        self.assertEqual(self.server.posts,1)

if __name__=='__main__':unittest.main()

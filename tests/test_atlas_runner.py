"""Localhost-only OpenAI-compatible inference integration (fake real HTTP server)."""
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import tempfile
import threading
import unittest
from atlas.runner import run_local_chat, RunnerError
from atlas.audit import verify_log

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path!='/v1/models':self.send_error(404);return
        self.respond({'data':[{'id':'verified-model-id'}]})
    def do_POST(self):
        if self.path!='/v1/chat/completions':self.send_error(404);return
        req=json.loads(self.rfile.read(int(self.headers['Content-Length'])))
        self.server.request=req
        self.respond({'choices':[{'message':{'content':'Odpowiedź lokalna'}}]})
    def respond(self,obj):
        data=json.dumps(obj).encode()
        self.send_response(200);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(data)));self.end_headers();self.wfile.write(data)
    def log_message(self,*args):pass

class RunnerTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
        self.server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
        self.thread=threading.Thread(target=self.server.serve_forever,daemon=True);self.thread.start()
        self.url=f'http://127.0.0.1:{self.server.server_port}'
    def tearDown(self):
        self.server.shutdown();self.server.server_close();self.thread.join(timeout=3);self.tmp.cleanup()
    def test_real_local_http_and_provenance(self):
        output=self.root/'out.txt';log=self.root/'audit.jsonl';key=b'k'*32
        res=run_local_chat('Czy działa?',output,'verified-model-id',self.url,log,key,max_tokens=64)
        self.assertEqual(res['status'],'COMPLETED')
        self.assertEqual(output.read_text(),'Odpowiedź lokalna')
        self.assertEqual(verify_log(log,key,verify_outputs=True)['records'],1)
        self.assertEqual(self.server.request['stream'],False)
        self.assertEqual(self.server.request['model'],'verified-model-id')
        self.assertNotIn('Czy działa?',log.read_text())
    def test_mismatched_model_rejected(self):
        out=self.root/'out'
        with self.assertRaisesRegex(RunnerError,'model'):
            run_local_chat('test',out,'other-model',self.url,self.root/'log',b'k'*32)
        self.assertFalse(out.exists())
    def test_public_host_and_bad_scheme_rejected(self):
        for url in ['http://example.com:8082','https://127.0.0.1:8082','http://127.0.0.1:8082@evil.test','http://0.0.0.0:8082']:
            with self.subTest(url=url),self.assertRaises(RunnerError):
                run_local_chat('x',self.root/'out','model',url,self.root/'log',b'k'*32)
    def test_existing_output_not_overwritten(self):
        out=self.root/'out';out.write_text('valuable')
        with self.assertRaises(FileExistsError):
            run_local_chat('test',out,'verified-model-id',self.url,self.root/'log',b'k'*32)
        self.assertEqual(out.read_text(),'valuable')
    def test_invalid_token_limit_rejected(self):
        with self.assertRaises(RunnerError):
            run_local_chat('test',self.root/'out','verified-model-id',self.url,self.root/'log',b'k'*32,max_tokens=1000000)

if __name__=='__main__':unittest.main()

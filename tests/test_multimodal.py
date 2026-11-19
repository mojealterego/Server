import hashlib, os, shutil, subprocess, sys, tempfile, unittest
from pathlib import Path
from unittest.mock import Mock
from atlas.artifacts import ArtifactStore
from atlas.multimodal import PipelineError, validate_recipes, run_node, media_command, probe_output, verify_weights

class PipelineTests(unittest.TestCase):
    def setUp(self):
        t=tempfile.TemporaryDirectory();self.addCleanup(t.cleanup);self.root=Path(t.name)
        self.cas=ArtifactStore(self.root/'cas');self.work=self.root/'work';self.work.mkdir(mode=0o700)
        self.catalog={}
        self.paths={}
        for mid,family,role in [('q','qwen','llm'),('f','flux1','image_dit'),('c','flux1','clip_l'),('t','flux1','t5xxl'),('v','flux1','vae'),('w','wan','video_dit'),('wt','wan','t5xxl'),('wv','wan','vae'),('l','ltx2','video_dit'),('ll','ltx2','llm'),('lc','ltx2','embeddings_connectors'),('lv','ltx2','vae')]:
            p=self.root/(mid+'.gguf');p.write_bytes(mid.encode());self.paths[mid]=str(p)
            self.catalog[mid]={'bytes':len(mid),'sha256':hashlib.sha256(mid.encode()).hexdigest(),'format':'gguf','family':family,'role':role,'lineage_verified':True,'bundle':family+'-verified','profiles':{'flux1':['flux1'],'wan':['wan_i2v','wan_t2v'],'ltx2':['ltx2']}.get(family,[])}
        def task(i,engine,models,recipe,deps=()):return {'id':i,'engine':engine,'models':models,'recipe':recipe,'depends_on':list(deps),'ram_mb':64,'output_bytes':1000000,'privacy':'local_only'}
        self.tasks=[task('text','llama',['q'],{'kind':'qwen_text','prompt':'write prompt','runtime_model':'qwen-local'}),task('image','sd-cli',['f','c','t','v'],{'kind':'flux1','prompt_from':'text','slots':{'diffusion_model':'f','clip_l':'c','t5xxl':'t','vae':'v'},'width':64,'height':64,'steps':4},['text']),task('video','sd-cli',['w','wt','wv'],{'kind':'wan_i2v','prompt_from':'text','image_from':'image','slots':{'diffusion_model':'w','t5xxl':'wt','vae':'wv'},'width':64,'height':64,'steps':4,'frames':5,'fps':5},['text','image'])]
        self.tasks[0]['runtime_model_ids']={'qwen-local':'q'}
        self.assign={t['id']:{'id':t['id'],'node':'phone','effective_privacy':'local_only'} for t in self.tasks}
        self.deploy={'node':'phone','llama_endpoint':'http://127.0.0.1:8082','sd_cli':sys.executable,'ffprobe':str(Path(shutil.which('ffprobe')).resolve()),'ffmpeg':str(Path(shutil.which('ffmpeg')).resolve()),'model_paths':self.paths,'backend':'cpu'}
        self.lease=Mock();self.lease.task_list=self.tasks;self.lease.tasks={t['id']:t for t in self.tasks};self.lease.assignments=self.assign;self.lease.catalog=self.catalog
        self.states={};self.lease.status.side_effect=lambda i:self.states.get(i,{'state':'PENDING','epoch':0})
        self.executor=Mock();self.executor.root=self.work
    def test_valid_complete_dag(self):
        self.assertEqual([t['id'] for t in validate_recipes(self.tasks,self.catalog,self.assign)],['text','image','video'])
    def test_typed_edge_rejected(self):
        self.tasks[2]['recipe']['image_from']='text'
        with self.assertRaises(PipelineError):validate_recipes(self.tasks,self.catalog,self.assign)
    def test_unknown_or_extra_slot_rejected(self):
        self.tasks[1]['recipe']['slots']['vae']='q'
        with self.assertRaises(PipelineError):validate_recipes(self.tasks,self.catalog,self.assign)
    def test_unverified_family_rejected(self):
        self.catalog['f']['family']='flux2'
        with self.assertRaises(PipelineError):validate_recipes(self.tasks,self.catalog,self.assign)
    def test_bundle_and_variant_rejected(self):
        self.catalog['f']['bundle']='different';
        with self.assertRaises(PipelineError):validate_recipes(self.tasks,self.catalog,self.assign)
        self.catalog['f']['bundle']='flux1-verified';self.catalog['w']['profiles']=['wan_t2v']
        with self.assertRaises(PipelineError):validate_recipes(self.tasks,self.catalog,self.assign)
    def test_ltx_and_wan_t2v_recipes(self):
        video=self.tasks[2];r=video['recipe'];r.pop('image_from');video['depends_on']=['text'];r['kind']='wan_t2v'
        validate_recipes(self.tasks,self.catalog,self.assign)
        r.update(kind='ltx2',slots={'diffusion_model':'l','llm':'ll','embeddings_connectors':'lc','vae':'lv'});video['models']=['l','ll','lc','lv']
        validate_recipes(self.tasks,self.catalog,self.assign)
        payload={**r,'sd_cli':sys.executable,'backend':'cpu','slots':{k:{'path':self.paths[v]} for k,v in r['slots'].items()}}
        argv=media_command(payload,'hello',self.root/'out.avi');self.assertIn('--embeddings-connectors',argv);self.assertIn('--llm',argv);self.assertNotIn('-i',argv)
    def test_arbitrary_command_rejected(self):
        self.tasks[1]['recipe']['command']=['/bin/sh','-c','bad']
        with self.assertRaises(PipelineError):validate_recipes(self.tasks,self.catalog,self.assign)
    def test_cross_node_edge_rejected(self):
        self.assign['image']['node']='gpu'
        with self.assertRaises(PipelineError):validate_recipes(self.tasks,self.catalog,self.assign)
    def test_prompt_must_be_declared(self):
        self.tasks[1]['depends_on']=[]
        with self.assertRaises(PipelineError):validate_recipes(self.tasks,self.catalog,self.assign)
    def test_weight_integrity(self):
        verify_weights([{'path':self.paths['f'],'sha256':self.catalog['f']['sha256'],'bytes':1}]);Path(self.paths['f']).write_bytes(b'X')
        with self.assertRaises(PipelineError):verify_weights([{'path':self.paths['f'],'sha256':self.catalog['f']['sha256'],'bytes':1}])
    def test_video_flag_and_flux_separation(self):
        payload={'kind':'wan_i2v','sd_cli':sys.executable,'slots':{'diffusion_model':{'path':self.paths['w']},'t5xxl':{'path':self.paths['wt']},'vae':{'path':self.paths['wv']}},'backend':'cpu','width':64,'height':64,'steps':4,'frames':5,'fps':5,'image':str(self.root/'image.png')}
        argv=media_command(payload,'hello',self.root/'out.avi');self.assertIn('vid_gen',argv);self.assertIn('-i',argv);self.assertIn('--video-frames',argv)
        payload['kind']='flux1';payload['slots']={'diffusion_model':{'path':self.paths['f']},'clip_l':{'path':self.paths['c']},'t5xxl':{'path':self.paths['t']},'vae':{'path':self.paths['v']}}
        argv=media_command(payload,'hello',self.root/'out.png');self.assertIn('img_gen',argv);self.assertNotIn('--video-frames',argv);self.assertNotIn('-i',argv)
    def test_no_shell_and_prompt_injection(self):
        with self.assertRaises(PipelineError):media_command({'kind':'flux1'},'--bad',self.root/'out.png')
    def test_completed_verified_and_skip(self):
        self.tasks[:]=self.tasks[:1];self.assign.pop('image');self.assign.pop('video')
        p=self.root/'text';p.write_text('ok');d=self.cas.put(p)['sha256'];self.states['text']={'state':'COMPLETED','output_sha256':d,'epoch':1}
        r=run_node(self.lease,self.cas,self.executor,'phone',self.deploy);self.assertEqual(r['status'],'COMPLETED');self.executor.run.assert_not_called()
        (self.cas.objects/d).write_bytes(b'bad')
        with self.assertRaises(ValueError):run_node(self.lease,self.cas,self.executor,'phone',self.deploy)
    def test_failed_not_retried_by_default(self):
        self.states['text']={'state':'FAILED','epoch':1}
        r=run_node(self.lease,self.cas,self.executor,'phone',self.deploy);self.assertEqual(r['status'],'BLOCKED');self.executor.run.assert_not_called()
    def test_dag_handoff_and_result_validation(self):
        calls=[]
        def execute(tid,node,argv,**kw):
            import json
            calls.append(tid);p=self.root/('result-'+tid)
            if tid=='text':p.write_text('a red square')
            else:
                spec=json.loads(Path(argv[argv.index('--spec')+1]).read_text())
                self.assertEqual(Path(spec['prompt']).read_text(),'a red square')
                if tid=='video':self.assertTrue(Path(spec['image']).is_file())
                p=self.root/('result-'+tid+kw['suffix'])
                self.real_media(p,tid)
            d=self.cas.put(p)['sha256'];self.states[tid]={'state':'COMPLETED','epoch':1,'output_sha256':d}
            return {'status':'COMPLETED','sha256':d,'epoch':1}
        self.executor.run.side_effect=execute
        self.assertEqual(run_node(self.lease,self.cas,self.executor,'phone',self.deploy)['status'],'COMPLETED');self.assertEqual(calls,['text','image','video'])
        self.assertEqual(run_node(self.lease,self.cas,self.executor,'phone',self.deploy)['status'],'COMPLETED');self.assertEqual(calls,['text','image','video'])
    def real_media(self,p,kind):
        subprocess.run([self.deploy['ffmpeg'],'-v','error','-f','lavfi','-i','color=red:s=64x64:r=5','-frames:v','1' if kind=='image' else '5','-threads','1',str(p)],check=True,capture_output=True)
    def test_bad_media_rejected(self):
        p=self.root/'bad.png';p.write_bytes(b'not png')
        with self.assertRaises(PipelineError):probe_output(p,'flux1',self.tasks[1]['recipe'],self.deploy)
    def test_real_image_and_video_probe(self):
        for kind,profile,idx,suffix in [('image','flux1',1,'.png'),('video','wan_i2v',2,'.avi')]:
            p=self.root/(kind+suffix);self.real_media(p,kind);probe_output(p,profile,self.tasks[idx]['recipe'],self.deploy)
            with self.assertRaises(PipelineError):probe_output(p,profile,{**self.tasks[idx]['recipe'],'width':128},self.deploy)
            if kind=='video':
                with self.assertRaises(PipelineError):probe_output(p,profile,{**self.tasks[idx]['recipe'],'fps':7},self.deploy)

if __name__=='__main__':unittest.main()

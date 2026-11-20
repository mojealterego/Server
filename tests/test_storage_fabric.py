import unittest
from atlas.storage_fabric import Fabric, FabricError, digest

class FabricTests(unittest.TestCase):
    def setUp(self):
        self.doc={'schema':'omega.storage.fabric.v1','models':{'qwen':{'sha256':'a'*64,'public_key':'MCowBQYDK2VwAyEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=','remotes':['primary','secondary']}},'recovery':{'sha256':'b'*64,'remotes':['backup1:omega','backup2:omega']}}
    def fabric(self):return Fabric(self.doc,digest(self.doc))
    def test_catalog_pin_is_required(self):
        with self.assertRaises(FabricError):Fabric(self.doc,'c'*64)
    def test_model_routes_only_to_enrolled_pins(self):
        calls=[]
        def stage(*args):calls.append(args);return {'sha256':'a'*64,'path':'/cache/object.gguf'}
        result=self.fabric().stage_model('qwen',{'envelope':True},'/cache',stage=stage)
        self.assertEqual(calls[0],({'envelope':True},self.doc['models']['qwen']['public_key'],'a'*64,'/cache',['primary','secondary']))
        self.assertEqual(result['sha256'],'a'*64)
    def test_unknown_model_never_calls_backend(self):
        with self.assertRaises(FabricError):self.fabric().stage_model('../x',{},'/cache',stage=lambda *a:self.fail('backend called'))
    def test_mismatched_stage_receipt_rejected(self):
        with self.assertRaises(FabricError):self.fabric().stage_model('qwen',{},'/cache',stage=lambda *a:{'sha256':'f'*64})
    def test_recovery_routes_only_current_generation(self):
        calls=[]
        def restore(*args):calls.append(args);return {'status':'RECOVERED_OFFLINE','set_sha256':'b'*64}
        self.fabric().restore({'set':True},'/vault','/dest',restore=restore)
        self.assertEqual(calls[0],({'set':True},'b'*64,'/vault','/dest',['backup1:omega','backup2:omega']))
    def test_wrong_recovery_receipt_fails(self):
        with self.assertRaises(FabricError):self.fabric().restore({},'/vault','/dest',restore=lambda *a:{'status':'RECOVERED_OFFLINE','set_sha256':'c'*64})
    def test_reject_path_injection_duplicate_alias_and_wrong_schema(self):
        for remotes in [['../../a'],['a','a'],['a:other/share']]:
            self.doc['models']['qwen']['remotes']=remotes
            with self.assertRaises(FabricError):self.fabric()
    def test_input_mutation_does_not_change_routing(self):
        f=self.fabric();self.doc['models']['qwen']['sha256']='f'*64
        self.assertEqual(f.stage_model('qwen',{},'/cache',stage=lambda *a:{'sha256':a[2]})['sha256'],'a'*64)

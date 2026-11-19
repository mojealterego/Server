import tempfile,unittest,hashlib
from pathlib import Path
from atlas.artifacts import ArtifactStore
from atlas.storage_snapshot import create,restore,load_index,replicate,retrieve,SnapshotError
from atlas.replication import Replica

class MemoryReplica(Replica):
    def __init__(self,name):super().__init__(name+':vault');self.data={};self.writes=[]
    def read(self,key,limit):
        from atlas.replication import Missing,ReplicationError
        if key not in self.data:raise Missing('missing')
        if len(self.data[key])>limit:raise ReplicationError('too long')
        return self.data[key]
    def ensure(self,key,data):
        if key in self.data:
            if self.data[key]!=data:raise ValueError('conflict')
            return False
        self.data[key]=data;self.writes.append(key);return True

class SnapshotTests(unittest.TestCase):
    def setUp(self):
        t=tempfile.TemporaryDirectory();self.addCleanup(t.cleanup);self.root=Path(t.name)
        self.source=self.root/'share';self.source.mkdir(mode=0o700);(self.source/'folder').mkdir();(self.source/'empty').mkdir()
        (self.source/'folder'/'photo.raw').write_bytes(b'photo');(self.source/'same').write_bytes(b'photo');(self.source/'zero').touch()
        self.cas=ArtifactStore(self.root/'vault');self.other=ArtifactStore(self.root/'other')
    def test_roundtrip_and_empty_dirs(self):
        r=create(self.cas,self.source,'omega-secure');index=load_index(self.cas,r['sha256']);self.assertEqual(len(index['files']),3)
        self.assertEqual(len(list(self.cas.objects.iterdir())),3)
        d=self.root/'restored';restore(self.cas,r['sha256'],d);self.assertEqual((d/'folder'/'photo.raw').read_bytes(),b'photo');self.assertTrue((d/'empty').is_dir());self.assertEqual((d/'zero').stat().st_size,0)
        with self.assertRaises(FileExistsError):restore(self.cas,r['sha256'],d)
    def test_versioned_and_failover_restore(self):
        a=create(self.cas,self.source,'omega-secure');(self.source/'same').write_bytes(b'new');b=create(self.cas,self.source,'omega-secure');self.assertNotEqual(a['sha256'],b['sha256'])
        one,two=MemoryReplica('one'),MemoryReplica('two');replicate(self.cas,a['sha256'],[one,two]);self.assertEqual(one.writes[-1],'manifests/'+a['sha256']+'.json')
        one.data.clear();retrieve(self.other,a['sha256'],a['manifest_sha256'],[one,two]);restore(self.other,a['sha256'],self.root/'old');self.assertEqual((self.root/'old'/'same').read_bytes(),b'photo')
    def test_corrupt_object_no_publication(self):
        a=create(self.cas,self.source,'omega-secure');(self.cas.objects/hashlib.sha256(b'photo').hexdigest()).write_bytes(b'bad')
        dest=self.root/'bad';
        with self.assertRaises(ValueError):restore(self.cas,a['sha256'],dest)
        self.assertFalse(dest.exists())
    def test_symlink_and_bad_share_rejected(self):
        (self.source/'link').symlink_to(self.root/'vault')
        with self.assertRaises(ValueError):create(self.cas,self.source,'omega-secure')
        with self.assertRaises(ValueError):create(self.cas,self.source,'smb-secrets')
    def test_vault_inside_source_rejected(self):
        with self.assertRaises(ValueError):create(ArtifactStore(self.source/'vault'),self.source,'omega-secure')
    def test_bad_index_traversal(self):
        import json
        p=self.root/'bad.json';p.write_text(json.dumps({'schema':'omega.smb.snapshot.v1','share':'omega-secure','dirs':['../evil'],'files':[]}));h=self.cas.put(p)['sha256']
        with self.assertRaises(ValueError):load_index(self.cas,h)
    def test_snapshot_pin_rejected(self):
        a=create(self.cas,self.source,'omega-secure');r=MemoryReplica('one');replicate(self.cas,a['sha256'],[r])
        with self.assertRaises(ValueError):retrieve(self.other,a['sha256'],'0'*64,[r])
    def test_encrypted_remote_policy(self):
        from unittest.mock import patch
        from types import SimpleNamespace
        from atlas.storage_snapshot import encrypted_replicas
        with patch('atlas.storage_snapshot.subprocess.run',return_value=SimpleNamespace(stdout=b'[backup]\ntype = crypt\n')):
            self.assertEqual(encrypted_replicas(['backup:vault'])[0].root,'backup:vault')
            with self.assertRaises(ValueError):encrypted_replicas(['wrong:vault'])
            with self.assertRaises(ValueError):encrypted_replicas(['backup:a','backup:b'])
        with patch('atlas.storage_snapshot.subprocess.run',return_value=SimpleNamespace(stdout=b'[backup]\ntype = smb\n')):
            with self.assertRaises(ValueError):encrypted_replicas(['backup:vault'])
    def test_bad_config_does_not_echo_secret(self):
        from unittest.mock import patch
        from types import SimpleNamespace
        from atlas.storage_snapshot import encrypted_replicas
        with patch('atlas.storage_snapshot.subprocess.run',return_value=SimpleNamespace(stdout=b'private-secret-value\n')):
            with self.assertRaisesRegex(SnapshotError,'Invalid encrypted remote configuration') as e:encrypted_replicas(['backup:vault'])
            self.assertNotIn('private-secret',str(e.exception))

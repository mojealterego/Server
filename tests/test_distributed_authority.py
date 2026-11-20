import base64
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from atlas.distributed_authority import Authority, AuthorityError

class TxnFixture:
    """Atomic in-memory fixture for the etcd JSON contract; not a real etcd server."""
    def __init__(self):
        self.lock=threading.Lock(); self.revision=0; self.row=None; self.fail=False
    def __call__(self,path,body):
        with self.lock:
            if self.fail: raise OSError('network down')
            if path=='/v3/kv/range':
                return {'header':{'cluster_id':'42'},'kvs':[self.row] if self.row else []}
            cmp=body['compare'][0]; mod=int(self.row['mod_revision']) if self.row else 0
            ok=(cmp['target']=='VERSION' and self.row is None) or (cmp['target']=='MOD' and int(cmp['mod_revision'])==mod and mod>0)
            if ok:
                self.revision+=1; put=body['success'][0]['request_put']; self.row={'key':put['key'],'value':put['value'],'mod_revision':str(self.revision),'lease':'0'}
            return {'succeeded':ok,'header':{'revision':str(self.revision),'cluster_id':'42'}}

class AuthorityTests(unittest.TestCase):
    def setUp(self):
        self.backend=TxnFixture(); self.a=Authority(self.backend,'omega','42'); self.pin='a'*64
    def test_concurrent_bootstrap_only_one(self):
        def contender(i):
            try:return self.a.bootstrap('node'+str(i),self.pin,confirm_empty=True)
            except AuthorityError:return None
        with ThreadPoolExecutor(max_workers=8) as pool: results=list(pool.map(contender,range(8)))
        self.assertEqual(sum(x is not None for x in results),1)
    def test_transfer_requires_fencing_and_latest(self):
        grant=self.a.bootstrap('a',self.pin,confirm_empty=True)
        for f,l in [(False,True),(True,False),(False,False)]:
            with self.assertRaises(AuthorityError):self.a.transfer(grant.revision,'b','b'*64,confirm_fenced=f,confirm_latest=l)
        self.assertEqual(self.a.current(),grant)
    def test_stale_transfer_rejected(self):
        old=self.a.bootstrap('a',self.pin,confirm_empty=True)
        new=self.a.transfer(old.revision,'b','b'*64,confirm_fenced=True,confirm_latest=True)
        self.assertGreater(new.revision,old.revision)
        with self.assertRaises(AuthorityError):self.a.transfer(old.revision,'c',self.pin,confirm_fenced=True,confirm_latest=True)
        self.assertEqual(self.a.current(),new)
    def test_network_failure_never_grants(self):
        self.backend.fail=True
        with self.assertRaises(AuthorityError):self.a.bootstrap('a',self.pin,confirm_empty=True)
    def test_cluster_mismatch(self):
        with self.assertRaises(AuthorityError):Authority(self.backend,'omega','99').current()
    def test_invalid_inputs(self):
        for node,pin in [('a/b',self.pin),('a','wrong')]:
            with self.assertRaises(AuthorityError):self.a.bootstrap(node,pin,confirm_empty=True)
        with self.assertRaises(AuthorityError):self.a.bootstrap('a',self.pin,confirm_empty=False)
    def test_non_expiring_key(self):
        self.a.bootstrap('a',self.pin,confirm_empty=True)
        self.backend.row['lease']='9'
        with self.assertRaises(AuthorityError): self.a.current()
    def test_lost_reply_does_not_allow_second_bootstrap(self):
        def lost(path,body):
            result=self.backend(path,body)
            if path=='/v3/kv/txn':raise OSError('lost response')
            return result
        with self.assertRaises(AuthorityError):Authority(lost,'omega','42').bootstrap('a',self.pin,confirm_empty=True)
        with self.assertRaises(AuthorityError):self.a.bootstrap('b',self.pin,confirm_empty=True)
        self.assertEqual(self.a.current().node,'a')

class GuardTests(unittest.TestCase):
    def test_stale_or_unreachable_registry_rejects_before_dispatch(self):
        from atlas.distributed_authority import AuthorityGuard,GuardedCoordinator
        backend=TxnFixture();a=Authority(backend,'omega','42');grant=a.bootstrap('node1','a'*64,confirm_empty=True)
        calls=[]
        class Coordinator:
            policy={};replay='replay.db'
            def handle(self,*args):calls.append(args);return {'status':'OK'}
        q=GuardedCoordinator(Coordinator(),AuthorityGuard(a,grant));self.assertEqual(q.handle('worker',{}),{'status':'OK'})
        backend.fail=True
        with self.assertRaises(AuthorityError):q.handle('worker',{})
        backend.fail=False;a.transfer(grant.revision,'node2','b'*64,confirm_fenced=True,confirm_latest=True)
        with self.assertRaises(AuthorityError):q.handle('worker',{})
        self.assertEqual(len(calls),1)

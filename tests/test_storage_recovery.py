import hashlib
import tempfile
import unittest
from pathlib import Path
from atlas.storage_recovery import recovery_set, restore_set, RecoveryError

SHARES=('omega-compat','omega-secure','omega-models')
class RecoveryTests(unittest.TestCase):
    def setUp(self):
        t=tempfile.TemporaryDirectory();self.addCleanup(t.cleanup);self.root=Path(t.name)
        self.rows={s:{'sha256':hashlib.sha256(s.encode()).hexdigest(),'manifest_sha256':hashlib.sha256((s+'pin').encode()).hexdigest()} for s in SHARES}
        self.set=recovery_set(self.rows,quiesced=True);self.calls=[]
    def retrieve(self,sha,pin):self.calls.append(('pull',sha,pin))
    def inspect(self,sha):return {'share':next(s for s,r in self.rows.items() if r['sha256']==sha)}
    def restore(self,sha,dest):dest.mkdir(mode=0o700);(dest/'content').write_text(sha);return {'status':'RESTORED','sha256':sha}
    def run_restore(self,**kw):
        opts={'retrieve':self.retrieve,'inspect':self.inspect,'restore':self.restore};opts.update(kw)
        return restore_set(self.set['set'],self.set['sha256'],self.root/'recovered',**opts)
    def test_all_three_shares_and_recovery_receipt(self):
        r=self.run_restore();self.assertEqual(r['status'],'RECOVERED_OFFLINE');self.assertEqual(len(self.calls),3)
        for s in SHARES:self.assertEqual((self.root/'recovered'/s/'content').read_text(),self.rows[s]['sha256'])
    def test_bad_share_identity_no_publish(self):
        with self.assertRaises(RecoveryError):self.run_restore(inspect=lambda s:{'share':'wrong'})
        self.assertFalse((self.root/'recovered').exists())
    def test_failed_replica_no_publish(self):
        def fail(sha,pin):
            if sha==self.rows['omega-secure']['sha256']:raise OSError('offline')
        with self.assertRaises(OSError):self.run_restore(retrieve=fail)
        self.assertFalse((self.root/'recovered').exists())
    def test_pin_mismatch_before_network(self):
        self.set['sha256']='0'*64
        with self.assertRaises(ValueError):self.run_restore()
        self.assertEqual(self.calls,[])
    def test_no_implicit_fallback_or_missing_shares(self):
        with self.assertRaises(ValueError):recovery_set({'omega-secure':self.rows['omega-secure']},quiesced=True)
        with self.assertRaises(ValueError):recovery_set(self.rows,quiesced=False)
    def test_existing_destination_preserved(self):
        (self.root/'recovered').mkdir();(self.root/'recovered/keep').write_text('ok')
        with self.assertRaises(FileExistsError):self.run_restore()
        self.assertEqual(self.calls,[])
    def test_full_capture_receipt_accepted(self):
        from atlas.storage_recovery import validate
        self.assertEqual(validate(self.set,self.set['sha256']),self.rows)
        with self.assertRaises(ValueError):validate(self.set,'0'*64)

class ReplicaRecoveryTests(unittest.TestCase):
    def test_real_snapshot_cas_replica_loss_and_restore(self):
        from atlas.artifacts import ArtifactStore
        from atlas.replication import Replica,Missing,ReplicationError
        from atlas.storage_snapshot import create,replicate,retrieve,load_index,restore
        class Remote(Replica):
            def __init__(self,name):super().__init__(name+':vault');self.blocks={};self.offline=False
            def ensure(self,key,data):
                if key in self.blocks:
                    if self.blocks[key]!=data:raise ReplicationError('conflict')
                    return False
                self.blocks[key]=data;return True
            def read(self,key,limit):
                if self.offline:raise ReplicationError('unavailable')
                if key not in self.blocks:raise Missing('missing')
                return self.blocks[key]
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);src=ArtifactStore(root/'src');dst=ArtifactStore(root/'dst');a,b=Remote('a'),Remote('b');rows={}
            for s in SHARES:
                p=root/s;p.mkdir();(p/'empty').mkdir();(p/'file').write_bytes(s.encode())
                r=create(src,p,s);rows[s]={k:r[k] for k in ('sha256','manifest_sha256')};replicate(src,r['sha256'],[a,b])
            receipt=recovery_set(rows,quiesced=True);a.offline=True
            out=restore_set(receipt,receipt['sha256'],root/'restored',retrieve=lambda sha,pin:retrieve(dst,sha,pin,[a,b]),inspect=lambda sha:load_index(dst,sha),restore=lambda sha,p:restore(dst,sha,p))
            self.assertEqual(out['status'],'RECOVERED_OFFLINE')
            for s in SHARES:
                self.assertEqual((root/'restored'/s/'file').read_bytes(),s.encode());self.assertTrue((root/'restored'/s/'empty').is_dir())
            # If both replicas are lost, no incomplete generation is published.
            b.offline=True;fresh=ArtifactStore(root/'fresh')
            with self.assertRaises(ReplicationError):restore_set(receipt,receipt['sha256'],root/'failed',retrieve=lambda sha,pin:retrieve(fresh,sha,pin,[a,b]),inspect=lambda sha:load_index(fresh,sha),restore=lambda sha,p:restore(fresh,sha,p))
            self.assertFalse((root/'failed').exists())
    def test_cli_capture_push_restore_with_subprocess_replicas(self):
        import contextlib,io,json,os,subprocess,sys
        from unittest.mock import patch
        from atlas.storage_recovery import main
        from atlas.storage_snapshot import SHARES as PATHS
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);vps=root/'vps'
            for s,rel in PATHS.items():
                p=vps/rel;p.mkdir(parents=True);(p/'file').write_text(s)
            fake=root/'rclone';fake.write_text('''#!/bin/sh
set -eu
case "$1" in
 config) printf '[%s]\\ntype = crypt\\n' "$3"; exit 0;;
 cat) key="$2";;
 copyto) key="$3";;
 *) exit 2;;
esac
alias=${key%%:*}; rel=${key#*:}
[ ! -e "$OMEGA_TEST_REMOTES/$alias/offline" ] || exit 1
path="$OMEGA_TEST_REMOTES/$alias/$rel"
if [ "$1" = cat ]; then
 [ -f "$path" ] || exit 4
 cat "$path"
else
 mkdir -p "$(dirname "$path")"
 if [ -f "$path" ]; then cmp -s "$path" "$2"; else cp "$2" "$path"; fi
fi
''');fake.chmod(0o700)
            out=io.StringIO()
            with patch('atlas.storage_snapshot.VPS',vps),contextlib.redirect_stdout(out):self.assertEqual(main(['--vault',str(root/'src'),'capture','--confirm-quiesced']),0)
            receipt=json.loads(out.getvalue());path=root/'receipt.json';path.write_text(json.dumps(receipt));pin=receipt['sha256']
            remotes=['--remote','a:vault','--remote','b:vault'];env={**os.environ,'PATH':str(root)+os.pathsep+os.environ['PATH'],'OMEGA_TEST_REMOTES':str(root/'remote')}
            def run(vault,action,extra):return subprocess.run([sys.executable,'-m','atlas.storage_recovery','--vault',str(root/vault),action,'--set',str(path),'--sha256',pin,*remotes,*extra],env=env,capture_output=True,text=True,timeout=30)
            r=run('src','push',['--allow-export']);self.assertEqual(r.returncode,0,r.stderr);self.assertEqual(json.loads(r.stdout)['status'],'VERIFIED_READBACK')
            (root/'remote/a/offline').touch();r=run('dst','restore',['--dest',str(root/'restored')]);self.assertEqual(r.returncode,0,r.stderr)
            self.assertEqual(json.loads(r.stdout)['status'],'RECOVERED_OFFLINE')
            for s in SHARES:self.assertEqual((root/'restored'/s/'file').read_text(),s)

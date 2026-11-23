"""E22b: deterministic channel-loss, replay, ACL and integrity acceptance."""
from __future__ import annotations
from concurrent.futures import ThreadPoolExecutor
import hashlib
import random
import unittest

from atlas.smb_channel_sim import ChannelSimulation, ChannelError

HASH = lambda data: hashlib.sha256(data).hexdigest()


class SMBChannelSimulationTests(unittest.TestCase):
    def setUp(self):
        self.sim=ChannelSimulation(('lan','wan'))
        self.compat=self.sim.open('omega-compat','omega-compat','SMB2_10','sign')
        self.secure=self.sim.open('omega-secure','omega-secure','SMB3_11','encrypt')
        self.reader=self.sim.open('omega-model-reader','omega-models','SMB3_11','encrypt')
        self.models=self.sim.open('omega-secure','omega-models','SMB3_11','encrypt')

    def test_strict_share_protocol_and_account_matrix(self):
        for account,share,dialect,protection in (
            ('omega-compat','omega-secure','SMB3_11','encrypt'),
            ('omega-secure','omega-compat','SMB2_10','sign'),
            ('omega-secure','omega-secure','SMB2_10','sign'),
            ('omega-compat','omega-compat','NT1','sign'),
            ('omega-model-reader','omega-models','SMB3_11','sign'),
            ('unknown','omega-secure','SMB3_11','encrypt'),
            ('omega-secure','not-existing','SMB3_11','encrypt')):
            with self.subTest(share=share,account=account,dialect=dialect,protection=protection):
                with self.assertRaises(ChannelError):
                    self.sim.open(account,share,dialect,protection)

    def test_two_channel_write_readback(self):
        payload=b'abc'*240
        receipt=self.sim.put(self.secure,'doc.bin',payload,'write-1','lan')
        self.assertEqual(receipt['sha256'],HASH(payload))
        self.assertEqual(self.sim.get(self.secure,'doc.bin',HASH(payload),'wan'),payload)
        self.assertEqual(self.sim.commits,1)

    def test_channel_failure_and_heal_preserve_pinned_bytes(self):
        payload=b'a'*4096
        self.sim.put(self.compat,'data',payload,'op1','lan')
        self.sim.fail('lan')
        with self.assertRaises(ChannelError):self.sim.get(self.compat,'data',HASH(payload),'lan')
        self.assertEqual(self.sim.get(self.compat,'data',HASH(payload),'wan'),payload)
        self.sim.recover('lan')
        self.assertEqual(self.sim.get(self.compat,'data',HASH(payload),'lan'),payload)

    def test_total_channel_outage_fails_closed_and_no_write_occurs(self):
        self.sim.fail('lan');self.sim.fail('wan')
        with self.assertRaises(ChannelError):self.sim.put(self.secure,'doc',b'x','op1','lan')
        self.assertEqual(self.sim.commits,0)
        self.sim.recover('wan')
        with self.assertRaises(ChannelError):self.sim.get(self.secure,'doc',HASH(b'x'),'wan')

    def test_ack_loss_after_durable_logical_commit_idempotent_retry(self):
        self.sim.drop_ack('lan')
        with self.assertRaisesRegex(ChannelError,'acknowledgment'):
            self.sim.put(self.secure,'blob',b'payload','op1','lan')
        self.assertEqual(self.sim.commits,1)
        replay=self.sim.put(self.secure,'blob',b'payload','op1','wan')
        self.assertEqual(replay['status'],'ALREADY_COMMITTED')
        self.assertEqual(self.sim.commits,1)
        self.assertEqual(self.sim.get(self.secure,'blob',HASH(b'payload'),'wan'),b'payload')

    def test_crash_before_commit_does_not_publish_half_write(self):
        self.sim.abort_before_commit('lan')
        with self.assertRaisesRegex(ChannelError,'pre-commit'):
            self.sim.put(self.secure,'blob',b'payload','op1','lan')
        self.assertEqual(self.sim.commits,0)
        with self.assertRaises(ChannelError):self.sim.get(self.secure,'blob',HASH(b'payload'),'wan')
        self.assertEqual(self.sim.put(self.secure,'blob',b'payload','op1','wan')['status'],'COMMITTED')

    def test_operation_id_conflict_and_no_overwrite(self):
        self.sim.put(self.compat,'blob',b'first','op1','lan')
        with self.assertRaises(ChannelError):self.sim.put(self.compat,'blob',b'second','op1','wan')
        with self.assertRaises(ChannelError):self.sim.put(self.compat,'blob',b'second','op2','wan')
        self.assertEqual(self.sim.get(self.compat,'blob',HASH(b'first'),'wan'),b'first')
        self.assertEqual(self.sim.commits,1)

    def test_models_readonly_and_per_share_acl(self):
        self.sim.seed_model('Qwen.gguf',b'model',sha256=HASH(b'model'))
        self.assertEqual(self.sim.get(self.reader,'Qwen.gguf',HASH(b'model'),'lan'),b'model')
        self.assertEqual(self.sim.get(self.models,'Qwen.gguf',HASH(b'model'),'wan'),b'model')
        with self.assertRaises(ChannelError):self.sim.put(self.models,'Qwen.gguf',b'evil','op1','wan')
        with self.assertRaises(ChannelError):self.sim.put(self.reader,'evil',b'evil','op2','wan')
        with self.assertRaises(ChannelError):self.sim.get(self.reader,'doc',HASH(b'doc'),'wan')
        self.assertEqual(self.sim.commits,1)  # seeded read-only image

    def test_corrupted_channel_read_is_never_silently_accepted(self):
        self.sim.put(self.secure,'payload',b'abc','op1','lan')
        self.sim.corrupt_next_read('lan')
        with self.assertRaisesRegex(ChannelError,'integrity'):
            self.sim.get(self.secure,'payload',HASH(b'abc'),'lan')
        self.assertEqual(self.sim.get(self.secure,'payload',HASH(b'abc'),'wan'),b'abc')

    def test_stale_or_wrong_digest_is_denied(self):
        self.sim.put(self.compat,'doc',b'abc','op1','lan')
        with self.assertRaisesRegex(ChannelError,'integrity'):
            self.sim.get(self.compat,'doc',HASH(b'abd'),'wan')

    def test_invalid_identity_and_payload_bounds(self):
        for key in ('../secret','x/y','','a'*65,'\x00bad'):
            with self.subTest(key=key),self.assertRaises(ChannelError):
                self.sim.put(self.compat,key,b'abc','op1','lan')
        for bad in (False,123,'plain text',b'x'*(1024*1024+1)):
            with self.assertRaises(ChannelError):self.sim.put(self.compat,'safe',bad,'op2','lan')
        with self.assertRaises(ChannelError):self.sim.put(self.compat,'safe',b'abc','../bad','lan')
        with self.assertRaises(ChannelError):self.sim.fail('unknown')

    def test_concurrent_replay_single_commit(self):
        def attempt(i):
            return self.sim.put(self.compat,'blob',b'payload','same-op',('lan','wan')[i%2])
        with ThreadPoolExecutor(max_workers=8) as workers:
            result=list(workers.map(attempt,range(32)))
        self.assertEqual(sum(x['status']=='COMMITTED' for x in result),1)
        self.assertEqual(sum(x['status']=='ALREADY_COMMITTED' for x in result),31)
        self.assertEqual(self.sim.commits,1)

    def test_share_isolation_prevents_cross_share_data_visibility(self):
        self.sim.put(self.compat,'same-name',b'compat','id-compat','lan')
        self.sim.put(self.secure,'same-name',b'secure','id-secure','wan')
        self.assertEqual(self.sim.get(self.compat,'same-name',HASH(b'compat'),'wan'),b'compat')
        self.assertEqual(self.sim.get(self.secure,'same-name',HASH(b'secure'),'lan'),b'secure')
        with self.assertRaises(ChannelError):
            self.sim.get(self.secure,'same-name',HASH(b'compat'),'wan')

    def test_200_seeded_fault_sequences_never_publish_corruption(self):
        rng=random.Random(20261123)
        for case in range(200):
            sim=ChannelSimulation(('a','b'))
            session=sim.open('omega-secure','omega-secure','SMB3_11','encrypt')
            data=rng.randbytes(rng.randint(1,4096))
            if rng.random()<0.4:sim.abort_before_commit('a')
            if rng.random()<0.4:sim.drop_ack('a')
            try:sim.put(session,'object',data,'op','a')
            except ChannelError:pass
            # A bounded retry from an independent channel handles either outcome.
            sim.put(session,'object',data,'op','b')
            if rng.random()<0.5:sim.corrupt_next_read('a')
            try:
                candidate=sim.get(session,'object',HASH(data),'a')
                self.assertEqual(candidate,data)
            except ChannelError:pass
            self.assertEqual(sim.get(session,'object',HASH(data),'b'),data)
            self.assertEqual(sim.commits,1,case)

    def test_repeated_trace_has_same_digest(self):
        def run():
            sim=ChannelSimulation(('a','b'))
            s=sim.open('omega-secure','omega-secure','SMB3_11','encrypt')
            sim.drop_ack('a')
            try:sim.put(s,'f',b'data','op','a')
            except ChannelError:pass
            sim.fail('a')
            sim.put(s,'f',b'data','op','b')
            return sim.trace_digest()
        self.assertEqual(run(),run())


if __name__=='__main__':unittest.main()

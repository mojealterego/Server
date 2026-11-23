"""E20 deterministic fault-injection acceptance against the real Authority API."""
from __future__ import annotations
from concurrent.futures import ThreadPoolExecutor
import unittest
from unittest.mock import patch

from atlas.distributed_authority import Authority, AuthorityError, AuthorityGuard, GuardedCoordinator
from atlas.quorum_simulation import QuorumSimulation, SimulationError

PIN_A='a'*64
PIN_B='b'*64


class QuorumSimulationTests(unittest.TestCase):
    def setUp(self):
        self.fabric=QuorumSimulation(('node-a','node-b','node-c'),cluster_id='42')

    def authority(self,node='node-a',namespace='omega'):
        return Authority(self.fabric.rpc(node),namespace,'42')

    def test_majority_accepts_initial_grant_and_strict_compare_swap(self):
        first=self.authority().bootstrap('a',PIN_A,confirm_empty=True)
        self.assertEqual(first.revision,2)
        self.assertEqual(self.authority('node-c').current(),first)
        with self.assertRaises(AuthorityError):
            self.authority('node-b').bootstrap('b',PIN_B,confirm_empty=True)
        self.assertEqual(len(self.fabric.commits),1)

    def test_minority_cannot_read_or_modify_under_partition(self):
        first=self.authority().bootstrap('a',PIN_A,confirm_empty=True)
        self.fabric.partition((('node-a',),('node-b','node-c')))
        with self.assertRaises(AuthorityError): self.authority('node-a').current()
        with self.assertRaises(AuthorityError):
            self.authority('node-a').transfer(first.revision,'attacker',PIN_B,
                                               confirm_fenced=True,confirm_latest=True)
        second=self.authority('node-b').transfer(first.revision,'b',PIN_B,
                                                 confirm_fenced=True,confirm_latest=True)
        self.assertEqual(second.revision,3)
        self.assertEqual(self.authority('node-c').current(),second)
        self.assertEqual(len(self.fabric.commits),2)

    def test_quorum_loss_rejects_read_and_write_without_mutating_state(self):
        first=self.authority().bootstrap('a',PIN_A,confirm_empty=True)
        self.fabric.crash('node-b');self.fabric.crash('node-c')
        with self.assertRaises(AuthorityError):self.authority().current()
        with self.assertRaises(AuthorityError):
            self.authority().transfer(first.revision,'b',PIN_B,
                                      confirm_fenced=True,confirm_latest=True)
        self.assertEqual(len(self.fabric.commits),1)
        self.fabric.recover('node-b')
        self.assertEqual(self.authority().current(),first)

    def test_lost_transaction_ack_never_allows_competing_bootstrap(self):
        self.fabric.drop_reply_after_commit('node-a')
        with self.assertRaises(AuthorityError):
            self.authority().bootstrap('a',PIN_A,confirm_empty=True)
        found=self.authority('node-b').current()
        self.assertEqual(found.node,'a')
        self.assertEqual(found.revision,2)
        with self.assertRaises(AuthorityError):
            self.authority('node-c').bootstrap('b',PIN_B,confirm_empty=True)
        self.assertEqual(len(self.fabric.commits),1)

    def test_stale_grant_is_revoked_after_handover_and_cannot_recover(self):
        old=self.authority().bootstrap('a',PIN_A,confirm_empty=True)
        guard=AuthorityGuard(self.authority('node-b'),old)
        guard.check()
        current=self.authority('node-c').transfer(old.revision,'b',PIN_B,
                                                    confirm_fenced=True,confirm_latest=True)
        with self.assertRaises(AuthorityError):guard.check()
        self.fabric.partition((('node-b','node-c'),('node-a',)))
        self.fabric.heal()
        with self.assertRaises(AuthorityError):guard.check()
        AuthorityGuard(self.authority(),current).check()

    def test_guarded_dispatch_denies_minority_and_reenables_on_quorum_return(self):
        grant=self.authority().bootstrap('a',PIN_A,confirm_empty=True)
        calls=[]
        class Coordinator:
            policy={};replay=None
            def handle(self,ident,request):calls.append((ident,request));return {'status':'OK'}
        q=GuardedCoordinator(Coordinator(),AuthorityGuard(self.authority(),grant))
        self.assertEqual(q.handle('user',{'op':'noop'}),{'status':'OK'})
        self.fabric.partition((('node-a',),('node-b','node-c')))
        with self.assertRaises(AuthorityError):q.handle('user',{})
        self.fabric.heal()
        self.assertEqual(q.handle('user',{}),{'status':'OK'})
        self.assertEqual(len(calls),2)

    def test_racing_transfers_single_winner(self):
        first=self.authority().bootstrap('a',PIN_A,confirm_empty=True)
        def attempt(i):
            try:return self.authority('node-'+('abc'[i%3])).transfer(
                first.revision,'new'+str(i),PIN_B,confirm_fenced=True,confirm_latest=True)
            except AuthorityError:return None
        with ThreadPoolExecutor(max_workers=12) as workers:
            results=list(workers.map(attempt,range(12)))
        self.assertEqual(sum(x is not None for x in results),1)
        self.assertEqual(self.fabric.revision,3)

    def test_namespace_separation_under_same_cluster(self):
        a=self.authority(namespace='one').bootstrap('a',PIN_A,confirm_empty=True)
        b=self.authority(namespace='two').bootstrap('b',PIN_B,confirm_empty=True)
        self.assertNotEqual(a.nonce,b.nonce)
        self.assertEqual(self.authority(namespace='one').current(),a)
        self.assertEqual(self.authority(namespace='two').current(),b)
        self.assertEqual(len(self.fabric.commits),2)

    def test_different_cluster_id_is_denied(self):
        self.authority().bootstrap('a',PIN_A,confirm_empty=True)
        with self.assertRaises(AuthorityError):
            Authority(self.fabric.rpc('node-a'),'omega','99').current()

    def test_five_node_majority_and_multiple_faults(self):
        q=QuorumSimulation(tuple(f'n{i}' for i in range(5)),cluster_id='51')
        a=lambda node:Authority(q.rpc(node),'omega','51')
        first=a('n0').bootstrap('a',PIN_A,confirm_empty=True)
        q.partition((('n0','n1'),('n2','n3','n4')))
        with self.assertRaises(AuthorityError):a('n0').current()
        q.crash('n4')
        with self.assertRaises(AuthorityError):a('n2').current()
        q.recover('n4')
        second=a('n3').transfer(first.revision,'b',PIN_B,
                                 confirm_fenced=True,confirm_latest=True)
        self.assertEqual(a('n4').current(),second)
        self.assertEqual(len(q.commits),2)

    def test_exhaustive_three_member_partition_safety(self):
        from itertools import product
        for state in product((0,1,2),repeat=3):
            # 0 or 1: partition id, 2: crashed.
            f=QuorumSimulation(('a','b','c'),cluster_id='42')
            live=[i for i,v in enumerate(state) if v!=2]
            for index,v in enumerate(state):
                if v==2:f.crash(('a','b','c')[index])
            f.partition((tuple(('a','b','c')[i] for i,v in enumerate(state) if v==0),
                         tuple(('a','b','c')[i] for i,v in enumerate(state) if v==1),
                         tuple(('a','b','c')[i] for i,v in enumerate(state) if v==2)))
            winners=0
            for member in ('a','b','c'):
                try:
                    Authority(f.rpc(member),'omega','42').current()
                    winners+=1
                except AuthorityError:pass
            self.assertIn(winners,(0,2,3),state)

    def test_failed_input_partition_never_weakens_quorum(self):
        for groups in ((('node-a','node-a'),('node-b','node-c')),
                       (('node-a','node-b'),),
                       (('node-a','node-b','evil'),('node-c',))):
            with self.assertRaises(SimulationError):self.fabric.partition(groups)
        self.assertEqual(self.fabric.connected_quorum(),('node-a','node-b','node-c'))

    def test_trace_deterministic_for_fixed_authority_nonce(self):
        def scenario():
            f=QuorumSimulation(('a','b','c'),cluster_id='42')
            with patch('atlas.distributed_authority.secrets.token_hex',return_value='d'*64):
                a=Authority(f.rpc('a'),'prod','42')
                first=a.bootstrap('one',PIN_A,confirm_empty=True)
                f.partition((('a',),('b','c')))
                Authority(f.rpc('b'),'prod','42').transfer(first.revision,'two',PIN_B,
                                                          confirm_fenced=True,confirm_latest=True)
            return f.trace_digest(), f.commits
        self.assertEqual(scenario(),scenario())


if __name__=='__main__':unittest.main()

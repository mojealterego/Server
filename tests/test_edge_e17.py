"""E17a actual Ed25519 authorization and replay-protected local enrollment."""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import json
import tempfile
import time
import unittest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
from atlas.edge_enrollment import EdgeRegistry, EdgeError, issue_grant, proof_for_challenge

class EdgeTests(unittest.TestCase):
    def setUp(self):
        d=tempfile.TemporaryDirectory();self.addCleanup(d.cleanup)
        self.dir=Path(d.name);self.dir.chmod(0o700)
        self.operator=Ed25519PrivateKey.generate()
        self.node=Ed25519PrivateKey.generate()
        self.other=Ed25519PrivateKey.generate()
        self.pub=self.operator.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)
        self.now=1_800_000_000
        self.db=self.dir/'edge.sqlite'
        self.r=EdgeRegistry(self.db,self.pub)
        self.addCleanup(self.r.close)

    def grant(self, **updates):
        kwargs=dict(node_id='edge-001',tenant='omega',owner_id='owner-001',
            node_public_key=self.node.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw),
            domain_claim='domain-unknown',max_bytes=8_000_000_000,
            not_before=self.now-10,expires_at=self.now+3600)
        kwargs.update(updates)
        return issue_grant(self.operator,**kwargs)

    def enroll(self, grant=None, *, node=None, at=None):
        grant=grant or self.grant(); at=self.now if at is None else at
        nonce=self.r.challenge(grant['node_id'],now=at)
        proof=proof_for_challenge(node or self.node,grant,nonce)
        return self.r.enroll(grant,nonce,proof,now=at,epoch=1)

    def test_enroll_requires_real_operator_and_node_signatures(self):
        receipt=self.enroll()
        self.assertEqual(receipt['node_id'],'edge-001')
        self.assertEqual(receipt['trust'],'OPERATOR_AUTHORIZED_NOT_PHYSICALLY_ATTESTED')
        self.assertEqual(self.r.status('edge-001',tenant='omega')['max_bytes'],8_000_000_000)

    def test_forged_operator_grant_fails_closed(self):
        grant=self.grant();grant['max_bytes']+=1
        with self.assertRaises(EdgeError):self.enroll(grant)

    def test_node_key_possession_required(self):
        with self.assertRaises(EdgeError):self.enroll(node=self.other)

    def test_expired_or_not_yet_valid_fails(self):
        for args in ({'expires_at':self.now}, {'not_before':self.now+60}):
            with self.subTest(args=args),self.assertRaises(EdgeError):self.enroll(self.grant(**args))

    def test_replay_and_duplicate_enrollment_denied(self):
        grant=self.grant()
        nonce=self.r.challenge('edge-001',now=self.now)
        proof=proof_for_challenge(self.node,grant,nonce)
        self.r.enroll(grant,nonce,proof,now=self.now,epoch=1)
        with self.assertRaises(EdgeError):self.r.enroll(grant,nonce,proof,now=self.now,epoch=1)
        with self.assertRaises(EdgeError):self.enroll(grant)

    def test_challenge_bound_to_node_and_expiration(self):
        grant=self.grant()
        nonce=self.r.challenge('edge-002',now=self.now)
        with self.assertRaises(EdgeError):
            self.r.enroll(grant,nonce,proof_for_challenge(self.node,grant,nonce),now=self.now,epoch=1)
        nonce=self.r.challenge('edge-001',now=self.now)
        with self.assertRaises(EdgeError):
            self.r.enroll(grant,nonce,proof_for_challenge(self.node,grant,nonce),now=self.now+61,epoch=1)

    def test_stale_authority_epoch_denied(self):
        self.r.fence(expected_epoch=1,new_epoch=2)
        grant=self.grant();nonce=self.r.challenge('edge-001',now=self.now)
        proof=proof_for_challenge(self.node,grant,nonce)
        with self.assertRaises(EdgeError):self.r.enroll(grant,nonce,proof,now=self.now,epoch=1)
        self.assertEqual(self.r.enroll(grant,nonce,proof,now=self.now,epoch=2)['node_id'],'edge-001')

    def test_tenant_scope_and_revocation(self):
        self.enroll()
        self.assertIsNone(self.r.status('edge-001',tenant='other'))
        self.r.revoke('edge-001',epoch=1)
        self.assertIsNone(self.r.status('edge-001',tenant='omega'))
        with self.assertRaises(EdgeError):self.enroll()

    def test_operator_key_pinned_on_disk(self):
        different=self.other.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)
        with self.assertRaises(EdgeError):EdgeRegistry(self.db,different)

    def test_database_permissions_and_no_symlink(self):
        link=self.dir/'shortcut';link.symlink_to(self.db)
        with self.assertRaises(EdgeError):EdgeRegistry(link,self.pub)
        self.dir.chmod(0o755)
        with self.assertRaises(EdgeError):EdgeRegistry(self.db,self.pub)

    def test_numeric_validation_fails_closed(self):
        for bad in [True,-1,'999',1<<70]:
            with self.subTest(bad=bad),self.assertRaises(EdgeError):self.grant(max_bytes=bad)

if __name__=='__main__':unittest.main()

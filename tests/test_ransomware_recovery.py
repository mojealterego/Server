"""E21 deterministic local cryptographic and fail-closed admission tests.

E20 and SMB data plane are controlled adapters here; physical SMB E2E is NOT_RUN.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption, PublicFormat

from atlas.ransomware_recovery import (RecoveryDenied, canonical, claim_once,
    destination_path, issue, parse_document, read_private, restore_authorized, require,
    verify_permit)

PIN = 'a' * 64
TIP = 'b' * 64


class E21Tests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.secure = self.root / 'secure'
        self.secure.mkdir(mode=0o700)
        self.claims = self.root / 'claims'
        self.claims.mkdir(mode=0o700)
        self.signer = Ed25519PrivateKey.generate()
        self.signer_path = self.secure / 'sign.key'
        self.signer_path.write_bytes(self.signer.private_bytes(
            Encoding.Raw, PrivateFormat.Raw, NoEncryption()))
        self.signer_path.chmod(0o600)
        self.public = self.signer.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self.authority_public = Ed25519PrivateKey.generate().public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw)
        self.dest = str(self.secure / 'recovered')
        self.doc = self.new_permit()
        self.set_doc = {'set': {'schema': 'omega.smb.recovery-set.v1', 'shares': {}}, 'sha256': PIN}

    def new_permit(self, **kw):
        settings = dict(tenant='omega', set_sha256=PIN, checkpoint_tip=TIP,
            destination=self.dest, nonce='f' * 32, issued_at=1000, expires_at=1500)
        settings.update(kw)
        return issue(self.signer_path, **settings)

    def admitted(self, **kw):
        authority_verifier = kw.pop("authority_verifier", lambda *a, **k: {"digest": TIP, "length": 1})
        settings = dict(permit=self.doc, recovery_public_key=self.public,
            authority_public_key=self.authority_public, checkpoint_dir=self.secure,
            checkpoint_tip=TIP, tenant='omega', recovery_set=self.set_doc,
            set_sha256=PIN, destination=Path(self.dest), claims_dir=self.claims,
            retrieve=lambda *_: None, inspect=lambda _: {'share': 'omega-compat'},
            restore=lambda *_: {'status': 'RESTORED', 'sha256': PIN}, now=1200)
        settings.update(kw)
        # The active upstream E20 and SMB storage contracts are mocked; there is
        # no false claim of dialect E2E or distributed authority.
        authority = types.ModuleType('atlas.authority_checkpoint')
        authority.verify = authority_verifier
        storage = types.ModuleType('atlas.storage_recovery')
        storage.validate = lambda doc, pin: require(pin == PIN, 'Pinned set mismatch')
        storage.restore_set = lambda *a, **k: {
            'status': 'RECOVERED_OFFLINE', 'set_sha256': PIN, 'shares': [
                'omega-compat', 'omega-secure', 'omega-models']}
        with patch.dict(sys.modules, {'atlas.authority_checkpoint': authority,
                                      'atlas.storage_recovery': storage}):
            return restore_authorized(**settings)

    def test_valid_signed_permit_and_pinned_identifiers(self):
        digest = verify_permit(self.doc, self.public, tenant='omega', set_sha256=PIN,
                               checkpoint_tip=TIP, destination=self.dest, now=1200)
        self.assertEqual(len(digest), 64)
        self.assertEqual(self.admitted()['authorization'], 'CONSUMED')
        self.assertEqual(len(list(self.claims.glob('*.claim'))), 1)

    def test_replay_is_rejected_before_restore(self):
        self.admitted()
        with self.assertRaisesRegex(RecoveryDenied, 'already used'):
            self.admitted()

    def test_failed_or_ambiguous_restore_is_not_replayable(self):
        module = types.ModuleType('atlas.storage_recovery')
        module.validate = lambda *_: None
        module.restore_set = lambda *a, **k: (_ for _ in ()).throw(OSError('disk lost'))
        authority = types.ModuleType('atlas.authority_checkpoint')
        authority.verify = lambda *_: {'digest': TIP, 'length': 1}
        with patch.dict(sys.modules, {'atlas.storage_recovery': module,
                                      'atlas.authority_checkpoint': authority}):
            with self.assertRaisesRegex(OSError, 'disk lost'):
                restore_authorized(permit=self.doc, recovery_public_key=self.public,
                    authority_public_key=self.authority_public, checkpoint_dir=self.secure,
                    checkpoint_tip=TIP, tenant='omega', recovery_set=self.set_doc,
                    set_sha256=PIN, destination=Path(self.dest), claims_dir=self.claims,
                    retrieve=lambda *_: None, inspect=lambda *_: None, restore=lambda *_: None,
                    now=1200)
        with self.assertRaisesRegex(RecoveryDenied, 'already used'):
            self.admitted()

    def test_target_and_checkpoint_mismatch_fail_before_claim(self):
        for overrides in ({'checkpoint_tip': 'c'*64}, {'set_sha256': 'e'*64},
                          {'tenant': 'other'}, {'destination': self.secure/'other'}):
            with self.subTest(overrides=overrides):
                with self.assertRaises(RecoveryDenied):
                    self.admitted(**overrides)
        self.assertEqual(list(self.claims.iterdir()), [])

    def test_wrong_separate_authority_key_fails(self):
        with self.assertRaisesRegex(RecoveryDenied, 'separate'):
            self.admitted(authority_public_key=self.public)

    def test_signed_bytes_tampering_is_rejected(self):
        for key, changed in (('nonce', 'e'*32), ('expires_at', 1600),
                             ('destination', str(self.secure/'else'))):
            with self.subTest(key=key):
                doc = dict(self.doc, **{key: changed})
                with self.assertRaises(RecoveryDenied):
                    verify_permit(doc, self.public, tenant='omega', set_sha256=PIN,
                                  checkpoint_tip=TIP, destination=doc['destination'], now=1200)

    def test_window_and_type_are_strict(self):
        for now in (999, 1501, True):
            with self.subTest(now=now), self.assertRaises(RecoveryDenied):
                verify_permit(self.doc, self.public, tenant='omega', set_sha256=PIN,
                              checkpoint_tip=TIP, destination=self.dest, now=now)
        for bad in (dict(self.doc, issued_at=True), dict(self.doc, expires_at=99999999),
                    dict(self.doc, nonce='x' * 32)):
            with self.assertRaises(RecoveryDenied):
                verify_permit(bad, self.public, tenant='omega', set_sha256=PIN,
                              checkpoint_tip=TIP, destination=self.dest, now=1200)

    def test_private_file_and_symlink_protection(self):
        self.signer_path.chmod(0o644)
        with self.assertRaises(RecoveryDenied): self.new_permit()
        self.signer_path.chmod(0o600)
        alias = self.secure / 'key-alias'
        alias.symlink_to(self.signer_path)
        with self.assertRaises(OSError): read_private(alias, 32, exact=32)
        os.chmod(self.secure, 0o755)
        with self.assertRaises(RecoveryDenied): self.new_permit()

    def test_canonical_json_and_duplicate_fields(self):
        doc_path = self.secure/'permit.json'
        doc_path.write_bytes(canonical(self.doc));doc_path.chmod(0o600)
        self.assertEqual(parse_document(doc_path, limit=4096), self.doc)
        doc_path.write_bytes(b'{"a":1,"a":2}')
        with self.assertRaisesRegex(RecoveryDenied, 'Duplicate'):
            parse_document(doc_path, limit=4096)
        doc_path.write_bytes(b'{"a": 1}')
        with self.assertRaisesRegex(RecoveryDenied, 'canonical'):
            parse_document(doc_path, limit=4096)

    def test_destination_no_overwrite_and_parent_symlink(self):
        target=Path(self.dest);target.write_text('do not overwrite')
        with self.assertRaisesRegex(RecoveryDenied, 'exists'):
            destination_path(self.dest)
        target.unlink()
        linked=self.secure/'link';linked.symlink_to(self.secure, target_is_directory=True)
        with self.assertRaises(RecoveryDenied):
            destination_path(str(linked/'out'))

    def test_cli_issue_process(self):
        cmd=[sys.executable, '-m','atlas.ransomware_recovery','issue',
             '--key',str(self.signer_path),'--tenant','omega','--set-sha256',PIN,
             '--checkpoint-tip',TIP,'--dest',self.dest,'--nonce','e'*32,
             '--issued-at','1000','--expires-at','1200']
        root=str(Path(__file__).resolve().parents[1])
        run=subprocess.run(cmd,cwd=root,capture_output=True,text=True,timeout=10)
        self.assertEqual(run.returncode,0,run.stderr)
        result=json.loads(run.stdout)
        self.assertEqual(result['signature'],self.new_permit(nonce='e'*32,expires_at=1200)['signature'])

    def test_no_unverified_chain_can_start_restore(self):
        with self.assertRaisesRegex(RecoveryDenied, 'history'):
            self.admitted(authority_verifier=lambda *a, **k: {'digest': 'c'*64, 'length': 1})
        self.assertEqual(list(self.claims.iterdir()), [])

    def test_reused_nonce_on_new_signed_document_is_denied(self):
        self.admitted()
        updated = self.new_permit(expires_at=1450)  # Same nonce, different valid signature.
        with self.assertRaisesRegex(RecoveryDenied, 'already used'):
            self.admitted(permit=updated)


if __name__ == '__main__':
    unittest.main()

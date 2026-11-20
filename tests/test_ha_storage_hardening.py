import os
import threading
from concurrent.futures import ThreadPoolExecutor
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from atlas.distributed_authority import Authority, AuthorityError, AuthorityGuard
from atlas import storage_fabric
from test_distributed_authority import TxnFixture


class AuthorityHardeningTests(unittest.TestCase):
    def setUp(self):
        self.backend = TxnFixture()
        self.authority = Authority(self.backend, 'production', '42')
        self.grant = self.authority.bootstrap('node-a', 'a' * 64, confirm_empty=True)

    def test_observed_revocation_is_sticky_after_rollback(self):
        guard = AuthorityGuard(self.authority, self.grant)
        guard.check()
        old_row = dict(self.backend.row)
        self.authority.transfer(self.grant.revision, 'node-b', 'b' * 64,
                                confirm_fenced=True, confirm_latest=True)
        with self.assertRaises(AuthorityError):
            guard.check()
        self.backend.row = old_row
        with self.assertRaises(AuthorityError):
            guard.check()

    def test_missing_grant_requires_restart_even_if_restored(self):
        guard = AuthorityGuard(self.authority, self.grant)
        old_row = self.backend.row
        self.backend.row = None
        with self.assertRaises(AuthorityError):
            guard.check()
        self.backend.row = old_row
        with self.assertRaises(AuthorityError):
            guard.check()

    def test_transient_outage_allows_same_grant_to_recover(self):
        guard = AuthorityGuard(self.authority, self.grant)
        self.backend.fail = True
        with self.assertRaises(AuthorityError):
            guard.check()
        self.backend.fail = False
        guard.check()

    def test_inflight_old_observation_cannot_clear_revocation(self):
        started, release = threading.Event(), threading.Event()
        old = self.grant
        def current():
            if threading.current_thread().name == 'MainThread':
                return None
            started.set()
            if not release.wait(3):
                raise RuntimeError('fixture timeout')
            return old
        guard = AuthorityGuard(self.authority, old)
        with patch.object(self.authority, 'current', side_effect=current):
            with ThreadPoolExecutor(max_workers=1) as pool:
                pending = pool.submit(guard.check)
                try:
                    self.assertTrue(started.wait(3))
                    with self.assertRaises(AuthorityError):
                        guard.check()
                finally:
                    release.set()
                with self.assertRaises(AuthorityError):
                    pending.result(timeout=3)

    def test_inconsistent_range_response_rejected(self):
        for extra in ({'count': '2'}, {'count': '0'}, {'more': True}, {'header': {'cluster_id': '42', 'revision': '0'}}):
            with self.subTest(extra=extra):
                def rpc(path, body):
                    return {**self.backend(path, body), **extra}
                with self.assertRaises(AuthorityError):
                    Authority(rpc, 'production', '42').current()


class SMBEnrollmentTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.binary = self.root / 'rclone'

    def fake(self, response):
        self.binary.write_text('#!/usr/bin/env python3\nimport sys\n'
                               'assert sys.argv[1:] == ["config", "redacted", "primary"]\n'
                               f'print({response!r}, end="")\n')
        self.binary.chmod(0o700)

    def test_real_subprocess_accepts_smb(self):
        self.fake('[primary]\ntype = smb\nhost = 192.0.2.1\n')
        storage_fabric.check_smb_alias('primary', rclone=str(self.binary))

    def test_real_subprocess_rejects_wrong_backend_or_ambiguous_config(self):
        for response in ('[primary]\ntype = sftp\n', '[other]\ntype = smb\n',
                         '[DEFAULT]\ntype = smb\n[primary]\n',
                         '[primary]\ntype = smb\ntype = crypt\n',
                         '[primary]\ntype = smb\n[other]\ntype = smb\n', 'x' * 70000):
            with self.subTest(length=len(response)):
                self.fake(response)
                with self.assertRaises(storage_fabric.FabricError):
                    storage_fabric.check_smb_alias('primary', rclone=str(self.binary))

    def test_type_environment_override_rejected_before_process(self):
        with patch.dict(os.environ, {'RCLONE_CONFIG_PRIMARY_TYPE': 'sftp'}):
            with self.assertRaises(storage_fabric.FabricError):
                storage_fabric.check_smb_alias('primary', rclone='/nonexistent')

    def test_config_deadline_kills_subprocess(self):
        self.binary.write_text('#!/usr/bin/env python3\nimport time\ntime.sleep(20)\n')
        self.binary.chmod(0o700)
        with self.assertRaisesRegex(storage_fabric.FabricError, 'deadline'):
            storage_fabric.check_smb_alias('primary', rclone=str(self.binary), timeout=1)

    def test_reader_checks_only_used_replicas_once(self):
        checked, reads = [], []
        def verify(alias):
            checked.append(alias)
            if alias == 'primary':
                raise storage_fabric.FabricError('Wrong backend')
        def read(remote, offset, length):
            reads.append(remote)
            return b'x' * length
        reader = storage_fabric.smb_reader(('primary', 'secondary'), verify=verify, read=read)
        self.assertEqual(checked, [])
        with self.assertRaises(storage_fabric.FabricError):
            reader('primary:omega-models/model.gguf', 0, 1)
        self.assertEqual(reads, [])
        self.assertEqual(reader('secondary:omega-models/model.gguf', 0, 1), b'x')
        self.assertEqual(reader('secondary:omega-models/model.gguf', 1, 1), b'x')
        with self.assertRaises(storage_fabric.FabricError):
            reader('other:omega-models/model.gguf', 0, 1)
        self.assertEqual(checked, ['primary', 'secondary'])
        self.assertEqual(len(reads), 2)

    def test_default_stage_receives_enrolled_reader_without_eager_network(self):
        import sys
        import types
        module = types.ModuleType('atlas.storage_cache')
        def stage(envelope, key, sha, cache, remotes, *, reader):
            self.assertTrue(callable(reader))
            return {'sha256': sha, 'status': 'ALREADY_PRESENT'}
        module.stage = stage
        document = {'schema': 'omega.storage.fabric.v1', 'models': {'qwen': {
            'sha256': 'a'*64, 'public_key': 'MCowBQYDK2VwAyEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=',
            'remotes': ['primary']}}, 'recovery': {'sha256': 'b'*64, 'remotes': ['backup:vault']}}
        with patch.dict(sys.modules, {'atlas.storage_cache': module}):
            with patch.object(storage_fabric, 'check_smb_alias', side_effect=AssertionError('unexpected config read')):
                result = storage_fabric.Fabric(document, storage_fabric.digest(document)).stage_model('qwen', {}, self.root)
        self.assertEqual(result['status'], 'ALREADY_PRESENT')

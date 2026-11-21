"""E12 regression: registry pins, backend identity and fail-closed probes."""
import json
import os
from pathlib import Path
import tempfile
import unittest
from atlas import provider_registry as registry


class ProviderEnrollmentGateTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root=Path(temp.name)
        self.config=self.root/'rclone.conf'
        self.config.write_text('[vault]\ntype = s3\nprovider = Cloudflare\nendpoint = https://'+('a'*32)+'.r2.cloudflarestorage.com\n')
        self.config.chmod(0o600)
        self.fake=self.root/'rclone'
        self.fake.write_text('''#!/usr/bin/env python3
import json,sys
argv=sys.argv[1:]
if argv[2:4]==['config','redacted']:
 print('[vault]\\ntype = s3\\nprovider = Cloudflare\\nendpoint = https://'+('a'*32)+'.r2.cloudflarestorage.com')
elif argv[2:4]==['about','vault:']:
 print(json.dumps({'total':100000, 'free':70000, 'used':30000}))
else:sys.exit(5)
''')
        self.fake.chmod(0o700)
        self.row=dict(id='cloud',provider='cloudflare_r2',account='one',domain='primary',alias='vault',
            authorized=True,free_tier_attested=True,write_enabled=False,limit_bytes=90000,
            reserve_bytes=10000,monthly_write_bytes=20000,monthly_read_bytes=30000,
            monthly_operations=15,attested_at=1700000000)
        self.doc={'schema':registry.SCHEMA,'max_age_seconds':600,'providers':[self.row]}

    def inspect(self,**changes):
        self.row.update(changes)
        return registry.inspect(self.doc,registry.digest(self.doc),now=1700000000,
            config=self.config,executable=str(self.fake),extra_env={})['providers']['cloud']

    def test_valid_enrollment_is_readonly(self):
        self.assertEqual(self.inspect()['status'],'ENROLLED_READ_ONLY')
        self.assertEqual(self.inspect()['available_bytes'],20000)

    def test_no_attestation_stops_before_subprocess(self):
        self.fake.unlink()
        self.assertEqual(self.inspect(free_tier_attested=False)['status'],'BLOCKED_OPERATOR_AUTH')

    def test_wrong_backend_identity_denied(self):
        self.assertEqual(self.inspect(provider='google_drive')['status'],'BLOCKED_PROBE')

    def test_alias_and_account_duplication_denied(self):
        self.doc['providers'].append({**self.row,'id':'second'})
        with self.assertRaises(registry.ProviderError):registry.validate(self.doc)
        self.doc['providers'][1]['account']='different'
        with self.assertRaises(registry.ProviderError):registry.validate(self.doc)

    def test_registry_pin_detects_tampering(self):
        good=registry.digest(self.doc)
        self.row['monthly_operations']=99
        with self.assertRaises(registry.ProviderError):
            registry.inspect(self.doc,good,now=1700000000)

    def test_terabox_is_not_automatically_admitted(self):
        self.doc['providers']=[{**self.row,'provider':'terabox','alias':None,'write_enabled':False}]
        reply=registry.inspect(self.doc,registry.digest(self.doc),now=1700000000)
        self.assertEqual(reply['providers']['cloud']['status'],'BLOCKED_OFFICIAL_OAUTH')

    def test_injected_environment_backend_denied(self):
        self.assertEqual(registry.inspect(self.doc,registry.digest(self.doc),now=1700000000,
            config=self.config,executable=str(self.fake),
            extra_env={'RCLONE_CONFIG_VAULT_TYPE':'local'})['providers']['cloud']['status'],'BLOCKED_PROBE')

if __name__=='__main__': unittest.main()

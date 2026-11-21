import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from atlas import provider_registry as p


class ProviderRegistryTests(unittest.TestCase):
    def setUp(self):
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        self.root = Path(d.name)
        self.config = self.root / 'rclone.conf'
        self.config.write_text('[cloud]\ntype = s3\nprovider = Cloudflare\nendpoint = https://'+'a'*32+'.r2.cloudflarestorage.com\n')
        self.config.chmod(0o600)
        self.binary = self.root / 'rclone'
        self.binary.write_text('''#!/usr/bin/env python3
import json,sys
args=sys.argv[1:]
assert args[:2]==['--config',sys.argv[2]]
a=args[2:]
if a[:2]==['config','redacted']:
    print('[cloud]\\ntype = s3\\nprovider = Cloudflare\\nendpoint = https://'+'a'*32+'.r2.cloudflarestorage.com\\n')
elif a[:2]==['about','cloud:']:
    print(json.dumps({'total':100000,'free':70000,'used':30000}))
else: sys.exit(1)
''')
        self.binary.chmod(0o700)
        self.row = dict(id='cloud1', provider='cloudflare_r2', account='cloudflare_account_1',
                        domain='cloudflare-main', alias='cloud', authorized=True,
                        free_tier_attested=True, write_enabled=False, limit_bytes=90000,
                        reserve_bytes=10000, attested_at=1700000000, monthly_write_bytes=20000,
                        monthly_read_bytes=30000, monthly_operations=100)
        self.doc = dict(schema=p.SCHEMA,max_age_seconds=600,providers=[self.row])

    def test_valid_read_only_enrollment(self):
        result = p.inspect(self.doc, p.digest(self.doc), now=1700000000,
                           config=self.config, executable=str(self.binary), extra_env={})
        self.assertEqual(result['providers']['cloud1']['status'],'ENROLLED_READ_ONLY')
        self.assertEqual(result['providers']['cloud1']['available_bytes'],20000)

    def test_no_account_free_tier_attestation_means_no_probe(self):
        self.row['free_tier_attested'] = False
        result = p.inspect(self.doc, p.digest(self.doc), now=1700000000,
                           config=self.config, executable='/does/not/exist')
        self.assertEqual(result['providers']['cloud1']['status'],'BLOCKED_OPERATOR_AUTH')

    def test_rejects_duplicate_account_and_alias(self):
        duplicate = dict(self.row,id='cloud2')
        self.doc['providers'].append(duplicate)
        with self.assertRaises(p.ProviderError):p.validate(self.doc)
        duplicate['account']='unique'
        with self.assertRaises(p.ProviderError):p.validate(self.doc)

    def test_wrong_backend_fails_closed(self):
        self.row['provider']='google_drive'
        result = p.inspect(self.doc,p.digest(self.doc),now=1700000000,
                           config=self.config,executable=str(self.binary),extra_env={})
        self.assertEqual(result['providers']['cloud1']['status'],'BLOCKED_PROBE')

    def test_tampered_registry_refused(self):
        pin=p.digest(self.doc)
        self.row['monthly_operations']=9999
        with self.assertRaises(p.ProviderError):p.inspect(self.doc,pin,now=1700000000)

    def test_tbox_not_implicitly_admitted(self):
        self.doc['providers']=[dict(self.row,id='tbox',provider='terabox',alias=None,write_enabled=False)]
        result=p.inspect(self.doc,p.digest(self.doc),now=1700000000)
        self.assertEqual(result['providers']['tbox']['status'],'BLOCKED_OFFICIAL_OAUTH')
        self.doc['providers'][0]['write_enabled']=True
        with self.assertRaises(p.ProviderError):p.validate(self.doc)

    def test_config_permission_and_env_overrides(self):
        self.config.chmod(0o644)
        result=p.inspect(self.doc,p.digest(self.doc),now=1700000000,
                         config=self.config,executable=str(self.binary),extra_env={})
        self.assertEqual(result['providers']['cloud1']['status'],'BLOCKED_PROBE')
        self.config.chmod(0o600)
        result=p.inspect(self.doc,p.digest(self.doc),now=1700000000,
                         config=self.config,executable=str(self.binary),extra_env={'RCLONE_CONFIG_CLOUD_TYPE':'local'})
        self.assertEqual(result['providers']['cloud1']['status'],'BLOCKED_PROBE')

    def test_rejects_stale_attestation(self):
        self.row['attested_at']=1690000000
        result=p.inspect(self.doc,p.digest(self.doc),now=1700000000,
                         config=self.config,executable=str(self.binary),extra_env={})
        self.assertEqual(result['providers']['cloud1']['status'],'BLOCKED_STALE_ATTESTATION')

    def test_fake_rclone_deadline_and_output_limit(self):
        self.binary.write_text('#!/usr/bin/env python3\nimport time\ntime.sleep(15)\n')
        self.binary.chmod(0o700)
        with self.assertRaises(p.ProviderError):p.check_remote(self.row,config=self.config,executable=str(self.binary),timeout=1,extra_env={})
        self.binary.write_text('#!/usr/bin/env python3\nprint("x"*100000)\n')
        with self.assertRaises(p.ProviderError):p.check_remote(self.row,config=self.config,executable=str(self.binary),timeout=1,extra_env={})

    def test_duplicate_json_keys_rejected(self):
        path=self.root/'duplicate.json';path.write_text('{"schema":"a","schema":"b"}')
        with self.assertRaises(p.ProviderError):p.bounded_json(path)

if __name__=='__main__':unittest.main()

class CloudflareBindingTests(unittest.TestCase):
    def test_wrong_s3_endpoint_cannot_be_admitted_as_cloudflare(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            config=root/'config';config.write_text('x');config.chmod(0o600)
            fake=root/'rclone'
            fake.write_text("#!/usr/bin/env python3\nimport sys\nprint('[cloud]\\ntype = s3\\nprovider = Cloudflare\\nendpoint = https://s3.amazonaws.com\\n')\n")
            fake.chmod(0o700)
            row={'alias':'cloud','provider':'cloudflare_r2'}
            with self.assertRaises(p.ProviderError):p.check_remote(row,config=config,executable=str(fake),extra_env={})

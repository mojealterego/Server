"""E22a: deterministic subprocess-based qualification tests; not live SMB."""
from __future__ import annotations
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch

from tools.smb_qualification import QualificationError, qualify, p95


FAKE_CLIENT = r'''#!/usr/bin/env bash
set -euo pipefail
args=("$@")
share="${args[0]##*/}"
dialect=""
auth=""
protection=""
minimum=""
for ((i=0; i<${#args[@]}; i++)); do
  case "${args[i]}" in
    -A) auth="${args[i+1]}" ;;
    -m) dialect="${args[i+1]}" ;;
    --option=client\ min\ protocol=*) minimum="${args[i]#*=}" ;;
    --client-protection=*) protection="${args[i]#*=}" ;;
  esac
done
[ "$(stat -c %a "$auth")" = 600 ]
[ "$minimum" = "client min protocol=$dialect" ]
if [ "$share" = omega-compat ]; then
  [ "$dialect" = SMB2_10 ] && [ "$protection" = sign ]
else
  [ "$share" = omega-secure ] && [ "$dialect" = SMB3_11 ] && [ "$protection" = encrypt ]
fi
read -r operation arg1 arg2 <<< "${args[${#args[@]}-1]}"
if [ "$operation" = put ]; then name="$arg2";else name="$arg1";fi
[[ "$name" = omega-e22-*.bin ]]
dir="$OMEGA_E22_FAKE_REMOTE/$share"
mkdir -p "$dir"
case "$operation" in
 put) cp "$arg1" "$dir/$name"; if [ "${OMEGA_E22_FAIL_PUT:-0}" = 1 ]; then exit 12; fi ;;
 get) if [ "${OMEGA_E22_FAIL_GET:-0}" = 1 ]; then exit 11; fi; cp "$dir/$name" "$arg2"; if [ "${OMEGA_E22_CORRUPT:-0}" = 1 ]; then : > "$arg2"; fi ;;
 del) if [ "${OMEGA_E22_FAIL_DELETE:-0}" = 1 ]; then exit 10; fi; rm "$dir/$name" ;;
 *) exit 13 ;;
esac
''' 


class QualificationTests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup);self.root=Path(tmp.name)
        self.vps=self.root/'vps';(self.vps/'smb-secrets').mkdir(parents=True,mode=0o700)
        for name in ('compat','secure'):
            p=self.vps/'smb-secrets'/f'{name}_password';p.write_text('b'*64+'\n');p.chmod(0o600)
        self.remote=self.root/'fake-remote';self.remote.mkdir()
        self.bin=self.root/'bin';self.bin.mkdir();fake=self.bin/'smbclient';fake.write_text(FAKE_CLIENT);fake.chmod(0o700)
        env=dict(os.environ);env['PATH']=str(self.bin)+os.pathsep+env['PATH'];env['OMEGA_E22_FAKE_REMOTE']=str(self.remote)
        self.env_patch=patch.dict(os.environ,env,clear=True);self.env_patch.start();self.addCleanup(self.env_patch.stop)

    def run_qualify(self,**kwargs):
        options={'root':self.vps,'address':'127.0.0.1','port':1445,'allow_network':False,'mib':1,'samples':3,'timeout':10}
        options.update(kwargs)
        return qualify(**options)

    def test_both_protocols_integrity_samples_and_cleanup(self):
        report=self.run_qualify()
        self.assertEqual(report['status'],'OBSERVED_NOT_CERTIFIED')
        self.assertEqual(report['client_dialect_attestation'],'NOT_INDEPENDENTLY_VERIFIED')
        self.assertEqual([x['share'] for x in report['scenarios']],['omega-compat','omega-secure'])
        for scenario in report['scenarios']:
            self.assertEqual(len(scenario['measurements']),3)
            for measurement in scenario['measurements']:
                self.assertEqual(measurement['bytes'],1<<20)
                self.assertGreater(measurement['write_ms'],0)
                self.assertGreater(measurement['read_ms'],0)
                self.assertEqual(len(measurement['sha256']),64)
            self.assertGreater(scenario['write_mib_s_median'],0)
            self.assertGreater(scenario['read_mib_s_median'],0)
        self.assertFalse(list(self.remote.rglob('*.bin')))
        self.assertNotIn('b'*64,json.dumps(report))

    def test_rejects_network_exposure(self):
        for address in ('0.0.0.0','8.8.8.8','169.254.7.1','localhost','::1'):
            with self.subTest(address=address),self.assertRaises(QualificationError):
                self.run_qualify(address=address,allow_network=True)
        with self.assertRaises(QualificationError):self.run_qualify(address='192.168.1.8')
        self.assertEqual(len(list(self.remote.rglob('*.bin'))),0)

    def test_rejects_unsafe_limits(self):
        for kw in ({'samples':1},{'samples':21},{'samples':True},{'mib':0},{'mib':17},
                   {'mib':True},{'timeout':1},{'timeout':True},{'port':0}):
            with self.subTest(kw=kw),self.assertRaises(QualificationError):self.run_qualify(**kw)

    def test_rejects_symlink_secret_and_permissive_secret(self):
        secret=self.vps/'smb-secrets'/'compat_password';secret.chmod(0o644)
        with self.assertRaises(QualificationError):self.run_qualify()
        secret.chmod(0o600);target=self.root/'original';target.write_text('b'*64+'\n')
        secret.unlink();secret.symlink_to(target)
        with self.assertRaises(QualificationError):self.run_qualify()

    def test_detects_corrupt_readback_and_cleans_remote(self):
        with patch.dict(os.environ,{'OMEGA_E22_CORRUPT':'1'}):
            with self.assertRaisesRegex(QualificationError,'integrity'):
                self.run_qualify()
        self.assertFalse(list(self.remote.rglob('*.bin')))

    def test_failed_get_does_not_leave_remote_payload(self):
        with patch.dict(os.environ,{'OMEGA_E22_FAIL_GET':'1'}):
            with self.assertRaisesRegex(QualificationError,'operation failed: get'):
                self.run_qualify()
        self.assertFalse(list(self.remote.rglob('*.bin')))

    def test_ambiguous_put_cleans_random_remote_filename(self):
        with patch.dict(os.environ,{'OMEGA_E22_FAIL_PUT':'1'}):
            with self.assertRaisesRegex(QualificationError,'operation failed: put'):
                self.run_qualify()
        self.assertFalse(list(self.remote.rglob('*.bin')))

    def test_hardlinked_secret_rejected(self):
        source=self.vps/'smb-secrets'/'compat_password'
        (self.root/'extra-hardlink').hardlink_to(source)
        with self.assertRaises(QualificationError):self.run_qualify()

    def test_private_network_requires_explicit_optin(self):
        result=self.run_qualify(address='10.7.2.6',allow_network=True)
        self.assertEqual(result['address'],'10.7.2.6')

    def test_cleanup_failure_fails_closed(self):
        with patch.dict(os.environ,{'OMEGA_E22_FAIL_DELETE':'1'}):
            with self.assertRaisesRegex(QualificationError,'cleanup'):
                self.run_qualify()
        self.assertTrue(list(self.remote.rglob('*.bin')))

    def test_private_report_no_overwrite(self):
        report_path=self.root/'report.json'
        report=self.run_qualify(report_path=report_path)
        self.assertEqual(json.loads(report_path.read_text()),report)
        self.assertEqual(stat.S_IMODE(report_path.stat().st_mode),0o600)
        with self.assertRaises(QualificationError):self.run_qualify(report_path=report_path)
        self.assertEqual(json.loads(report_path.read_text()),report)

    def test_report_path_symlink_refused(self):
        original=self.root/'original';original.write_text('keep')
        link=self.root/'alias';link.symlink_to(original)
        with self.assertRaises(QualificationError):self.run_qualify(report_path=link)
        self.assertEqual(original.read_text(),'keep')

    def test_quantile_bounds(self):
        self.assertEqual(p95([1,2,3,4,5]),5)
        with self.assertRaises(QualificationError):p95([])

    def test_cli_subprocess_produces_json(self):
        import subprocess
        cp=subprocess.run([sys.executable,'-m','tools.smb_qualification','--root',str(self.vps),
                '--port','1445','--mib','1','--samples','3','--timeout','10'],
                cwd=Path(__file__).resolve().parents[1],capture_output=True,text=True,timeout=30)
        self.assertEqual(cp.returncode,0,cp.stderr)
        self.assertEqual(json.loads(cp.stdout)['status'],'OBSERVED_NOT_CERTIFIED')


if __name__=='__main__':unittest.main()

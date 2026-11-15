import pathlib
import subprocess
import tempfile
import unittest
import os
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]


class DeploymentContractTests(unittest.TestCase):
    def test_compose_isolated_services(self):
        import re
        text = (ROOT/'vps/compose.yaml').read_text()
        sections = {}
        for match in re.finditer(r'(?m)^  (ftps|sftp|media-worker):$', text):
            nxt = re.search(r'(?m)^  (?:ftps|sftp|media-worker):$', text[match.end():])
            stop = match.end() + nxt.start() if nxt else len(text)
            sections[match.group(1)] = text[match.end():stop]
        self.assertEqual(set(sections), {'ftps','sftp','media-worker'})
        for name, section in sections.items():
            self.assertIn('no-new-privileges:true',section)
            self.assertIn('cap_drop:',section)
            self.assertNotIn('privileged: true',section)
            self.assertIn('pids_limit:',section)
        for name in ('ftps','sftp'):
            self.assertIn('127.0.0.1',sections[name])
        self.assertIn('profiles: [media]',sections['media-worker'])
        self.assertIn('SYS_CHROOT',sections['sftp'])

    def test_docker_media_context_excludes_large_local_models_and_secrets(self):
        ignored=set((ROOT/'vps/.dockerignore').read_text().splitlines())
        self.assertTrue({'data','models','engine','secrets','.env'}.issubset(ignored))

    def test_ftps_tls_is_not_optional_or_anonymous(self):
        conf = (ROOT/'vps/ftps/proftpd.conf.template').read_text()
        entry = (ROOT/'vps/ftps/entrypoint.sh').read_text()
        self.assertIn('TLSRequired on', conf)
        self.assertIn('DefaultRoot ~', conf)
        self.assertIn('TLS certificate/private key mismatch', entry)
        self.assertNotIn('Anonymous ~ftp', conf)
        self.assertNotIn('DenyAll', conf)

    def test_sftp_no_password_or_shell(self):
        conf = (ROOT/'vps/sftp/sshd_config').read_text()
        self.assertIn('PasswordAuthentication no', conf)
        self.assertIn('ChrootDirectory /srv/omega-jail', conf)
        self.assertIn('ForceCommand internal-sftp', conf)
        self.assertIn('PermitRootLogin no', conf)
        self.assertIn('AuthenticationMethods publickey', conf)

    def test_shell_syntax(self):
        files = [*ROOT.glob('vps/*.sh'), *ROOT.glob('cloud/*.sh'), *ROOT.glob('termux/*.sh')]
        for file in files:
            with self.subTest(file=file.name):
                subprocess.run(['bash', '-n', str(file)], check=True)
        for file in ROOT.glob('vps/*/entrypoint.sh'):
            subprocess.run(['sh', '-n', str(file)], check=True)

    def test_termux_initialize_no_secret_in_code(self):
        with tempfile.TemporaryDirectory() as d:
            state = pathlib.Path(d) / 'state'
            p = subprocess.run([sys.executable, str(ROOT/'termux/omega_node.py'), 'init',
                                '--without-webdav', '--root', str(state)],
                               text=True, capture_output=True, timeout=15)
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertTrue((state/'client_ed25519').is_file())
            self.assertEqual((state/'client_ed25519').stat().st_mode & 0o777, 0o600)
            self.assertTrue((state/'authorized_keys').read_text().startswith('ssh-ed25519 '))
            self.assertTrue((state/'host_ed25519').is_file())

    def test_cloud_refuses_traversal(self):
        with tempfile.TemporaryDirectory() as d:
            fake = pathlib.Path(d)/'rclone'
            fake.write_text('#!/bin/sh\necho remote1:\necho remote2:\n')
            fake.chmod(0o755)
            env = {**os.environ, 'PATH': d+os.pathsep+os.environ['PATH']}
            p = subprocess.run(['bash', str(ROOT/'cloud/make_union.sh'), 'u',
                                'remote1:../../bad', 'remote2:safe'],
                               text=True, capture_output=True, env=env)
            self.assertNotEqual(p.returncode, 0)
            self.assertIn('Invalid upstream', p.stderr)

    def test_sample_onnx_integrity(self):
        import hashlib
        f = ROOT/'samples/xor-neural.onnx'
        self.assertEqual(f.stat().st_size, 1993)
        self.assertEqual(hashlib.sha256(f.read_bytes()).hexdigest(),
                         '4429fec3a4ad5d7c05842fa27f245ed1f8323629c3622aa9d44dfca1b179ecdc')


if __name__ == '__main__':
    unittest.main()

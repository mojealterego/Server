import importlib.util
import os
import pathlib
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


def load(name, filename):
    import sys
    source_dir = str(ROOT / 'termux')
    if source_dir not in sys.path: sys.path.insert(0,source_dir)
    spec = importlib.util.spec_from_file_location(name, ROOT / 'termux' / filename)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class MobileTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.node = load('omega_node', 'omega_node.py')
        cls.inventory = load('model_inventory', 'model_inventory.py')

    def test_sftp_keys_not_password(self):
        with tempfile.TemporaryDirectory() as d:
            home = pathlib.Path(d)
            (home / 'authorized_keys').write_text('ssh-ed25519 AAAA012345 demo\n')
            (home / 'hostkey').write_text('TEST')
            argv = self.node.sftp_command('rclone', home/'data', '127.0.0.1', 2022, home/'authorized_keys', home/'hostkey')
            self.assertIn('--authorized-keys', argv)
            self.assertIn('--key', argv)
            self.assertNotIn('--pass', argv)
            self.assertEqual(argv[argv.index('--addr')+1], '127.0.0.1:2022')

    def test_webdav_requires_htpasswd_and_localhost(self):
        with tempfile.TemporaryDirectory() as d:
            base = pathlib.Path(d)
            auth = base / 'htpasswd'
            auth.write_text('omega:$2y$10$fake\n')
            argv = self.node.webdav_command('rclone', base/'data', auth)
            self.assertIn('--htpasswd', argv)
            self.assertEqual(argv[argv.index('--addr') + 1], '127.0.0.1:8081')
            with self.assertRaises(ValueError):
                self.node.webdav_command('rclone', base/'data', base/'missing')

    def test_reject_bad_bind(self):
        for addr in ['', '0.0.0.0;rm -rf /', '[]', 'localhost:22']:
            with self.assertRaises(ValueError):
                self.node.check_bind(addr)
        self.assertEqual(self.node.check_bind('127.0.0.1'), '127.0.0.1')
        self.assertEqual(self.node.check_bind('0.0.0.0'), '0.0.0.0')

    def test_llm_invalid_model_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            p = pathlib.Path(d) / 'x.gguf'
            p.write_bytes(b'x'*16)
            with self.assertRaises(ValueError):
                self.node.llm_command('llama-server', p, 4, 2048)
            import struct
            def string_kv(key,value):
                k=key.encode();v=value.encode()
                return struct.pack('<Q',len(k))+k+struct.pack('<IQ',8,len(v))+v
            p.write_bytes(b'GGUF'+struct.pack('<IQQ',3,0,1)+string_kv('general.architecture','qwen3'))
            cmd = self.node.llm_command('llama-server', p, 4, 2048)
            self.assertIn('--parallel', cmd)
            self.assertEqual(cmd[cmd.index('--host')+1], '127.0.0.1')

    def test_model_inventory_category_and_symlinks(self):
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d)
            (root/'Huihui-Qwen3-Q4_K_M.gguf').write_bytes(b'GGUF'+b'0'*12)
            (root/'wan_2.1_vae.safetensors').write_bytes(b'123')
            (root/'mmproj-F16.gguf').write_bytes(b'GGUF'+b'x')
            (root/'ignored.txt').write_text('hi')
            (root/'sym.gguf').symlink_to(root/'Huihui-Qwen3-Q4_K_M.gguf')
            data = self.inventory.scan(root, hash_files=False)
            self.assertEqual(len(data), 3)
            self.assertEqual(data[0]['category'], 'llm')
            self.assertTrue(any(x['category']=='vae' for x in data))
            self.assertTrue(any(x['category']=='projector' for x in data))

    def test_model_manifest_sha256(self):
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d)
            (root/'xor-neural.onnx').write_bytes(b'test')
            data = self.inventory.scan(root, hash_files=True)
            self.assertEqual(len(data), 1)
            self.assertEqual(len(data[0]['sha256']), 64)
            self.assertEqual(data[0]['category'], 'onnx')

    def test_restart_budget(self):
        budget = self.node.RestartBudget(limit=3, window=60)
        for t in [10, 11, 12]:
            self.assertTrue(budget.allow(t))
        self.assertFalse(budget.allow(13))
        self.assertTrue(budget.allow(72))

    def test_same_ports_not_used(self):
        self.assertEqual(len(set(self.node.PORTS.values())), len(self.node.PORTS))


if __name__ == '__main__':
    unittest.main()

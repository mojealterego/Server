import configparser
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch
from tools.smbctl import prepare, prepare_layout, binding, SmbError, compose, probe

ROOT = Path(__file__).resolve().parents[1]

class SMBTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(); self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)

    def test_reject_public_and_wildcard(self):
        for addr in ('0.0.0.0','8.8.8.8','169.254.1.1','224.0.0.1','192.0.2.1','localhost','::1'):
            with self.subTest(addr=addr), self.assertRaises(SmbError): binding(addr,445,True)
        with self.assertRaises(SmbError): binding('192.168.1.10',445,False)
        self.assertEqual(binding('192.168.1.10',445,True),'192.168.1.10')
        self.assertEqual(binding('127.0.0.1',1445,False),'127.0.0.1')

    def test_bad_port(self):
        for port in (0,65536,True,'445'):
            with self.assertRaises(SmbError): binding('127.0.0.1',port,False)

    def test_prepare_requires_root(self):
        with patch('tools.smbctl.os.geteuid',return_value=1000):
            with self.assertRaises(SmbError): prepare(self.root)
        self.assertEqual(list(self.root.iterdir()),[])

    def provision(self):
        if os.geteuid()==0: prepare(self.root)
        else:
            owner=(os.geteuid(),os.getegid());prepare_layout(self.root,owner,owner,owner)

    def test_prepare_idempotent_and_separate(self):
        self.provision()
        paths=[self.root/'smb-secrets'/f'{k}_password' for k in ('compat','secure')]
        first=[p.read_bytes() for p in paths]
        self.assertNotEqual(*first)
        for p in paths:
            self.assertEqual(stat.S_IMODE(p.stat().st_mode),0o600)
            self.assertEqual(len(p.read_bytes()),65)
        for path,uid in [('smb-data/compat',10002),('smb-data/secure',10003),('smb-models',10003)]:
            st=(self.root/path).stat(); expected=(uid,uid) if os.geteuid()==0 else (os.geteuid(),os.getegid());self.assertEqual((st.st_uid,st.st_gid,stat.S_IMODE(st.st_mode)),(*expected,0o700))
        self.provision(); self.assertEqual([p.read_bytes() for p in paths],first)

    def test_no_overwrite_or_symlink(self):
        self.provision(); p=self.root/'smb-secrets'/'secure_password'; p.chmod(0o644)
        before=p.read_bytes()
        with self.assertRaises(SmbError): self.provision()
        self.assertEqual(p.read_bytes(),before); self.assertEqual(stat.S_IMODE(p.stat().st_mode),0o644)
        p.unlink(); target=self.root/'outside';target.write_text('untouched'); p.symlink_to(target)
        with self.assertRaises(SmbError): self.provision()
        self.assertEqual(target.read_text(),'untouched')

    def test_unsafe_directory_refused(self):
        s=self.root/'smb-data';s.mkdir(mode=0o777);s.chmod(0o777)
        with self.assertRaises(SmbError): self.provision()

    def test_protocol_and_share_policy(self):
        conf=configparser.ConfigParser(interpolation=None);conf.read(ROOT/'vps/smb/smb.conf')
        g=conf['global'];self.assertEqual(g['server min protocol'],'SMB2_02');self.assertEqual(g['server max protocol'],'SMB3_11')
        self.assertEqual(g['server signing'],'mandatory');self.assertEqual(g['map to guest'],'Never');self.assertEqual(g['server smb encrypt'],'if_required')
        self.assertEqual(set(conf.sections()),{'global','omega-compat','omega-secure','omega-models'})
        for name,account,encrypt,ro in [('omega-compat','omega-compat','if_required','no'),('omega-secure','omega-secure','required','no'),('omega-models','omega-secure','required','yes')]:
            sec=conf[name];self.assertEqual(sec['valid users'],account);self.assertEqual(sec['server smb encrypt'],encrypt);self.assertEqual(sec['read only'],ro);self.assertEqual(sec['guest ok'],'no')
        self.assertEqual(g['wide links'],'no');self.assertEqual(g['follow symlinks'],'no')

    def test_compose_isolation(self):
        s=(ROOT/'vps/compose.smb.yaml').read_text()
        self.assertIn('${SMB_BIND_ADDRESS:-127.0.0.1}:${SMB_PORT:-445}:1445/tcp',s)
        self.assertIn('source: ./smb-models',s);self.assertIn('read_only: true',s)
        self.assertNotIn('OMEGA_DATA_DIR',s);self.assertNotIn('/var/run/docker.sock',s)
        self.assertEqual(s.count('create_host_path: false'),5)

    def test_compose_uses_fixed_arguments(self):
        with patch('tools.smbctl.subprocess.run') as run:
            compose('up','10.0.0.5',445,True)
            argv=run.call_args.args[0];self.assertEqual(argv[-4:],['up','-d','--build','smb'])
            self.assertEqual(run.call_args.kwargs['env']['SMB_BIND_ADDRESS'],'10.0.0.5')
            with self.assertRaises(SmbError):compose('up','8.8.8.8',445,True)
            self.assertEqual(run.call_count,1)

    def test_probe_matrix_and_cleanup(self):
        from types import SimpleNamespace
        self.provision(); calls=[]; payload={}
        def fake(argv, **kwargs):
            cmd=argv[-1];share=argv[1].split('/')[-1];version=argv[argv.index('-m')+1]
            auth=Path(argv[argv.index('-A')+1]);self.assertEqual(stat.S_IMODE(auth.stat().st_mode),0o600)
            account=auth.read_text().splitlines()[0].split(' = ')[1];calls.append((share,version,account,cmd))
            self.assertNotIn('password = ', ' '.join(argv))
            if version=='NT1' or share!='omega-compat' and (version=='SMB2_10' or account=='omega-compat') or share=='omega-models' and cmd.startswith('put '):
                return SimpleNamespace(returncode=1,stdout=b'',stderr=b'NT_STATUS_ACCESS_DENIED')
            if cmd.startswith('put '):payload[cmd.split()[2]]=(Path(kwargs['cwd'])/'send.bin').read_bytes()
            if cmd.startswith('get '):(Path(kwargs['cwd'])/'recv.bin').write_bytes(payload[cmd.split()[1]])
            if cmd.startswith('del '):payload.pop(cmd.split()[1],None)
            return SimpleNamespace(returncode=0,stdout=b'',stderr=b'')
        with patch('tools.smbctl.subprocess.run',side_effect=fake):
            result=probe(self.root,'127.0.0.1',1445)
        self.assertEqual(result['status'],'PASS');self.assertFalse(payload);self.assertIn(('omega-secure','SMB2_10','omega-secure','ls'),calls)

    def test_probe_refuses_missing_security_rejection(self):
        from types import SimpleNamespace
        self.provision()
        def insecure(argv, **kwargs):
            if argv[-1].startswith('get '):
                work=Path(kwargs['cwd']);(work/'recv.bin').write_bytes((work/'send.bin').read_bytes())
            return SimpleNamespace(returncode=0,stdout=b'',stderr=b'')
        with patch('tools.smbctl.subprocess.run',side_effect=insecure):
            with self.assertRaisesRegex(SmbError,'Forbidden operation succeeded'):probe(self.root,'127.0.0.1',1445)

if __name__=='__main__':unittest.main()

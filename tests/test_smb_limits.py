import configparser
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch
from vps.smb.limits import parse_limits, check_volumes, LimitError
from tools.smbctl import prepare_layout, volume_policy, SmbError
import os

ROOT=Path(__file__).resolve().parents[1]
class LimitsTests(unittest.TestCase):
    def test_parse(self):
        self.assertEqual(parse_limits('1,2,3'),(1048576,2097152,3145728))
        for value in ('','1,2','0,1,2','-1,2,3','1,2,3,4','1,2,1.5','1,2,999999999999999999999'):
            with self.assertRaises(LimitError):parse_limits(value)
    def test_volume_checks(self):
        with tempfile.TemporaryDirectory() as d:
            paths=[Path(d)/n for n in ('a','b','c')]
            for p in paths:p.mkdir()
            def mount(p):return True
            def device(p):return paths.index(p)+1 if p in paths else 0
            def usage(p):return Mock(f_blocks=1024,f_frsize=1024,f_bavail=512)
            rows=check_volumes(paths,(1048576,)*3,mount=mount,device=device,usage=usage,layout=lambda p:None)
            self.assertEqual(len(rows),3);self.assertEqual(rows[0]['available_bytes'],524288)
            for kwargs in ({'mount':lambda p:False},{'device':lambda p:0},{'device':lambda p:1 if p in paths else 0},{'usage':lambda p:Mock(f_blocks=1025,f_frsize=1024,f_bavail=512)}):
                with self.assertRaises(LimitError):check_volumes(paths,(1048576,)*3,**({'mount':mount,'device':device,'usage':usage,'layout':lambda p:None}|kwargs))
    def test_plain_directory_refused(self):
        with tempfile.TemporaryDirectory() as d:
            ps=[Path(d)/n for n in ('a','b','c')]
            for p in ps:p.mkdir()
            with self.assertRaises(LimitError):check_volumes(ps,(1024**3,)*3)
    def test_acl_and_audit(self):
        c=configparser.ConfigParser(interpolation=None,delimiters=('=',));c.read(ROOT/'vps/smb/smb.conf')
        self.assertIn('omega-model-reader',c['omega-models']['valid users'].split());self.assertEqual(c['omega-models']['read only'],'yes')
        for n in ('omega-compat','omega-secure'):self.assertNotIn('omega-model-reader',c[n]['valid users'].split())
        self.assertEqual(c['global']['vfs objects'],'full_audit');self.assertIn('%U',c['global']['full_audit:prefix']);self.assertEqual(c['global']['full_audit:syslog'],'false')
    def test_third_credential(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d);owner=(os.geteuid(),os.getegid());prepare_layout(p,owner,owner,owner)
            secrets=[(p/'smb-secrets'/(n+'_password')).read_bytes() for n in ('compat','secure','models')];self.assertEqual(len(set(secrets)),3)

    def test_persistent_volume_policy(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d);owner=(os.geteuid(),os.getegid());prepare_layout(p,owner,owner,owner)
            self.assertIsNone(volume_policy(p))
            self.assertEqual(volume_policy(p,'1,2,3',commit=True),'1,2,3')
            self.assertEqual(volume_policy(p),'1,2,3')
            with self.assertRaises(SmbError):volume_policy(p,'2,2,3')
            (p/'smb-secrets'/'volume-limits').chmod(0o644)
            with self.assertRaises(SmbError):volume_policy(p)

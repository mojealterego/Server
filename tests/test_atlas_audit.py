"""ATLAS chained provenance evidence tests."""
from pathlib import Path
import json
import tempfile
import threading
import unittest
from atlas.audit import append_record, verify_log, AuditError

class AuditTests(unittest.TestCase):
    def test_append_verify_and_tamper_detection(self):
        with tempfile.TemporaryDirectory() as d:
            r=Path(d);key=b'x'*32;log=r/'audit.jsonl';out=r/'photo.bin';out.write_bytes(b'photodata')
            append_record(log,key,{'stage':'image','status':'completed','model_sha256':'a'*64},output=out)
            append_record(log,key,{'stage':'upscale','status':'blocked'})
            self.assertEqual(verify_log(log,key)['records'],2)
            rows=log.read_text().splitlines()
            rows[0]=rows[0].replace('completed','forged')
            log.write_text('\n'.join(rows)+'\n')
            with self.assertRaises(AuditError):verify_log(log,key)
    def test_output_tampering_detected(self):
        with tempfile.TemporaryDirectory() as d:
            r=Path(d);key=b'k'*32;log=r/'audit';out=r/'output';out.write_bytes(b'ok')
            append_record(log,key,{'stage':'video','status':'completed'},output=out)
            out.write_bytes(b'evil')
            with self.assertRaises(AuditError):verify_log(log,key,verify_outputs=True)
    def test_concurrent_writers_form_one_chain(self):
        with tempfile.TemporaryDirectory() as d:
            r=Path(d);log=r/'audit';key=b'z'*32;errs=[]
            def worker(i):
                try:append_record(log,key,{'stage':f's{i}','status':'blocked'})
                except Exception as e:errs.append(str(e))
            ts=[threading.Thread(target=worker,args=(i,)) for i in range(12)]
            for t in ts:t.start()
            for t in ts:t.join()
            self.assertEqual(errs,[])
            self.assertEqual(verify_log(log,key)['records'],12)
    def test_no_key_or_raw_prompt_in_record(self):
        with tempfile.TemporaryDirectory() as d:
            r=Path(d);log=r/'audit';key=b's'*32
            append_record(log,key,{'stage':'text','status':'completed','prompt':'private prompt'})
            text=log.read_text()
            self.assertNotIn('private prompt',text)
            self.assertNotIn(key.hex(),text)
            self.assertIn('prompt_sha256',text)
    def test_truncation_detected_with_external_anchor(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);log=root/'log';key=b'k'*32
            append_record(log,key,{'stage':'one','status':'completed'})
            anchor=verify_log(log,key)['head']
            log.write_bytes(b'')
            with self.assertRaises(AuditError):verify_log(log,key,expected_head=anchor)

    def test_symlink_log_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            r=Path(d);target=r/'target';target.write_text('do not change');link=r/'link';link.symlink_to(target)
            with self.assertRaises(AuditError):append_record(link,b'a'*32,{'stage':'x','status':'blocked'})
            self.assertEqual(target.read_text(),'do not change')

if __name__=='__main__':unittest.main()

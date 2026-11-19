import tempfile
import unittest
from pathlib import Path
from atlas.runtime_gate import Telemetry, RuntimeGate, GateError

class RuntimeGateTests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup)
        self.root=Path(tmp.name)
        self.mem=self.root/'meminfo';self.mem.write_text('MemAvailable: 4194304 kB\n')
        self.temp=self.root/'temp';self.temp.write_text('38000\n')
        self.cg=self.root/'cg';self.cg.mkdir()
        (self.cg/'memory.max').write_text('2147483648\n')
        (self.cg/'memory.current').write_text('536870912\n')
        self.probe=Telemetry(self.temp,self.root,meminfo=self.mem,cgroup=self.cg)
        self.node={'id':'s24','ram_available_mb':1500,'ram_headroom_mb':256,'disk_free_bytes':10000,'thermal_c':38,'capabilities':['llama'],'models':['qwen'],'trust':'local','priority':1}
        self.task={'id':'a','engine':'llama','models':['qwen'],'ram_mb':512,'output_bytes':1}
        self.now=100.0
        self.gate=RuntimeGate(self.probe,self.node,self.task,deadline=120,clock=lambda:self.now)
    def test_measure_cgroup_and_temperature(self):
        snap=self.probe.sample();self.assertEqual(snap['ram_available_mb'],1536);self.assertEqual(snap['thermal_c'],38)
        self.assertGreater(snap['disk_free_bytes'],0)
    def test_ram_guard_before_launch(self):
        (self.cg/'memory.current').write_text(str(1800*1024**2))
        with self.assertRaisesRegex(GateError,'RAM'):self.gate.check(starting=True)
    def test_running_guard_reserve_not_double_counted(self):
        self.gate.check(starting=True)
        (self.cg/'memory.current').write_text(str(1700*1024**2))
        self.gate.check()
        (self.cg/'memory.current').write_text(str(1900*1024**2))
        with self.assertRaisesRegex(GateError,'RAM'):self.gate.check()
    def test_temperature_and_missing_sensor(self):
        self.temp.write_text('43000\n')
        with self.assertRaisesRegex(GateError,'THERMAL'):self.gate.check(starting=True)
        self.temp.unlink()
        with self.assertRaises(GateError):self.gate.check()
    def test_expired_attestation(self):
        self.now=120
        with self.assertRaisesRegex(GateError,'EXPIRED'):self.gate.check(starting=True)
    def test_unknown_or_invalid_cgroup_fails(self):
        (self.cg/'memory.current').write_text('-1\n')
        with self.assertRaises(GateError):self.probe.sample()
    def test_unlimited_cgroup(self):
        (self.cg/'memory.max').write_text('max\n');self.assertEqual(self.probe.sample()['ram_available_mb'],4096)
    def test_task_not_authorized(self):
        with self.assertRaises(GateError):RuntimeGate(self.probe,self.node,{**self.task,'models':['other']},deadline=120)
    def test_disk_budget(self):
        with self.assertRaises(GateError):RuntimeGate(self.probe,self.node,{**self.task,'output_bytes':10001},deadline=120)
    def test_invalid_telemetry_is_fail_closed(self):
        self.mem.write_text('MemAvailable: 415 bytes\n')
        with self.assertRaises(GateError): self.probe.sample()
    def test_signed_gate_replay_and_identity(self):
        import subprocess,time
        from tools.capctl import sign
        from atlas.runtime_gate import admitted_gate
        key=self.root/'key.pem'
        subprocess.run(['openssl','genpkey','-algorithm','ED25519','-out',str(key)],check=True);key.chmod(0o600)
        env=sign({k:v for k,v in self.node.items() if k not in ('trust','priority')},key)
        policy={'s24':{'public_key':env['public_key'],'trust':'local','priority':1,'max_ram_mb':2000,'min_headroom_mb':256,'max_disk_bytes':100000,'capabilities':['llama'],'models':['qwen']}}
        with self.assertRaises(GateError):admitted_gate(self.probe,env,policy,self.root/'db',self.task,{**self.node,'id':'other'})
        gate=admitted_gate(self.probe,env,policy,self.root/'db',self.task,self.node)
        gate.check(starting=True)
        with self.assertRaises(GateError):admitted_gate(self.probe,env,policy,self.root/'db',self.task,self.node)
    def test_collect_and_sign(self):
        import subprocess
        from atlas.runtime_gate import collect_signed
        from tools.capctl import public
        key=self.root/'key.pem'
        subprocess.run(['openssl','genpkey','-algorithm','ED25519','-out',str(key)],check=True);key.chmod(0o600)
        template={k:self.node[k] for k in ('id','capabilities','models','ram_headroom_mb')}
        env=collect_signed(self.probe,template,key)
        self.assertEqual(env['node']['ram_available_mb'],1536)
        self.assertEqual(env['node']['thermal_c'],38)
        public(env['public_key'])
        with self.assertRaises(GateError):collect_signed(self.probe,{**template,'thermal_c':20},key)

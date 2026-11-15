#!/usr/bin/env python3
"""Run real offline host tests; never invent Android/GPU/Docker results."""
from __future__ import annotations
from datetime import datetime,timezone
import io
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import unittest

ROOT=Path(__file__).resolve().parents[1]
# unittest discovery from tools/verify.py otherwise omits project root from sys.path.
sys.path.insert(0, str(ROOT))
REPORTS=ROOT/'reports'

def command_test(cmd:list[str]):
    try:
        cp=subprocess.run(cmd,cwd=ROOT,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                          text=True,timeout=60,check=False)
        return {'status':'PASS' if cp.returncode==0 else 'FAIL', 'exit_code':cp.returncode,
                'stderr':cp.stderr[-3000:]}
    except (OSError,subprocess.TimeoutExpired) as exc:
        return {'status':'FAIL','error':str(exc)}

def main():
    REPORTS.mkdir(exist_ok=True)
    tests=unittest.defaultTestLoader.discover(str(ROOT/'tests'),pattern='test_*.py')
    stream=io.StringIO()
    runner=unittest.TextTestRunner(stream=stream,verbosity=2)
    result=runner.run(tests)
    (REPORTS/'unittest.txt').write_text(stream.getvalue(),encoding='utf-8')
    shell_files=[*ROOT.glob('cloud/*.sh'),*ROOT.glob('termux/*.sh'),*ROOT.glob('vps/*.sh')]
    shell_files += [*ROOT.glob('vps/*/entrypoint.sh')]
    shells=[]
    for p in sorted(shell_files):
        runner_cmd=['sh' if p.name=='entrypoint.sh' else 'bash','-n',str(p)]
        check=command_test(runner_cmd)
        shells.append({'path':p.relative_to(ROOT).as_posix(),**check})
    compile_result=command_test([sys.executable,'-m','compileall','-q','termux','vps/media_worker.py','tools','atlas'])
    docker_config=command_test(['docker','compose','-f','vps/compose.yaml','config']) if shutil.which('docker') else {'status':'NOT_RUN','reason':'Docker not installed in this runner'}
    synthetic_cmd = command_test([sys.executable, 'tools/phasebench.py', '--cases', '200', '--seed', '20261115'])
    try:
        synthetic = json.loads(subprocess.run([sys.executable, 'tools/phasebench.py', '--cases', '200', '--seed', '20261115'],
                         cwd=ROOT, capture_output=True, text=True, timeout=60, check=True).stdout)
        (REPORTS/'phaseshift_benchmark.json').write_text(json.dumps(synthetic,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
        benchmark_ok = synthetic['verified_certificates'] == synthetic['cases'] == 200
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as exc:
        synthetic = {'status':'FAIL','error':str(exc)}
        benchmark_ok = False
    ok=result.wasSuccessful() and all(x['status']=='PASS' for x in shells) and compile_result['status']=='PASS' and docker_config['status']!='FAIL' and benchmark_ok and synthetic_cmd['status']=='PASS'
    report={
        'schema':'omega.verification.v4.1','component':'OMEGA-X v4.1.0 PHASESHIFT + ATLAS + CAS',
        'timestamp_utc':datetime.now(timezone.utc).isoformat(),
        'runner':{'system':platform.system(),'machine':platform.machine(),'python':platform.python_version()},
        'local':{'status':'PASS' if ok else 'FAIL','unittest':{'executed':result.testsRun,
                  'failures':len(result.failures),'errors':len(result.errors),
                  'skipped':len(result.skipped)},
                 'shell_syntax':shells,'python_compile':compile_result, 'synthetic_benchmark':synthetic,
                 'docker_compose_config':docker_config},
        'external_evidence':{'S24_Ultra_device':'NOT_RUN','VPS_Docker_runtime':'NOT_RUN',
                             'GPU_Adreno_OpenCL':'NOT_RUN','Hexagon_NPU':'NOT_RUN',
                             'Wan_LTX_actual_inference':'NOT_RUN','cloud_real_transfer':'NOT_RUN'},
        'test_limits':'PHASESHIFT certifies only declared resources and restart scenarios. SQLite lease is single-host only. Synthetic benchmark is not GPU/energy/latency evidence. Rclone and sd-cli tests use controlled subprocess doubles. No real S24/VPS/GPU/cloud E2E.'
    }
    (REPORTS/'verification.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    (REPORTS/'green-mobile.txt').write_text('STATUS=NOT_RUN_ON_S24_ULTRA\nNO_REAL_MOBILE_E2E_EVIDENCE\nLOCAL_SIMULATIONS_IN=verification.json\n',encoding='utf-8')
    (REPORTS/'verification.txt').write_text(
        f"LOCAL_UNIT_TESTS={result.testsRun}\nLOCAL_FAILURES={len(result.failures)+len(result.errors)}\n"
        f"LOCAL_STATUS={'PASS' if ok else 'FAIL'}\nMOBILE_STATUS=NOT_RUN\nVPS_RUNTIME_STATUS=NOT_RUN\n",encoding='utf-8')
    (REPORTS/'red.txt').write_text('LOCAL_FAILURES=%d\n' % (len(result.failures)+len(result.errors)),encoding='utf-8')
    print(f"OMEGA-X v4.1 host verification: {'PASS' if ok else 'FAIL'}; tests={result.testsRun}; mobile=NOT_RUN; Docker runtime=NOT_RUN")
    return 0 if ok else 1

if __name__=='__main__':sys.exit(main())

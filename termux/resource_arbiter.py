#!/usr/bin/env python3
"""OMEGA-X bounded local-resource admission controller.

The thermal values are *policy thresholds*, not certified device safety limits.
Missing sensor data always blocks local video, and an active thermal trip
is never cleared without a confirmed low temperature measurement.
"""
from __future__ import annotations
from dataclasses import dataclass
import json
import os
from pathlib import Path
import shutil
import subprocess
import threading
import time

LOCAL_TYPES=frozenset({'LLM','VIDEO_LOCAL','SYNC'})
KINDS=LOCAL_TYPES|{'VIDEO_OFFLOAD'}

@dataclass(frozen=True)
class Job:
    id: str
    kind: str
    required_ram_mb: int

    def __post_init__(self):
        if not self.id or len(self.id)>128 or not all(x.isalnum() or x in '-_' for x in self.id):
            raise ValueError('Invalid job identifier')
        if self.kind not in KINDS or not (0<=self.required_ram_mb<=65536):
            raise ValueError('Invalid job resource declaration')
        if self.kind=='VIDEO_OFFLOAD' and self.required_ram_mb!=0:
            raise ValueError('Offload RAM reservation must be zero')

@dataclass
class StaticProbe:
    mem_available_mb: int | None
    thermal_celsius: float | None
    def sample(self):
        return {'mem_available_mb':self.mem_available_mb,'thermal_celsius':self.thermal_celsius}

class AndroidProbe:
    """Best-effort, no-root probe with honest unknown values.

    Termux API battery temperature refers to the battery, not the SoC. Use
    only if OMEGA_THERMAL_SOURCE=battery and thresholds were calibrated to it.
    """
    def sample(self):
        memory=None
        try:
            for line in Path('/proc/meminfo').read_text().splitlines():
                if line.startswith('MemAvailable:'):
                    memory=int(line.split()[1])//1024
                    break
        except (OSError,IndexError,ValueError):
            pass
        temp=None
        if os.environ.get('OMEGA_THERMAL_SOURCE')=='battery' and shutil.which('termux-battery-status'):
            try:
                res=subprocess.run(['termux-battery-status'],capture_output=True,text=True,timeout=3,check=True)
                value=json.loads(res.stdout)['temperature']
                if isinstance(value,(float,int)) and 0<=value<=70:
                    temp=float(value)
            except (OSError,ValueError,KeyError,subprocess.SubprocessError):
                pass
        return {'mem_available_mb':memory,'thermal_celsius':temp}

class OmegaResourceArbiter:
    def __init__(self,probe=None,*,high_c=43.0,low_c=39.5,reserve_mb=1024):
        if not 0<=low_c<high_c<=90:
            raise ValueError('Invalid thermal hysteresis')
        self.probe=probe or AndroidProbe()
        self.high_c,self.low_c,self.reserve_mb=high_c,low_c,reserve_mb
        self._lock=threading.RLock()
        self._active:dict[str,Job]={}
        self._throttled=False

    def try_start(self,job:Job)->tuple[bool,str]:
        with self._lock:
            if job.id in self._active:
                return False,'DUPLICATE_JOB'
            if job.kind=='VIDEO_OFFLOAD':
                self._active[job.id]=job
                return True,'OFFLOAD_QUEUED'
            snap=self.probe.sample()
            temp=snap.get('thermal_celsius')
            if temp is not None:
                if temp>=self.high_c:self._throttled=True
                elif self._throttled and temp<=self.low_c:self._throttled=False
            if self._throttled:
                return False,'THERMAL_TRIPPED'
            if temp is None and job.kind=='VIDEO_LOCAL':
                return False,'THERMAL_UNKNOWN_VIDEO_REFUSED'
            if any(j.kind in LOCAL_TYPES for j in self._active.values()):
                return False,'LOCAL_RESOURCE_MUTEX'
            free=snap.get('mem_available_mb')
            if free is None:
                return False,'RAM_TELEMETRY_UNAVAILABLE'
            if free < job.required_ram_mb+self.reserve_mb:
                return False,'RAM_INSUFFICIENT'
            self._active[job.id]=job
            return True,'ADMITTED'

    def complete(self,job_id:str)->bool:
        with self._lock:
            return self._active.pop(job_id,None) is not None

    def status(self)->dict:
        with self._lock:
            return {'telemetry':self.probe.sample(), 'thermal_tripped':self._throttled,
                    'active_jobs':[{'id':v.id,'kind':v.kind,'required_ram_mb':v.required_ram_mb}
                                   for v in self._active.values()]}

if __name__=='__main__':
    print(json.dumps(OmegaResourceArbiter().status(),indent=2))

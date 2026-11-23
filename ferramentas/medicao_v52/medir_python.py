"""Latência das camadas Python da RSD-S v5.2 (referência pedagógica, não de produção)."""
import time, json, statistics, hashlib, random
import sys, os
from pathlib import Path
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "implementacao")); sys.path.insert(0, str(ROOT / "testes"))
import subprocess, tempfile
def compilar(flags, nome, destino):
    so = Path(destino) / f"lib_{nome}.so"
    subprocess.run(["gcc", *flags.split(), "-Wall", "-Wextra", "-Werror", "-shared", "-fPIC",
                    str(ROOT / "implementacao" / "c_core" / "rsd_s_v5_ct.c"), "-o", str(so)], check=True)
    return so
from rsd_s_v5_hardened import diffuse_rsd_s_v5, diffuse_rsd_s_v5_pre_sha, derive_keys_v5, expand_key_words_v5
from bandlimited_dual_key import BandlimitedDualKeyEngine
os.sched_setaffinity(0,{int(os.environ.get('CPU_FIXA','2'))}) if hasattr(os,'sched_setaffinity') else None
s=bytes(range(32)); x=1; y=2
def med(fn, n, reps=9):
    fn(); v=[]
    for _ in range(reps):
        t=time.perf_counter()
        for _ in range(n): fn()
        v.append((time.perf_counter()-t)/n*1e3)
    v.sort(); return dict(ms_mediana=round(statistics.median(v),3), ms_min=round(v[0],3), ms_max=round(v[-1],3))
t=time.perf_counter(); eng=BandlimitedDualKeyEngine(); t_init=(time.perf_counter()-t)*1e3
out=dict(python=sys.version.split()[0])
import numpy; out['numpy']=numpy.__version__
out['init_engine_ms']=round(t_init,1)
out['pre_sha_8r']=med(lambda: diffuse_rsd_s_v5_pre_sha(x,y,s,1,rounds=8),3)
out['api_32B_8r']=med(lambda: diffuse_rsd_s_v5(x,y,s,1,rounds=8,output_bytes=32),3)
out['api_64B_8r']=med(lambda: diffuse_rsd_s_v5(x,y,s,1,rounds=8,output_bytes=64),3)
out['dual_key_refactor_8r']=med(lambda: eng.refactor_public_output(x,y,s,1),3)
out['derive_keys_8r_us']=round(med(lambda: derive_keys_v5(s,1,8),2000)['ms_mediana']*1e3,2)
print(json.dumps(out,indent=1))

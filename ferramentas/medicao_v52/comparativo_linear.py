"""Linear/Walsh com máscaras genéricas e o mesmo N para RSD-S v5.2 e AES (comparação simétrica)."""
import json
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
import numpy as np
from r5_metrics_harness import load_rsd_c_core, RSDKeyedV5, attack_linear_walsh
from test_r5_m2_aes_prp_comparison import load_aes_c_core, AESKeyedPRP
key=bytes(range(32)); rl=load_rsd_c_core(); al=load_aes_c_core()
out={}
N=524_288
for r in (1,2,3):
    rng=np.random.default_rng(777+r)
    p=RSDKeyedV5(rl,key,n_sess=1,rounds=r,schedule_rounds=8,with_sha=False)
    o=attack_linear_walsh(p,n_samples=N,n_masks=64,rng=rng)
    out[f'RSD-S v5.2 {r}R (generico)']=(o['max_z'],o['detected'])
    for nm,k,ro in (('AES-128',key[:16],r),('AES-256',key,r)):
        pa=AESKeyedPRP(al,k,rounds=ro,final_no_mixcolumns=True)
        oa=attack_linear_walsh(pa,n_samples=N,n_masks=64,rng=np.random.default_rng(900+r))
        out[f'{nm} {r}R (generico)']=(oa['max_z'],oa['detected'])
for k,v in out.items(): print(k.ljust(34),'max_z=',v[0],' detectado=',v[1])

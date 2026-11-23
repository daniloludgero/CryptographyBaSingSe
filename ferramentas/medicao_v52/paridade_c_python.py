"""Paridade bit a bit C99 x Python (vetores v5.2 + entradas aleatórias) e detecção de falha injetada em cada rodada."""
import json, random
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
from rsd_s_v5_hardened import diffuse_rsd_s_v5_pre_sha, run_c_core_pre_sha, P_CURVE25519, serialize_state_v5
kat=json.load(open(ROOT/'testes'/'vetores_v52.json'))['vectors']
rng=random.Random(20261123)
casos=[(int(v['x']),int(v['y']),bytes.fromhex(v['s_hex']),int(v['n_sess']),int(v['rounds']),v['pre_sha_hex']) for v in kat]
for _ in range(120):
    casos.append((rng.randrange(P_CURVE25519),rng.randrange(P_CURVE25519),rng.randbytes(32),rng.randrange(2**64),rng.choice([1,2,4,8]),None))
py=[]
for x,y,s,n,r,h in casos:
    st=diffuse_rsd_s_v5_pre_sha(x,y,s,n,rounds=r); py.append(st)
    if h: assert serialize_state_v5(st).hex()==h
res={}
_tmp=tempfile.mkdtemp(prefix='rsd_par_')
CONFIGS={'O3_avx2':'-O3 -mavx2','O2_escalar':'-O2 -mno-avx2','O0':'-O0'}
for n,fl in CONFIGS.items():
    lib=str(compilar(fl,n,_tmp)); ok=0
    for (x,y,s,nn,r,h),st in zip(casos,py):
        rc,out=run_c_core_pre_sha(lib,x,y,s,nn,rounds=r)
        assert rc==0 and np.array_equal(out,st),(n,r); ok+=1
    det=0; tot=0
    for r in range(1,9):
        for w in (0,17,31):
            rc,out=run_c_core_pre_sha(lib,1,2,bytes(range(32)),1,rounds=8,inject_fault_word=w,inject_fault_mask=0x0001,inject_fault_round=r)
            tot+=1; det+= (rc==-2 and not out.any())
    res[n]=dict(paridade=f'{ok}/{len(casos)}',falhas_detectadas_zeram_saida=f'{det}/{tot}')
print(json.dumps(res,indent=1))

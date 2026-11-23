"""Ataque Square/Integral de recuperação da subchave equivalente da 3ª rodada (saída pré-SHA), RSD-S v5.2.
Modelo: chave desconhecida, textos claros escolhidos (estado de entrada), saída pré-SHA de 64 B observável.
Alvo: k*_3 = rc_3·1 XOR M^{-1}·rk_3  (32 palavras de 16 bits = 512 bits)."""
import time, ctypes, json
import numpy as np
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
import rsd_s_v5_hardened as H
from mds_real import gf_mult, gf_add, gf_inv
LIB=str(compilar('-O3 -mavx2','sq3',tempfile.mkdtemp(prefix='rsd_sq_'))); ROUNDS=3; W=32
key=bytes.fromhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"); NS=1
keys=H.derive_keys_v5(key,NS,ROUNDS)
rk=np.concatenate([H.expand_key_words_v5(k,W) for k in keys]).astype(np.uint16)
rc=np.array([H.round_constant_v5(key,NS,r,ROUNDS) for r in range(1,ROUNDS+1)],dtype=np.uint16)
lib=ctypes.CDLL(LIB); P=ctypes.POINTER(ctypes.c_uint16)
lib.rsd_s_v5_core_ct.argtypes=[P,P,P,ctypes.c_int,ctypes.c_int,ctypes.c_uint16,P]
def core(st):
    out=np.zeros(W,dtype=np.uint16)
    r=lib.rsd_s_v5_core_ct(st.ctypes.data_as(P),rk.ctypes.data_as(P),rc.ctypes.data_as(P),ROUNDS,-1,0,out.ctypes.data_as(P)); assert r==0; return out
# --- M^{-1} em GF(2^16)
M=[[int(v) for v in row] for row in H.M_CAUCHY_32]
A=[M[i][:]+[1 if i==j else 0 for j in range(W)] for i in range(W)]
for c in range(W):
    p=next(r for r in range(c,W) if A[r][c]); A[c],A[p]=A[p],A[c]
    iv=gf_inv(A[c][c]); A[c]=[gf_mult(iv,v) for v in A[c]]
    for r in range(W):
        if r!=c and A[r][c]:
            f=A[r][c]; A[r]=[gf_add(a,gf_mult(f,b)) for a,b in zip(A[r],A[c])]
Minv=np.array([row[W:] for row in A],dtype=np.int64)
# verificação M*Minv=I
for i in (0,5,31):
    for j in (0,7,31):
        acc=0
        for t in range(W): acc=gf_add(acc,gf_mult(int(M[i][t]),int(Minv[t][j])))
        assert acc==(1 if i==j else 0)
# tabela S inversa
t0=time.time(); S=np.array([H.sbox_v5_eval(u) for u in range(65536)],dtype=np.int64); Sinv=np.zeros(65536,dtype=np.int64); Sinv[S]=np.arange(65536); assert len(set(S.tolist()))==65536
t_tab=time.time()-t0
def mat_gf(Mat,vec_batch):  # vec_batch: (n,32) -> (n,32), GF(2^16) matriz*vetor via tabelas log
    EXP=np.zeros(131072,dtype=np.int64); LOG=np.zeros(65536,dtype=np.int64); x=1
    for i in range(65535):
        EXP[i]=x; LOG[x]=i; x=gf_mult(x,2)
    EXP[65535:131070]=EXP[:65535]
    out=np.zeros_like(vec_batch)
    for i in range(W):
        acc=np.zeros(len(vec_batch),dtype=np.int64)
        for j in range(W):
            m=int(Mat[i][j]); v=vec_batch[:,j]
            if m==0: continue
            prod=np.where(v==0,0,EXP[(LOG[v]+LOG[m])%65535]); acc^=prod
        out[:,i]=acc
    return out
def wht(a):
    a=a.copy(); n=len(a); h=1
    while h<n:
        a=a.reshape(-1,2,h); x=a[:,0,:]+a[:,1,:]; y=a[:,0,:]-a[:,1,:]; a=np.stack([x,y],axis=1).reshape(-1); h*=2
    return a
SINV_BITS=[ (Sinv>>b)&1 for b in range(16)]; SINV_WHT=[wht(sb.astype(np.int64)) for sb in SINV_BITS]
def survivors(Zj):
    c=np.bincount(Zj,minlength=65536)&1
    ch=wht(c.astype(np.int64)); bad=np.zeros(65536,dtype=bool)
    for b in range(16):
        conv=wht(ch*SINV_WHT[b])//65536   # XOR-correlação inteira
        # F_b(k)=sum_z c[z]*Sinv_b[z^k] mod 2 ; correlação: (c * Sinv_b)(k)
        bad|=(conv&1)==1
    return set(np.nonzero(~bad)[0].tolist())
t0=time.time(); rng=np.random.default_rng(31337); sets=[]
for s in range(2):
    base=rng.integers(0,65536,size=W,dtype=np.int64); outs=np.zeros((65536,W),dtype=np.int64)
    for x in range(65536):
        st=base.astype(np.uint16).copy(); st[0]=x; outs[x]=core(st)
    sets.append(mat_gf(Minv,outs))
t_q=time.time()-t0
# subchave verdadeira
rk3=rk[3*W:4*W].astype(np.int64)[None,:]; Mrk=mat_gf(Minv,rk3)[0]
truth=np.array([int(Mrk[j])^int(rc[2]) for j in range(W)],dtype=np.int64)
t0=time.time(); rec=[]; fp=[]
for j in range(W):
    s1=survivors(sets[0][:,j]); s2=survivors(sets[1][:,j]); inter=s1&s2
    rec.append(sorted(inter)); fp.append((len(s1),len(s2),len(inter)))
t_a=time.time()-t0
ok=sum(1 for j in range(W) if rec[j]==[int(truth[j])])
print(json.dumps(dict(rounds=ROUNDS,textos_claros_escolhidos=2*65536,palavras_recuperadas_exatamente=f"{ok}/{W}",bits_recuperados=16*ok,
  candidatos_por_palavra_set1_set2_inter=fp[:6],tempo_consultas_s=round(t_q,1),tempo_analise_s=round(t_a,1),tempo_tabela_sbox_s=round(t_tab,1),tempo_total_s=round(t_q+t_a,1)),indent=1))

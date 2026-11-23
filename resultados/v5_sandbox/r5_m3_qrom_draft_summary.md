# Resumo Executivo — Rascunho Formal de Redução QROM (M_R5_3)

**Artefato Principal:** [`REDUCAO_QROM_RASCUNHO_V5_1.md`](../../especificacao/REDUCAO_QROM_RASCUNHO_V5_1.md)  
**Escopo:** `RSD-S v5.1` ([`rsd_s_v5_hardened.py`](../../implementacao/rsd_s_v5_hardened.py)) e `Dupla-Chave SIV` ([`bandlimited_dual_key.py`](../../implementacao/bandlimited_dual_key.py))

---

## 1. Enquadramento Estrito sob `RESTRICOES_DE_PROJETO.md`

- **Não baseado nos problemas de Shor:** A construção é uma primitiva simétrica de difusão/compressão chaveada e projeção modular; não utiliza fatoração, logaritmo discreto nem periodicidade circular.
- **Status Condicional:** O documento é um **rascunho de redução condicional** para revisão externa. **Não certifica** segurança pós-quântica, **não afirma** "superar Shor" e **não atesta** prontidão para produção.
- **Limites Estruturais Registrados:**
  - Entrada $\mathcal{D} = \mathbb{F}_p \times \mathbb{F}_p$ ($p = 2^{255}-19$) limita a entropia de entrada a $\approx 510$ bits ativos no estado de $512$ bits de $\text{SPN}_8$.
  - Primitiva determinística (sem IV aleatório por chamada): IND-CPA / qIND-CPA exige uso como PRF em modo com *nonce* único; o SIV protege apenas contra reuso de $n_{\text{sess}}$ entre entradas distintas $(x,y) \neq (x',y')$ em `Dupla-Chave`.

---

## 2. Separação Q1 vs. Q2 e Limites Genéricos

| Modelo / Noção | Regime de Consultas | Resultado / Limite |
| :--- | :--- | :--- |
| **Q1-qPRF** | $q_H$ quânticas ao QRO + $q_C$ clássicas a $F_s$ ($q_S \le q_C$ sessões) | Switching Lemma clássico + Compressed Oracle ($O(q_H \sqrt{q_C/2^{512}})$) |
| **Q2-Sessão-Clássica (Principal)** | $q_H$ quânticas ao QRO + $q_Q$ em superposição sobre $(x,y)$, $q_S$ sessões clássicas | Q1-qPRF ($17 q_S$) + $\text{SPN}_8$ qPRP + Quantum Switching ($O(q_Q^3/2^{512})$) + Compressed Oracle |
| **Q2-Superposição-Completa** | $q_H$ quânticas ao QRO + $q_Q$ em superposição sobre $(x,y,n_{\text{sess}})$ | Q2-qPRF ($17 q_Q$) + $\text{SPN}_8$ tqPRP + Switching Indexado ($O(q_Q^3/2^{512})$) + Compressed Oracle |
| **qMAC (Q1 / Q2 PO-EUF)** | EUF-CMA (Q1) / Plus-One Unforgeability (Q2, Boneh–Zhandry 2013) | $\mathbf{Adv}^{\text{qMAC}} \le \mathbf{Adv}^{\text{qPRF}} + O(q/|\mathcal{Y}|)$ |
| **qIND-CPA** ($\|\Pr[\text{acerto}]-1/2\|$) | Primitiva isolada vs. Modo Nonce Único | Isolada: $\mathbf{Adv} = 1/2$ (determinística). Com *nonce* único: $\le \mathbf{Adv}^{\text{qPRF}}$ |
| **Colisão (BHT) / Pré-imagem (Grover)** | Genérico sobre $\mathcal{Y}_{256}$ vs. $\mathcal{Y}_{512}$ | Colisão: $O(2^{85{,}3})$ ($256$b) vs. $O(2^{170{,}7})$ ($512$b). Pré-imagem $512$b: $\Omega(2^{256})$ (QRO, chave fixa); busca de $s$: $\Omega(2^{128})$ |

---

## 3. Desigualdades Principais (Teoremas 1 e 2)

- **Teorema 1 (`RSD-S v5.1`):**
  1. **Q1:**
     $$\mathbf{Adv}^{\text{Q1-qPRF}}_{\text{RSD-S v5.1}}(\mathcal{A}) \le \mathbf{Adv}^{\text{Q1-qPRF}}_{\text{HMAC-SHA256}}(17 q_S, t_1) + q_S \cdot \mathbf{Adv}^{\text{Q1-qPRP}}_{\text{SPN}_8}(q_C, t_2) + \frac{q_C(q_C-1)}{2^{513}} + O\!\left(q_H \sqrt{\frac{q_C}{2^{512}}}\right),$$
  2. **Q2-Sessão-Clássica:**
     $$\mathbf{Adv}^{\text{Q2-SessCla-qPRF}}_{\text{RSD-S v5.1}}(\mathcal{A}) \le \mathbf{Adv}^{\text{Q1-qPRF}}_{\text{HMAC-SHA256}}(17 q_S, t_1) + q_S \cdot \mathbf{Adv}^{\text{Q2-qPRP}}_{\text{SPN}_8}(q_Q, t_2) + O\!\left(\frac{q_Q^3}{2^{512}}\right) + O\!\left(q_H \sqrt{\frac{q_Q}{2^{512}}}\right),$$
  3. **Q2-Superposição-Completa:**
     $$\mathbf{Adv}^{\text{Q2-Full-qPRF}}_{\text{RSD-S v5.1}}(\mathcal{A}) \le \mathbf{Adv}^{\text{Q2-qPRF}}_{\text{HMAC-SHA256}}(17 q_Q, t_1) + \mathbf{Adv}^{\text{Q2-tqPRP}}_{\text{SPN}_8}(q_Q, t_2) + O\!\left(\frac{q_Q^3}{2^{512}}\right) + O\!\left(q_H \sqrt{\frac{q_Q}{2^{512}}}\right).$$

- **Teorema 2 (`Dupla-Chave SIV` + Folding 64B):**
  1. **Q1:**
     $$\mathbf{Adv}^{\text{Q1-qPRF}}_{\text{DualKey-SIV}}(\mathcal{A}) \le \mathbf{Adv}^{\text{Q1-qPRF}}_{\text{HMAC-SHA256}}(17 q_S + q_C, t_1) + q_S \cdot \mathbf{Adv}^{\text{Q1-qPRP}}_{\text{SPN}_8}(q_C, t_2) + \frac{q_C(q_C-1)}{2^{512}} + O\!\left(q_H \sqrt{\frac{q_C}{2^{256}}}\right) + O\!\left(q_H \sqrt{\frac{q_C}{2^{512}}}\right),$$
  2. **Q2-Sessão-Clássica:**
     $$\mathbf{Adv}^{\text{Q2-SessCla-qPRF}}_{\text{DualKey-SIV}}(\mathcal{A}) \le \mathbf{Adv}^{\text{Q1-qPRF}}_{\text{HMAC-SHA256}}(17 q_S, t_1') + \mathbf{Adv}^{\text{Q2-qPRF}}_{\text{HMAC-SHA256}}(q_Q, t_1'') + q_S \cdot \mathbf{Adv}^{\text{Q2-qPRP}}_{\text{SPN}_8}(q_Q, t_2) + O\!\left(\frac{q_Q^3}{2^{512}}\right) + O\!\left(q_H \sqrt{\frac{q_Q}{2^{256}}}\right) + O\!\left(q_H \sqrt{\frac{q_Q}{2^{512}}}\right),$$
  3. **Q2-Superposição-Completa:**
     $$\mathbf{Adv}^{\text{Q2-Full-qPRF}}_{\text{DualKey-SIV}}(\mathcal{A}) \le \mathbf{Adv}^{\text{Q2-qPRF}}_{\text{HMAC-SHA256}}(18 q_Q, t_1) + \mathbf{Adv}^{\text{Q2-tqPRP}}_{\text{SPN}_8}(q_Q, t_2) + O\!\left(\frac{q_Q^3}{2^{512}}\right) + O\!\left(q_H \sqrt{\frac{q_Q}{2^{256}}}\right) + O\!\left(q_H \sqrt{\frac{q_Q}{2^{512}}}\right),$$
  com **independência aditiva** de $Y_{\text{pub}} = (B_{K_j} R_1 + u) \bmod 65537$ (mesmo sob reuso de $n_{\text{sess}}$), termo explícito de colisão de $R_1$ ($+\frac{q_C(q_C-1)}{2^{513}}$ em Q1; $+O(q_Q^3/2^{512})$ em Q2) e **distância estatística $\text{TVD} = 0$** do *folding* 64B pela Lei da Probabilidade Total ($\frac{1}{65537} + \frac{1}{65537 \cdot 65536} = \frac{1}{65536}$).

---

## 4. Tabela Resumida: Reduzido Formalmente vs. Assumido

| Reduzido Formalmente (Condicional) | Assumido / Não Provado (Revisão Externa) |
| :--- | :--- |
| Composição QRO $\text{SPN}_8 \to H_{32}/H_{64}$ (Switching Lemma + Compressed Oracle de Zhandry) | $\text{SPN}_8$ ($8$ rodadas, **incluindo** `expand_key_words_v5`) é uma **qPRP** (e **tqPRP** em Q2-Superposição-Completa) sob $(K_r, rc_r)$ uniformes |
| Mascaramento aditivo SIV em $\mathbb{Z}_{65537}^{32}$ sob reuso de $n_{\text{sess}}$ | `HMAC-SHA256` é **Q1-qPRF** (e **Q2-qPRF** em Q2-Superposição-Completa / SIV-Q2) |
| Uniformidade exata do *folding* 64B ($\text{TVD} = 0$) | `SHA-256` e `SHAKE256` são QROs independentes (indiferenciabilidade) |
| Redução $\text{qPRF} \implies \text{qMAC}$ (Q1 e Q2 PO-EUF) | Ausência de subgrupo oculto/periodicidade explorável em $\text{SPN}_8$ / $B_{K_j}$ |
| — | Segurança *constant-time* fora do modelo QROM (ramo `== 65536` em Python) |

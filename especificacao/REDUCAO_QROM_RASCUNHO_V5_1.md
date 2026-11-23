# Rascunho Formal de Redução QROM — RSD-S v5.1 e Dupla-Chave SIV (histórico, pendente de atualização para a v5.2)

> **Rascunho condicional, escrito para a linha v5.1 e não atualizado para a v5.2.**
> Este documento **não certifica segurança pós-quântica** e não foi revisado por terceiros. Antes de usá-lo como base de qualquer afirmação, observe as divergências conhecidas em relação à v5.2:
>
> | Ponto | No rascunho | Na v5.2 (ver [`ESPECIFICACAO_V5_2.md`](ESPECIFICACAO_V5_2.md)) |
> | :--- | :--- | :--- |
> | Expansão de chave | `K_r ‖ HMAC(K_r, "EXP\|" ‖ 1)` (1º bloco = `K_r` literal) | HMAC em **todos** os blocos (`block_idx = 0, 1`) |
> | Anti-DFA | rodada final duplicada | dois fluxos A/B por `R1..R`, comparados ao final |
> | *Folding* do `Z_65537` | `SHA-256` com rótulo `FOLD16`, uma chamada por coordenada | um fluxo `SHAKE256` com rótulo `FOLD16\|V5.2\|`, seleção por máscara |
> | S-boxes ativas | texto dizia 132 em 4 rodadas | **66 em 4 rodadas**; 132 em 8 (correção já aplicada abaixo) |
>
> As seções 2.2, 2.3 e 5 e os jogos híbridos `G_1`, `G_2` e `H_1`–`H_4` **precisam ser refeitos** para a v5.2 antes de qualquer revisão externa.


> [!CAUTION]
> **Aviso de Status e Escopo (Conformidade com `RESTRICOES_DE_PROJETO.md`):**
> Este documento constitui um **rascunho formal de redução condicional no Modelo de Oráculo Aleatório Quântico (QROM)** destinado à **revisão criptográfica externa independente**. Ele **NÃO certifica segurança pós-quântica**, **NÃO prova que a construção "supera Shor"** e **NÃO atesta prontidão para produção**. Todas as conclusões dependem explicitamente das hipóteses não-provadas listadas na Seção 6.

---

## 1. Conformidade com `RESTRICOES_DE_PROJETO.md` e Premissas de Projeto

Em estrita observância às regras estabelecidas em [`RESTRICOES_DE_PROJETO.md`](RESTRICOES_DE_PROJETO.md), registram-se os seguintes pontos fundamentais antes de qualquer análise formal:

1. **Ausência de Base nos Problemas Atacados por Shor:** A família **RSD-S v5.1** ([`rsd_s_v5_hardened.py`](../implementacao/rsd_s_v5_hardened.py)) e o módulo operando final **Dupla-Chave SIV** ([`bandlimited_dual_key.py`](../implementacao/bandlimited_dual_key.py)) constituem primitivas simétricas de difusão/compressão chaveada e projeção modular. Elas **não se baseiam** em fatoração de inteiros, problema do logaritmo discreto (DLP/ECDLP) ou periodicidade geométrica circular. Consequentemente, o algoritmo de Shor não se aplica diretamente como ataque algébrico genérico contra a primitiva isolada. Contudo, conforme alertado em `RESTRICOES_DE_PROJETO.md`, a ausência de representação circular não equivale, por si só, a prova incondicional de ausência de subgrupos ocultos ou periodicidades internas.
2. **Limite de Entropia de Entrada ($\approx 510$ bits ativos):** As entradas de dados $(x, y)$ pertencem a $\mathbb{F}_p \times \mathbb{F}_p$ com $p = 2^{255} - 19$. Cada coordenada ocupa $255$ bits efetivos (codificada em $16$ palavras de $16$ bits `uint16`, onde o bit mais significativo da palavra mais alta $x_{15}, y_{15}$ assume valor nulo em quase todo o domínio, exceto na pequena faixa de $2^{255}-19$ — na prática $2^{255}-19 < 2^{255}$, logo o bit 15 da palavra 15 é **sempre** $0$). Portanto, o espaço de entrada $\mathcal{D} = \mathbb{F}_p \times \mathbb{F}_p$ possui cardinalidade $|\mathcal{D}| = p^2 \approx 2^{510}$, ligeiramente inferior a $2^{512}$. A permutação interna $\text{SPN}_8$ opera sobre $\{0,1\}^{512}$, de modo que a entropia máxima injetada na entrada é limitada a $\log_2(p^2) \approx 510$ bits (antes do *key-whitening* inicial $rk_0 \in \{0,1\}^{512}$).
3. **Natureza Determinística da Primitiva:** Tanto `diffuse_rsd_s_v5` quanto `BandlimitedDualKeyEngine.refactor_public_output` são **funções determinísticas** de $(x, y, s, n_{\text{sess}})$. Não há sorteio de vetor de inicialização (IV) aleatório por chamada. Por definição, nenhuma função determinística satisfaz IND-CPA padrão quando usada diretamente para cifrar mensagens repetidas sem *nonce*/IV único. A segurança **IND-CPA / qIND-CPA** só é definida quando a primitiva é empregada como PRF em um modo com *nonce* único (ex.: mascaramento `c = m XOR F_s(nonce)` ou construção AEAD). O mecanismo **SIV (*Synthetic IV*)** da `Dupla-Chave` protege especificamente contra o **vazamento diferencial de $\Delta S_{\text{priv}}$ quando há reuso acidental de $n_{\text{sess}}$** entre entradas distintas $(x,y) \neq (x',y')$, preservando a pseudoaleatoriedade de $Y_{\text{pub}}$, mas mantendo o determinismo para entradas idênticas $(x,y,n_{\text{sess}})$.

---

## 2. Notação, Domínios e Arquitetura Formal

### 2.1 Espaços e Conjuntos
- **Espaço de Chaves Mestras:** $\mathcal{K} = \{0,1\}^{256}$ ($32$ bytes).
- **Espaço de Sessões / Nonces:** $\mathcal{N} = \{0, 1, \dots, 2^{64}-1\}$ (codificado em $8$ bytes *big-endian*, `uint64_be`).
- **Espaço de Entradas:** $\mathcal{D} = \mathbb{F}_p \times \mathbb{F}_p$, onde $p = 2^{255}-19$, com $|\mathcal{D}| = (2^{255}-19)^2 \approx 2^{510}$.
- **Espaço de Estado Interno:** $\mathcal{S} = (\mathbb{F}_{2^{16}})^{32} \cong \{0,1\}^{512}$, representado por $32$ palavras de $16$ bits em *big-endian* (`>u2`), onde $\mathbb{F}_{2^{16}} \cong \mathbb{F}_2[z]/(P(z))$ (polinômio irredutível `GF16_POLY` definido em `mds_real.py`).
- **Espaços de Saída da Primitiva Principal:** $\mathcal{Y}_{256} = \{0,1\}^{256}$ (`output_bytes=32`) e $\mathcal{Y}_{512} = \{0,1\}^{512}$ (`output_bytes=64`).
- **Espaço Algébrico da Dupla-Chave:** $\mathbb{Z}_q^{32}$ com primo de Fermat $q = 65537 = 2^{16} + 1$, e saída compacta sem *padding* $\mathcal{Y}_{\text{DK}} = \{0,1\}^{512}$ ($64$ bytes).

### 2.2 Escalonamento de Chaves (`derive_keys_v5`, `round_constant_v5`, `expand_key_words_v5`)
Para um número oficial de rodadas $R = 8$ e identificador de sessão $n_{\text{sess}} \in \mathcal{N}$, define-se a etiqueta de domínio:
$$\text{DOM\_V5}(R, n_{\text{sess}}) = \mathtt{"RSD\text{-}S\text{-}V5.1|CORE|"} \parallel \text{uint8}(R) \parallel \text{uint64\_be}(n_{\text{sess}}) \in \{0,1\}^{200},$$
onde $\mathtt{"RSD\text{-}S\text{-}V5.1|CORE|"}$ ocupa $16$ bytes, $\text{uint8}(R)$ ocupa $1$ byte e $\text{uint64\_be}(n_{\text{sess}})$ ocupa $8$ bytes ($25\text{ B} = 200\text{ bits}$).

Dado $s \in \mathcal{K}$, as chaves encadeadas $K_0, K_1, \dots, K_R \in \{0,1\}^{256}$ e as constantes de rodada $rc_1, \dots, rc_R \in \mathbb{F}_{2^{16}}$ são derivadas via `HMAC-SHA256`:
$$K_0 = \text{HMAC-SHA256}(s, \text{DOM\_V5} \parallel \mathtt{0x00}),$$
$$K_r = \text{HMAC-SHA256}(s, K_{r-1} \parallel \text{DOM\_V5} \parallel \text{uint8}(r)), \quad r \in \{1,\dots,R\},$$
$$rc_r = \text{uint16\_be}\big(\text{HMAC-SHA256}(s, \text{DOM\_V5} \parallel \mathtt{"RC"} \parallel \text{uint8}(r))[0:2]\big).$$

Cada chave $K_r$ é expandida para $32$ palavras de $16$ bits ($512$ bits) via `expand_key_words_v5`:
$$\text{material}_r = K_r \parallel \text{HMAC-SHA256}(K_r, \mathtt{"EXP|"} \parallel \text{uint32\_be}(1)), \qquad rk_r = \text{words}_{>u2}(\text{material}_r[0:64]) \in (\mathbb{F}_{2^{16}})^{32}.$$

### 2.3 Permutação $\text{SPN}_8$ (`diffuse_rsd_s_v5_pre_sha`)
A função `fragment_full_v5` mapeia $(x,y) \in \mathcal{D}$ injetivamente em $X_0 \in (\mathbb{F}_{2^{16}})^{32}$ ($16$ fatias *little-endian* de $16$ bits de $x$ seguidas de $16$ fatias de $y$). Após o *whitening* inicial $Z_0 = X_0 \oplus rk_0$, cada rodada $r = 1, \dots, 8$ aplica:
1. **Camada Não-Linear ($S_{\text{v5}}$ + $rc_r$):** Para cada palavra $i \in \{0,\dots,31\}$:
   $$U_{r,i} = S_{\text{v5}}(Z_{r-1,i}) \oplus rc_r, \quad \text{onde } S_{\text{v5}}(u) = A_{16}(u^{-1}) \oplus \mathtt{0x63A9},$$
   sendo $u^{-1} = u^{2^{16}-2}$ em $\mathbb{F}_{2^{16}}$ (com $0^{-1} := 0$, calculado por cadeia de adição de Itoh–Tsujii em tempo constante) e $A_{16}$ a transformação $\mathbb{F}_2$-linear invertível dada por $\bigoplus_{k \in \{0,1,2,3,4,5,7,11,13\}} \text{rotl}_{16}(v, k)$. A S-box $S_{\text{v5}}$ não possui pontos fixos nem pontos fixos opostos em $\mathbb{F}_{2^{16}}$.
2. **Camada de Difusão Linear ($M_{\text{v5.1}}$):** Multiplicação matricial sobre $\mathbb{F}_{2^{16}}$ pela matriz Cauchy MDS $32 \times 32$ permutada nas colunas:
   $$M_{\text{v5.1}}[:, j] = M_{\text{Cauchy}}[:, p(j)], \qquad p(j) = (5j + 1) \bmod 32.$$
   A matriz $M_{\text{v5.1}}$ preserva integralmente a propriedade MDS (*Branch Number* $\mathcal{B} = 33$), garantindo ao menos $66$ S-boxes ativas em $4$ rodadas ($132$ em $8$ rodadas), e elimina a involução escalar $M^2 = c \cdot I$ ($992/992$ entradas fora da diagonal de $M_{\text{v5.1}}^2$ são não-nulas).
3. **Adição de Subchave:** $Z_r = (M_{\text{v5.1}} \cdot U_r) \oplus rk_r$.

Na rodada $r = 8$, a implementação executa **redundância temporal Anti-DFA** (duas avaliações independentes de $\text{round}_8$, abortando e zerando os *buffers* se $\bigvee_{i=0}^{31} (\text{out}_{a,i} \oplus \text{out}_{b,i}) \neq 0$). Em ausência de falhas físicas, a saída pré-hash é $S_{\text{priv}} = Z_8 \in \{0,1\}^{512}$.

### 2.4 Compressão Final (`diffuse_rsd_s_v5`)
Denotando $\text{raw} = \text{serialize\_state\_v5}(S_{\text{priv}}) \in \{0,1\}^{512}$ e $\text{dom} = \text{DOM\_V5}(R, n_{\text{sess}})$:
$$F_s^{(256)}(x, y, n_{\text{sess}}) = H_{32}(\text{dom} \parallel \text{raw}) := \text{SHA-256}(\text{dom} \parallel \text{raw}) \in \{0,1\}^{256},$$
$$F_s^{(512)}(x, y, n_{\text{sess}}) = H_{64}(\text{dom} \parallel \mathtt{"|XOF512|"} \parallel \text{raw}) := \text{SHAKE256}(\text{dom} \parallel \mathtt{"|XOF512|"} \parallel \text{raw}, 64) \in \{0,1\}^{512}.$$

### 2.5 Arquitetura `Dupla-Chave SIV` + Folding 64B (`bandlimited_dual_key.py`)
No modo endurecido `dual_key_stochastic_hardened`, dada a matriz espectral pública determinística de posto cheio $B_{K_j} \in \mathbb{Z}_{65537}^{32 \times 32}$ (derivada da quantização em ponto fixo da soma finita de Guinand–Weil e do kernel positivo $K_j$):
1. Calcula-se $S_{\text{priv}} = \text{SPN}_8(x, y; s, n_{\text{sess}}) \in (\mathbb{F}_{2^{16}})^{32}$ (codificado como `s_priv_bytes` de $64$ bytes e interpretado componente a componente em $\mathbb{Z}_{65537}^{32}$).
2. Deriva-se a chave efêmera vinculada ao estado (mecanismo SIV):
   $$K_{\text{priv}} = \text{HMAC-SHA256}\big(s, \mathtt{"RSD\text{-}S\text{-}V5|DUALKEY|V5.1|SIV|"} \parallel \text{uint64\_be}(n_{\text{sess}}) \parallel S_{\text{priv}}\big) \in \{0,1\}^{256}.$$
3. Amostra-se o vetor de ruído $e_{\text{priv}} \in \mathbb{Z}_{65537}^{32}$ a partir do fluxo $\text{SHAKE256}(\mathtt{"RSD\text{-}S\text{-}V5|DUALKEY|NOISE|V5.1|"} \parallel K_{\text{priv}})$ via *rejection sampling* uniforme em palavras de $32$ bits com limiar $\text{limit} = 2^{32} - (2^{32} \bmod 65537)$.
4. Projeta-se no grupo aditivo $\mathbb{Z}_{65537}^{32}$:
   $$Y_{\text{pub}} = (B_{K_j} S_{\text{priv}} + e_{\text{priv}}) \bmod 65537 \in \mathbb{Z}_{65537}^{32}.$$
5. **Folding 64B (`_unpadded_z65537_to_bytes64`):** Para cada coordenada $i \in \{0,\dots,31\}$:
   $$W_i = \begin{cases} Y_{\text{pub}}[i], & \text{se } Y_{\text{pub}}[i] \in \{0,\dots,65535\}, \\ \text{uint16\_be}\big(\text{SHA-256}(\mathtt{"RSD\text{-}S\text{-}V5|DUALKEY|FOLD16|"} \parallel \text{uint64\_be}(n_{\text{sess}}) \parallel \text{uint16\_be}(i) \parallel S_{\text{priv}})[0:2]\big), & \text{se } Y_{\text{pub}}[i] = 65536. \end{cases}$$
   A saída pública compacta é $Y_{\text{pub,64B}} = W_0 \parallel \dots \parallel W_{31} \in \{0,1\}^{512}$.

---

## 3. Modelos de Ameaça e Separação Explícita Q1 vs Q2

No modelo **QROM** (Boneh et al., 2011), um adversário quântico $\mathcal{A}$ de tempo polinomial (ou limitado por $(t, q_H, q_C/q_Q)$) tem acesso de oráculo em superposição às funções públicas de *hash* / XOF modeladas como oráculos aleatórios quânticos $H: \{0,1\}^* \to \mathcal{Y}$:
$$|u, v\rangle \xrightarrow{\mathcal{O}_H} |u, v \oplus H(u)\rangle,$$
realizando no máximo $q_H$ consultas a $\mathcal{O}_H$. Distinguimos rigorosamente dois regimes de acesso ao oráculo chaveado $F_s$:

- **Modelo Q1 (Acesso Clássico à Primitiva Chaveada):** $\mathcal{A}$ executa computação quântica local e faz até $q_H$ consultas em superposição ao QRO público $H$, mas interage com o oráculo chaveado $F_s$ (implementado em hardware ou servidor) apenas por meio de $q_C$ consultas **clássicas** $(x_i, y_i, n_{\text{sess}, i}) \mapsto F_s(x_i, y_i, n_{\text{sess}, i})$ sobre no máximo $q_S \le q_C$ sessões distintas. Este é o modelo realista para ataques contra sistemas implantados.
- **Modelo Q2 (Acesso em Superposição à Primitiva Chaveada):** $\mathcal{A}$ recebe acesso quântico em superposição ao próprio oráculo chaveado, realizando até $q_Q$ consultas quânticas a $\mathcal{O}_{F_s}$ e $q_H$ consultas quânticas a $\mathcal{O}_H$. Como consultas em superposição sobre $n_{\text{sess}}$ podem superpor até $2^{64}$ sessões em uma única chamada (invalidando $q_S \le q_Q$), separam-se explicitamente dois sub-regimes:
  - **Q2-Sessão-Clássica (Principal):** $n_{\text{sess}} \in \mathcal{N}$ é parâmetro público clássico fixado por sessão ($q_S$ sessões clássicas abertas; superposição apenas sobre $(x, y) \in \mathcal{D}$):
    $$|x, y, z\rangle \xrightarrow{\mathcal{O}_{F_s(\cdot, \cdot, n_{\text{sess}})}} |x, y, z \oplus F_s(x, y, n_{\text{sess}})\rangle.$$
  - **Q2-Superposição-Completa:** $(x, y, n_{\text{sess}}) \in \mathcal{D} \times \mathcal{N}$ é consultado conjuntamente em superposição:
    $$|x, y, n_{\text{sess}}, z\rangle \xrightarrow{\mathcal{O}_{F_s}} |x, y, n_{\text{sess}}, z \oplus F_s(x, y, n_{\text{sess}})\rangle.$$
  Este último é o modelo conservador extremo (exigido em provas QROM formais de composição com *tweak* em superposição).

### 3.1 Jogos de Segurança Formais

1. **Segurança qPRF ($\mathbf{Adv}^{\text{Q1-qPRF}}$ e $\mathbf{Adv}^{\text{Q2-qPRF}}$):**
   Seja $s \xleftarrow{\$} \mathcal{K}$ e $\mathcal{R}: \mathcal{D} \times \mathcal{N} \to \mathcal{Y}$ uma função aleatória ideal independente de $H$. A vantagem do adversário $\mathcal{A}$ é:
   $$\mathbf{Adv}^{\text{Q1-qPRF}}_{F}(\mathcal{A}) = \left|\Pr\left[\mathcal{A}^{\mathcal{O}_H, F_s(\cdot)}(1^\lambda) = 1\right] - \Pr\left[\mathcal{A}^{\mathcal{O}_H, \mathcal{R}(\cdot)}(1^\lambda) = 1\right]\right|,$$
   $$\mathbf{Adv}^{\text{Q2-qPRF}}_{F}(\mathcal{A}) = \left|\Pr\left[\mathcal{A}^{\mathcal{O}_H, \mathcal{O}_{F_s}}(1^\lambda) = 1\right] - \Pr\left[\mathcal{A}^{\mathcal{O}_H, \mathcal{O}_{\mathcal{R}}}(1^\lambda) = 1\right]\right|.$$

2. **Segurança qMAC ($\mathbf{Adv}^{\text{Q1-qMAC}}$ e $\mathbf{Adv}^{\text{Q2-qMAC}}$):**
   - **Q1 (EUF-CMA Clássico com Adversário Quântico):** Após $q_C$ consultas clássicas $(m_i, t_i = F_s(m_i))$, $\mathcal{A}$ deve produzir um par válido $(m^*, t^*)$ com $m^* \notin \{m_1,\dots,m_{q_C}\}$. Pela redução padrão PRF $\to$ MAC,
     $$\mathbf{Adv}^{\text{Q1-qMAC}}_F(\mathcal{A}) \le \mathbf{Adv}^{\text{Q1-qPRF}}_F(\mathcal{B}) + \frac{1}{|\mathcal{Y}|}.$$
   - **Q2 (BZ-EUF-CMA / Plus-One Unforgeability — Boneh–Zhandry 2013):** Como consultas em superposição permitem consultar todo o domínio em uma única chamada, a noção clássica colapsa. Adota-se a definição **PO-EUF** (ou *Blind-Unforgeability*): após $q_Q$ consultas em superposição a $\mathcal{O}_{F_s}$, $\mathcal{A}$ deve produzir $q_Q + 1$ pares distintos $(m_1, t_1), \dots, (m_{q_Q+1}, t_{q_Q+1})$ válidos. Pelo Teorema 4.1 de Boneh–Zhandry (2013), toda qPRF segura em Q2 implica um qMAC seguro no sentido PO-EUF:
     $$\mathbf{Adv}^{\text{Q2-qMAC}}_F(\mathcal{A}) \le \mathbf{Adv}^{\text{Q2-qPRF}}_F(\mathcal{B}) + \frac{q_Q + 1}{|\mathcal{Y}|}.$$

3. **Segurança qIND-CPA ($\mathbf{Adv}^{\text{Q1/Q2-qIND-CPA}}$):**
   Adota-se uniformemente a convenção $\mathbf{Adv}^{\text{qIND-CPA}}_{\Pi}(\mathcal{A}) := \left|\Pr[\text{acerto}] - \frac{1}{2}\right|$ (de modo que a vantagem trivial máxima para acerto determinístico é $1/2$).
   - **Primitiva Isolada:** Como $F_s(x, y, n_{\text{sess}})$ é determinística, um adversário que consulte duas vezes o mesmo $(x_0, y_0, n_{\text{sess}})$ (ou compare com um par desafio de mensagem repetida) acerta com probabilidade $1$, obtendo $\mathbf{Adv}^{\text{qIND-CPA}} = 1/2$. Logo, a primitiva isolada **não** é IND-CPA.
   - **Modo Cifra com Nonce Único (ou AEAD):** Quando $F_s$ é utilizada para cifrar $c = m \oplus F_s(\text{nonce}, \text{ctx})$ com $(\text{nonce}, \text{ctx})$ estritamente único (em Q1: desafio clássico com *nonce* fresco), a vantagem qIND-CPA reduz-se diretamente à vantagem qPRF:
     $$\mathbf{Adv}^{\text{Q1-qIND-CPA}}_{\Pi}(\mathcal{A}) \le \mathbf{Adv}^{\text{Q1-qPRF}}_F(\mathcal{B}).$$
     Em Q2, se o oráculo de cifragem permitir superposição sobre a mensagem $m$ mantendo um *nonce* clássico único por consulta de desafio, o mesmo limite $\le \mathbf{Adv}^{\text{Q2-qPRF}}_F(\mathcal{B})$ aplica-se. Já no modo **Dupla-Chave SIV**, o SIV não transforma a primitiva em cifra IND-CPA para mensagens repetidas, mas garante segurança de **compromisso/PRF resistente a reuso de $n_{\text{sess}}$**: para quaisquer $(x,y) \neq (x',y')$ sob o mesmo $n_{\text{sess}}$, as saídas $Y_{\text{pub}}$ permanecem computacionalmente indistinguíveis de uniformes independentes.

### 3.2 Limites Genéricos Quânticos (Busca, Colisão e Pré-imagem)

| Propriedade / Ataque Genérico | Saída 256 bits (`output_bytes=32`) | Saída 512 bits (`output_bytes=64` ou `Dupla-Chave 64B`) | Base Teórica |
| :--- | :--- | :--- | :--- |
| **Busca de Chave $s \in \{0,1\}^{256}$ (Grover)** | $\Omega(2^{128})$ consultas | $\Omega(2^{128})$ consultas | BBHT (1998) — limitado pela chave de 256 bits |
| **Pré-imagem na Saída (Grover)** | $\Omega(2^{128})$ consultas | $\Omega(2^{256})$ consultas *(inversão da saída de 512b com chave fixa desconhecida sob QRO ideal; recuperar $s$ custa $O(2^{128})$)* | Grover (1996) sobre QRO |
| **Colisão na Saída (BHT / CNS)** | $O(2^{256/3}) \approx O(2^{85{,}3})$ consultas | $O(2^{512/3}) \approx O(2^{170{,}7})$ consultas | Brassard–Høyer–Tapp (1997) / Zhandry (2015) |
| **Colisão no Estado Interno $\text{SPN}_8$ ($512$b)** | $O(2^{512/3}) \approx O(2^{170{,}7})$ | $O(2^{512/3}) \approx O(2^{170{,}7})$ | Espaço de estado $\mathcal{S} = \{0,1\}^{512}$ |

> [!NOTE]
> A opção `output_bytes=64` (via `SHAKE256`) e a saída compacta de $64$ bytes da `Dupla-Chave SIV` foram explicitamente dimensionadas para elevar o limite genérico de colisão BHT de $2^{85{,}3}$ para $2^{170{,}7}$ operações, mantendo a margem pós-quântica $\ge 128$ bits contra colisões genéricas.

---

## 4. Teorema 1: Redução Q1/Q2-qPRF de `RSD-S v5.1`

### 4.1 Ferramental QROM Utilizado
- **Switching Lemma Quântico e Indexado (Zhandry 2015 / *Compressed Oracle* 2019):** A distância de vantagem entre o acesso em superposição a uma permutação aleatória $\Pi: \{0,1\}^m \to \{0,1\}^m$ e a uma função aleatória $R: \{0,1\}^m \to \{0,1\}^m$ com $q_Q$ consultas quânticas é limitada por $O(q_Q^3 / 2^m)$ (no domínio restrito $\mathcal{D} \subsetneq \{0,1\}^{512}$ de cardinalidade $p^2 \approx 2^{510}$, a composição $\Pi \circ \text{frag}$ e $R_1: \mathcal{D} \to \{0,1\}^{512}$ têm imagem em $\{0,1\}^{512}$, mantendo o denominador $2^{512}$). Pelo **Switching Lemma Indexado** (para famílias indexadas por *tweak* $n_{\text{sess}} \in \mathcal{N}$ consultadas em superposição), o mesmo limite $O(q_Q^3 / 2^{512})$ aplica-se à distinção entre $\{\Pi_{n_{\text{sess}}}\}_{n_{\text{sess}} \in \mathcal{N}}$ e $\{R_{n_{\text{sess}}}\}_{n_{\text{sess}} \in \mathcal{N}}$. Em Q1 ($q_C$ consultas clássicas), aplica-se o Switching Lemma clássico: $\le \frac{q_C(q_C-1)}{2^{513}}$.
- **Compressed Oracle de Zhandry (2019):** Em vez de definir um conjunto secreto estático $S$ sobre todo o domínio $\mathcal{D} \times \mathcal{N}$ (o que tornaria $P_{\text{guess}}$ em O2H estático igual a $\Omega(1)$), modela-se a função aleatória secreta $R_1: \mathcal{D} \times \mathcal{N} \to \{0,1\}^m$ e o QRO público $H$ por meio de bancos de dados comprimidos purificados $D_{R_1}$ e $D_H$. Após $q$ consultas ao oráculo chaveado (com $q = q_C$ em Q1 ou $q = q_Q$ em Q2) e $q_H$ consultas ao QRO $H$, o tamanho efetivo dos bancos comprimidos satisfaz $|D_{R_1}| \le q$ e $|D_H| \le q_H$. Como cada entrada ativa em $D_{R_1}$ possui imagem uniforme e independente em $\{0,1\}^m$ (nunca revelada diretamente ao adversário), a probabilidade/amplitude de interseção entre uma consulta registrada em $D_H$ e qualquer imagem ativa em $D_{R_1}$ escala como $O\!\left(q_H \sqrt{q / 2^m}\right)$.

### 4.2 Enunciado do Teorema 1
**Teorema 1 (Redução Condicional qPRF de `RSD-S v5.1`).** *Modelando $H \in \{H_{32}, H_{64}\}$ como um Oráculo Aleatório Quântico (QRO) de saída de $n_{\text{out}} \in \{256, 512\}$ bits, para qualquer adversário quântico $\mathcal{A}$ rodando em tempo $t$ e realizando $q_H$ consultas quânticas a $H$, e $q_C$ consultas clássicas (em Q1) ou $q_Q$ consultas em superposição (em Q2) a $F_s$:*

1. **Regime Q1 ($q_S \le q_C$ sessões clássicas):**
   $$\mathbf{Adv}^{\text{Q1-qPRF}}_{\text{RSD-S v5.1}}(\mathcal{A}) \le \mathbf{Adv}^{\text{Q1-qPRF}}_{\text{HMAC-SHA256}}(17 q_S, t_1) + q_S \cdot \mathbf{Adv}^{\text{Q1-qPRP}}_{\text{SPN}_8}(q_C, t_2) + \frac{q_C(q_C-1)}{2^{513}} + O\!\left(q_H \sqrt{\frac{q_C}{2^{512}}}\right).$$
2. **Regime Q2-Sessão-Clássica (Principal — $q_S$ sessões clássicas abertas; superposição apenas em $(x,y) \in \mathcal{D}$):**
   $$\mathbf{Adv}^{\text{Q2-SessCla-qPRF}}_{\text{RSD-S v5.1}}(\mathcal{A}) \le \mathbf{Adv}^{\text{Q1-qPRF}}_{\text{HMAC-SHA256}}(17 q_S, t_1) + q_S \cdot \mathbf{Adv}^{\text{Q2-qPRP}}_{\text{SPN}_8}(q_Q, t_2) + O\!\left(\frac{q_Q^3}{2^{512}}\right) + O\!\left(q_H \sqrt{\frac{q_Q}{2^{512}}}\right).$$
3. **Regime Q2-Superposição-Completa ($(x,y,n_{\text{sess}})$ em superposição):**
   $$\mathbf{Adv}^{\text{Q2-Full-qPRF}}_{\text{RSD-S v5.1}}(\mathcal{A}) \le \mathbf{Adv}^{\text{Q2-qPRF}}_{\text{HMAC-SHA256}}(17 q_Q, t_1) + \mathbf{Adv}^{\text{Q2-tqPRP}}_{\text{SPN}_8}(q_Q, t_2) + O\!\left(\frac{q_Q^3}{2^{512}}\right) + O\!\left(q_H \sqrt{\frac{q_Q}{2^{512}}}\right),$$
*onde $\mathbf{Adv}^{\text{qPRP}}_{\text{SPN}_8}$ e $\mathbf{Adv}^{\text{Q2-tqPRP}}_{\text{SPN}_8}$ referem-se à permutação $\text{SPN}_8$ **incluindo** sua expansão determinística interna `expand_key_words_v5` chaveada por $(K_0,\dots,K_8, rc_1,\dots,rc_8)$, e $t_1, t_2 \approx t + \text{poly}(q_H, q_C/q_Q)$.*

### 4.3 Demonstração por Sequência de Jogos Híbridos ($G_0 \to G_4$)

- **Jogo $G_0$ (Real):** $\mathcal{A}$ interage com o QRO $H$ e com o oráculo real $F_s$ de `RSD-S v5.1` ($R = 8$ rodadas), onde $s \xleftarrow{\$} \{0,1\}^{256}$.
- **Jogo $G_1$ (Substituição do Key Schedule Base em $s$):** Substituímos **apenas** as $17$ saídas derivadas diretamente com a chave mestra $s$ por sessão — isto é, $(K_0,\dots,K_8) \in (\{0,1\}^{256})^9$ e $(rc_1,\dots,rc_8) \in (\mathbb{F}_{2^{16}})^8$ — por strings uniformes e independentes (mantendo `expand_key_words_v5` determinística sobre cada $K_r$, pois $rk_r = K_r \parallel \text{HMAC-SHA256}(K_r, \mathtt{"EXP|"} \parallel 1)$ não é uniforme em $\{0,1\}^{512}$ devido aos $256$ bits iniciais serem a própria chave $K_r$). Como os domínios `DOM_V5 || 0x00`, `DOM_V5 || uint8(r)` e `DOM_V5 || "RC" || uint8(r)` são disjuntos:
  - Em **Q1** e **Q2-Sessão-Clássica**, $n_{\text{sess}}$ é clássico ($q_S$ sessões abertas), exigindo $q_K \le 17 q_S$ chamadas clássicas a `HMAC-SHA256(s, ·)`:
    $$|\Pr[G_0 = 1] - \Pr[G_1 = 1]| \le \mathbf{Adv}^{\text{Q1-qPRF}}_{\text{HMAC-SHA256}}(17 q_S, t_1).$$
  - Em **Q2-Superposição-Completa**, $n_{\text{sess}}$ é consultado em superposição, exigindo a hipótese **Q2-qPRF** sobre `HMAC-SHA256(s, ·)` com até $17 q_Q$ avaliações em superposição:
    $$|\Pr[G_0 = 1] - \Pr[G_1 = 1]| \le \mathbf{Adv}^{\text{Q2-qPRF}}_{\text{HMAC-SHA256}}(17 q_Q, t_1).$$
- **Jogo $G_2$ (Substituição de $\text{SPN}_8$ por Permutação Aleatória):** Substituímos a permutação $\text{SPN}_8(\cdot; K^{(n_{\text{sess}})}, rc^{(n_{\text{sess}})})$ — **incluindo** sua expansão interna determinística `expand_key_words_v5` — sobre $\{0,1\}^{512}$ por uma família de permutações aleatórias secretas e independentes $\Pi_{n_{\text{sess}}} \xleftarrow{\$} \text{Perm}(\{0,1\}^{512})$, mantendo a injeção determinística $\text{frag}: \mathcal{D} \hookrightarrow \{0,1\}^{512}$ na entrada:
  - Em **Q1** e **Q2-Sessão-Clássica** (argumento híbrido sobre $q_S$ sessões clássicas):
    $$|\Pr[G_1 = 1] - \Pr[G_2 = 1]| \le q_S \cdot \mathbf{Adv}^{\text{qPRP}}_{\text{SPN}_8}(q, t_2), \quad (q = q_C \text{ em Q1}, \; q = q_Q \text{ em Q2-SessCla}).$$
  - Em **Q2-Superposição-Completa** (redução à hipótese de **tweakable qPRP** com *tweak* $n_{\text{sess}} \in \mathcal{N}$):
    $$|\Pr[G_1 = 1] - \Pr[G_2 = 1]| \le \mathbf{Adv}^{\text{Q2-tqPRP}}_{\text{SPN}_8}(q_Q, t_2).$$
- **Jogo $G_3$ (Switching Lemma: Permutação $\to$ Função Aleatória):** Substituímos cada $\Pi_{n_{\text{sess}}} \circ \text{frag}$ por uma função aleatória secreta independente $R_{n_{\text{sess}}}: \mathcal{D} \to \{0,1\}^{512}$.
  - Em **Q1**, a probabilidade de colisão em $R_{n_{\text{sess}}}$ sobre $q_C$ consultas clássicas é $\le \frac{q_C(q_C-1)}{2^{513}}$.
  - Em **Q2-Sessão-Clássica**, pelo *Quantum Switching Lemma* de Zhandry (2015), a vantagem é limitada por $O(q_Q^3 / 2^{512})$.
  - Em **Q2-Superposição-Completa**, pelo **Switching Lemma Indexado** de Zhandry (2015) sobre a família indexada por $n_{\text{sess}}$, a vantagem permanece limitada por $O(q_Q^3 / 2^{512})$.
- **Jogo $G_4$ (Desacoplamento QRO via Compressed Oracle de Zhandry):** Em $G_3$, o oráculo chaveado responde $H(\text{tag}(n_{\text{sess}}) \parallel R_{n_{\text{sess}}}(x, y))$, onde $\text{tag}(n_{\text{sess}}) = \text{DOM\_V5}(8, n_{\text{sess}})$ (para $H_{32}$) ou $\text{DOM\_V5}(8, n_{\text{sess}}) \parallel \mathtt{"|XOF512|"}$ (para $H_{64}$). No jogo ideal $G_4$, substituímos a resposta do oráculo chaveado por uma função aleatória totalmente independente $\mathcal{R}(x, y, n_{\text{sess}}) \xleftarrow{\$} \mathcal{Y}$.
  - No formalismo **Compressed Oracle de Zhandry (2019)**, mantemos o banco de dados comprimido $D_{R_1}$ para $R_1(x, y, n_{\text{sess}}) := R_{n_{\text{sess}}}(x, y)$ (com $|D_{R_1}| \le q$ registros ativos após $q \in \{q_C, q_Q\}$ consultas ao oráculo chaveado) e o banco comprimido $D_H$ para o QRO $H$ (com $|D_H| \le q_H$ registros ativos após $q_H$ consultas a $H$).
  - Sem definir nenhum conjunto estático sobre todo $\mathcal{D} \times \mathcal{N}$, a distinção entre $G_3$ e $G_4$ ocorre somente se $\mathcal{A}$ gerar amplitude não-desprezível de interseção entre entradas consultadas em $D_H$ e valores ativos $\text{tag}(n_{\text{sess}}) \parallel R_{n_{\text{sess}}}(x,y)$ armazenados em $D_{R_1}$. Como cada valor em $D_{R_1}$ tem $512$ bits uniformes e independentes ocultos por $H$, a norma da projeção no subespaço de interseção cresce no máximo $O(\sqrt{q / 2^{512}})$ por consulta ao QRO, resultando em:
    $$|\Pr[G_3 = 1] - \Pr[G_4 = 1]| \le O\!\left(q_H \sqrt{\frac{q}{2^{512}}}\right).$$

Somando os saltos $G_0 \to G_4$ pela desigualdade triangular obtêm-se exatamente os limites do Teorema 1 para os três regimes. $\blacksquare$

---

## 5. Teorema 2: Redução Q1/Q2-qPRF de `Dupla-Chave SIV` + Folding 64B

### 5.1 Enunciado do Teorema 2
**Teorema 2 (Redução Condicional qPRF de `Dupla-Chave SIV`).** *Modelando `SHAKE256` e `SHA-256` (no `FOLD16`) como QROs independentes (por separação de domínio explícita `NOISE|V5.1|` e `FOLD16|`), para qualquer adversário $\mathcal{A}$ com $q_H$ consultas ao QRO e $q$ consultas ao oráculo `Dupla-Chave SIV` ($q = q_C$ em Q1, $q = q_Q$ em Q2), mesmo sob reuso arbitrário de $n_{\text{sess}}$:*

1. **Regime Q1 ($q_S \le q_C$ sessões clássicas):**
   $$\mathbf{Adv}^{\text{Q1-qPRF}}_{\text{DualKey-SIV}}(\mathcal{A}) \le \mathbf{Adv}^{\text{Q1-qPRF}}_{\text{HMAC-SHA256}}(17 q_S + q_C, t_1) + q_S \cdot \mathbf{Adv}^{\text{Q1-qPRP}}_{\text{SPN}_8}(q_C, t_2) + \frac{q_C(q_C-1)}{2^{512}} + O\!\left(q_H \sqrt{\frac{q_C}{2^{256}}}\right) + O\!\left(q_H \sqrt{\frac{q_C}{2^{512}}}\right).$$
2. **Regime Q2-Sessão-Clássica ($q_S$ sessões clássicas; superposição em $(x,y)$):**
   $$\mathbf{Adv}^{\text{Q2-SessCla-qPRF}}_{\text{DualKey-SIV}}(\mathcal{A}) \le \mathbf{Adv}^{\text{Q1-qPRF}}_{\text{HMAC-SHA256}}(17 q_S, t_1') + \mathbf{Adv}^{\text{Q2-qPRF}}_{\text{HMAC-SHA256}}(q_Q, t_1'') + q_S \cdot \mathbf{Adv}^{\text{Q2-qPRP}}_{\text{SPN}_8}(q_Q, t_2) + O\!\left(\frac{q_Q^3}{2^{512}}\right) + O\!\left(q_H \sqrt{\frac{q_Q}{2^{256}}}\right) + O\!\left(q_H \sqrt{\frac{q_Q}{2^{512}}}\right).$$
   *(Nota: em Q2-Sessão-Clássica, $S_{\text{priv}}$ depende de $(x,y)$ em superposição, logo a chamada `DUALKEY|V5.1|SIV|` a `HMAC-SHA256(s, ·)` ocorre em superposição sobre $S_{\text{priv}}$.)*
3. **Regime Q2-Superposição-Completa ($(x,y,n_{\text{sess}})$ em superposição):**
   $$\mathbf{Adv}^{\text{Q2-Full-qPRF}}_{\text{DualKey-SIV}}(\mathcal{A}) \le \mathbf{Adv}^{\text{Q2-qPRF}}_{\text{HMAC-SHA256}}(18 q_Q, t_1) + \mathbf{Adv}^{\text{Q2-tqPRP}}_{\text{SPN}_8}(q_Q, t_2) + O\!\left(\frac{q_Q^3}{2^{512}}\right) + O\!\left(q_H \sqrt{\frac{q_Q}{2^{256}}}\right) + O\!\left(q_H \sqrt{\frac{q_Q}{2^{512}}}\right).$$

*Em todos os regimes, o termo $\frac{q_C(q_C-1)}{2^{512}} = 2 \cdot \frac{q_C(q_C-1)}{2^{513}}$ (ou $O(q_Q^3/2^{512})$ em Q2) contabiliza tanto o Switching Lemma de $\Pi \to R_1$ quanto a colisão de $R_1$ na entrada de `SIV`; o *rejection sampling* exato possui $\epsilon_{\text{rej}} = 0$ (probabilidade de falha de *buffer* $< 2^{-1000}$), e a saída final de $64$ bytes possui distância estatística total $\text{TVD} = 0$ da distribuição uniforme sobre $\{0,1\}^{512}$.*

### 5.2 Demonstração por Sequência de Jogos Híbridos ($H_0 \to H_4$)

- **Jogo $H_0$ (Real):** Execução real de `BandlimitedDualKeyEngine.refactor_public_output` no modo `dual_key_stochastic_hardened`.
- **Jogo $H_1$ (Substituição Única de Todas as Chamadas `HMAC-SHA256(s, ·)`):** Em um **único passo inicial**, substituímos todas as chamadas a `HMAC-SHA256(s, ·)` — tanto as $17$ chamadas por sessão do *key schedule* (`RSD-S-V5.1|CORE|`) quanto a derivação SIV (`RSD-S-V5|DUALKEY|V5.1|SIV|`) — por funções aleatórias independentes, pois os prefixos de domínio são estritamente disjuntos. Assim, $(K_0,\dots,K_8, rc_1,\dots,rc_8)$ tornam-se uniformes independentes por sessão e $K_{\text{priv}}$ é substituído por uma função aleatória secreta $K_{\text{priv}}^{\text{rand}}(n_{\text{sess}}, S_{\text{priv}}) \in \{0,1\}^{256}$. O custo é $\mathbf{Adv}^{\text{qPRF}}_{\text{HMAC-SHA256}}$ conforme o regime (até $17 q_S + q_C$ chamadas em Q1; $17 q_S$ clássicas + $q_Q$ em superposição em Q2-Sessão-Clássica; até $18 q_Q$ em Q2-Superposição-Completa).
- **Jogo $H_2$ (Substituição $\text{SPN}_8 \to \Pi \to R_1$):** Aplicando explicitamente os passos $G_1 \to G_2$ e $G_2 \to G_3$ do Teorema 1, substituímos $\text{SPN}_8$ (incluindo `expand_key_words_v5`) por $\Pi_{n_{\text{sess}}}$ e em seguida por uma função aleatória secreta $R_1(x, y, n_{\text{sess}}) \in \{0,1\}^{512}$:
  - Custo em Q1: $q_S \cdot \mathbf{Adv}^{\text{Q1-qPRP}}_{\text{SPN}_8}(q_C, t_2) + \frac{q_C(q_C-1)}{2^{513}}$.
  - Custo em Q2-Sessão-Clássica: $q_S \cdot \mathbf{Adv}^{\text{Q2-qPRP}}_{\text{SPN}_8}(q_Q, t_2) + O\!\left(\frac{q_Q^3}{2^{512}}\right)$.
  - Custo em Q2-Superposição-Completa: $\mathbf{Adv}^{\text{Q2-tqPRP}}_{\text{SPN}_8}(q_Q, t_2) + O\!\left(\frac{q_Q^3}{2^{512}}\right)$.
- **Jogo $H_3$ (Desacoplamento de $K_{\text{priv}}$ para Chave Independente por $(x, y, n_{\text{sess}})$):** Em $H_2$, $K_{\text{priv}} = K_{\text{priv}}^{\text{rand}}(n_{\text{sess}}, R_1(x, y, n_{\text{sess}}))$. Substituímos $K_{\text{priv}}$ por uma função aleatória independente $K_{\text{priv}}^*(x, y, n_{\text{sess}}) \xleftarrow{\$} \{0,1\}^{256}$ indexada diretamente por $(x, y, n_{\text{sess}})$. Os jogos $H_2$ e $H_3$ são idênticos a menos que ocorra colisão em $R_1(x, y, n_{\text{sess}}) = R_1(x', y', n_{\text{sess}})$ para $(x, y) \neq (x', y')$. Logo, adicionamos **explicitamente** o termo de colisão de $R_1$:
  - $+\frac{q_C(q_C-1)}{2^{513}}$ em Q1 (totalizando $\frac{q_C(q_C-1)}{2^{512}}$ ao somar com $H_1 \to H_2$), ou
  - $+O\!\left(\frac{q_Q^3}{2^{512}}\right)$ em Q2 (limite de colisão de Zhandry para função aleatória em $\{0,1\}^{512}$).
- **Jogo $H_4$ (Compressed Oracle em `SHAKE256` e `FOLD16` + Independência Aditiva + $\text{TVD}=0$):**
  1. **Compressed Oracle sobre `SHAKE256` ($K_{\text{priv}}^* \in \{0,1\}^{256}$):** Em $H_3$, $e_{\text{priv}}$ é amostrado de $\text{SHAKE256}(\mathtt{"RSD\text{-}S\text{-}V5|DUALKEY|NOISE|V5.1|"} \parallel K_{\text{priv}}^*)$. Pelo *Compressed Oracle* de Zhandry (2019) sobre o banco $D_{K_{\text{priv}}^*}$ ($|D_{K_{\text{priv}}^*}| \le q$) e $D_{\text{SHAKE}}$ ($|D_{\text{SHAKE}}| \le q_H$), a vantagem de interseção entre consultas a `SHAKE256` e as chaves secretas de $256$ bits em $D_{K_{\text{priv}}^*}$ é limitada por $O\!\left(q_H \sqrt{q / 2^{256}}\right)$.
  2. **Rejeição Exata e OTP em $\mathbb{Z}_{65537}^{32}$:** O *rejection sampling* com limiar $\text{limit} = 2^{32} - (2^{32} \bmod 65537)$ produz variáveis perfeitamente uniformes em $\mathbb{Z}_{65537}$ ($\epsilon_{\text{rej}} = 0$). Logo $e_{\text{priv}}$ torna-se um vetor uniforme $u \xleftarrow{\$} \mathbb{Z}_{65537}^{32}$ independente de $R_1$ e de $B_{K_j}$. Mesmo com $B_{K_j} \in \mathbb{Z}_{65537}^{32 \times 32}$ pública e invertível, $Y_{\text{pub}} = (B_{K_j} R_1 + u) \bmod 65537$ é **informacionalmente uniforme** em $\mathbb{Z}_{65537}^{32}$ (*One-Time Pad* aditivo), eliminando o vazamento diferencial $Y_{\text{pub}}' - Y_{\text{pub}} = B_{K_j}(S_{\text{priv}}' - S_{\text{priv}})$ mesmo sob reuso de $n_{\text{sess}}$ entre $(x,y) \neq (x',y')$.
  3. **Compressed Oracle sobre `FOLD16` ($R_1 \in \{0,1\}^{512}$) e $\text{TVD}=0$:** Quando $Y_{\text{pub}}[i] = 65536$ (prob. $\frac{1}{65537}$), $W_i$ usa $\text{SHA-256}(\dots \parallel R_1)[0:2]$. Pelo *Compressed Oracle* sobre $R_1 \in \{0,1\}^{512}$ (custo $O\!\left(q_H \sqrt{q / 2^{512}}\right)$), essa palavra é substituída por $U_i \xleftarrow{\$} \{0,\dots,65535\}$. Pela **Lei da Probabilidade Total**:
     $$\Pr[W_i = w] = \frac{1}{65537} + \frac{1}{65537} \cdot \frac{1}{65536} = \frac{1}{65536} \quad \forall w \in \{0,\dots,65535\}.$$
     Portanto $\text{TVD} = 0$ e $Y_{\text{pub,64B}}$ é indistinguível de uniforme em $\{0,1\}^{512}$. $\blacksquare$

---

## 6. Tabela de Hipóteses Explícitas e Não-Provadas (Para Revisão Externa)

| Categoria | Item / Propriedade | Status neste Rascunho | Detalhamento / Justificativa |
| :--- | :--- | :--- | :--- |
| **Reduzido Formalmente** | Composição $\text{SPN}_8 \to H_{32}/H_{64}$ no QROM (Q1 / Q2-Sessão-Clássica / Q2-Superposição-Completa) | **Provado (Condicional)** | Via Switching Lemma (Clássico / Quântico / Indexado: $O(q_Q^3/2^{512})$) e **Compressed Oracle** de Zhandry ($O(q_H \sqrt{q/2^{512}})$) sob qPRP / tqPRP para $\text{SPN}_8$. |
| **Reduzido Formalmente** | Mascaramento aditivo SIV em $\mathbb{Z}_{65537}^{32}$ | **Provado (Condicional)** | Independência informacional de $Y_{\text{pub}}$ frente a $B_{K_j} S_{\text{priv}}$, inclusive sob reuso de $n_{\text{sess}}$ para entradas distintas (com termo de colisão de $R_1$ explícito). |
| **Reduzido Formalmente** | Uniformidade exata do *Folding* 64B ($\text{TVD}=0$) | **Provado (Condicional)** | Pela Lei da Probabilidade Total, $\frac{1}{65537} + \frac{1}{65537\cdot 65536} = \frac{1}{65536}$ quando `FOLD16` é modelado como QRO sobre $R_1$ secreto via Compressed Oracle. |
| **Reduzido Formalmente** | Implicação $\text{qPRF} \implies \text{qMAC}$ (Q1 e Q2 PO-EUF) | **Provado (Condicional)** | Aplicação direta de Boneh–Zhandry (2013) a partir dos Teoremas 1 e 2. |
| **Assumido (Não Provado)** | Segurança **qPRP** de $\text{SPN}_8$ ($8$ rodadas) **incluindo** `expand_key_words_v5` (e **Q2-tqPRP** em Q2-Superposição-Completa) | **Hipótese Estrutural** | Assume-se que $\text{SPN}_8$ ($S_{\text{v5}}$ + $M_{\text{v5.1}}$ + expansão determinística interna `expand_key_words_v5` a partir de $(K_r, rc_r)$ uniformes) é indistinguível de permutação aleatória (ou *tweakable* PRP com *tweak* $n_{\text{sess}}$ em Q2-Superposição-Completa). Não há prova incondicional contra ataques estruturais de $8$ rodadas. |
| **Assumido (Não Provado)** | Segurança **Q1-qPRF** (e **Q2-qPRF** em Q2-Superposição-Completa / SIV-Q2) de `HMAC-SHA256` | **Hipótese Padrão** | Em Q1 e no *key schedule* de Q2-Sessão-Clássica basta Q1-qPRF ($17 q_S$ chamadas). Em Q2-Superposição-Completa e na chamada `SIV` de Q2-Sessão-Clássica exige-se Q2-qPRF de `HMAC-SHA256(s, ·)`. |
| **Assumido (Não Provado)** | Indiferenciabilidade QRO de `SHA-256` e `SHAKE256` | **Idealização QROM** | Modelados como QROs perfeitos e independentes (separação via prefixos de domínio). |
| **Assumido (Não Provado)** | Ausência de subgrupo oculto / periodicidade em $\text{SPN}_8$ ou $B_{K_j}$ | **Não Provado** | Embora não haja estrutura circular explícita, não há prova de impossibilidade contra algoritmos tipo Simon/Kuperberg além dos limites empíricos e de $\text{qPRP}$. |
| **Fora do Modelo QROM** | Segurança *Constant-Time* na camada Python (`== 65536` no folding) | **Limitação de Implementação** | O modelo QROM de caixa-preta não captura vazamentos de *timing*/cache. O ramo `if iv < 65536` em Python (`bandlimited_dual_key.py`) ocorre com prob. $1/65537$ e depende de $Y_{\text{pub}}$ (que é público, não secreto), mas exige verificação se portado para C. |

---

## 7. Checklist de Perguntas para Revisores Externos

1. **Limite $\text{qPRP}$ / $\text{Q2-tqPRP}$ de $\text{SPN}_8$ em Q2:** A S-box $S_{\text{v5}}(u) = A_{16}(u^{-1}) \oplus \mathtt{0x63A9}$ sobre $\mathbb{F}_{2^{16}}$ combinada com a matriz MDS $32\times 32$ ($M_{\text{v5.1}}$) e a expansão `expand_key_words_v5` em $8$ rodadas apresenta alguma estrutura diferencial/integral, de chave relacionada (via `EXP|`) ou polinomial de grau baixo explorável em superposição (Q2-Sessão-Clássica ou Q2-Superposição-Completa com *tweak* $n_{\text{sess}}$)?
2. **Absorção de `expand_key_words_v5` em $G_2$:** Como `rk_r = K_r || HMAC-SHA256(K_r, "EXP|" || 1)` não é uniforme em $\{0,1\}^{512}$, $G_1$ substitui apenas $(K_0,\dots,K_8, rc_1,\dots,rc_8)$ ($17 q_S$ chamadas) e `expand_key_words_v5` é absorvida na hipótese de $\text{SPN}_8$ em $G_2$. Seria preferível decompor $rk_r$ com uma hipótese intermediária explícita ou mantê-la integrada à especificação da $\text{SPN}_8$?
3. **Suficiência da Entropia de $K_{\text{priv}}$ ($256$ bits) no Teorema 2:** Em $H_4$, o termo de *Compressed Oracle* sobre `SHAKE256` para $K_{\text{priv}}^*$ escala como $O(q_H \sqrt{q / 2^{256}})$, compatível com a segurança de $128$ bits contra Grover na chave $s$. Esse termo domina $O(q_H \sqrt{q / 2^{512}})$ do Teorema 1: isso é aceitável para o alvo de $128$ bits pós-quânticos ou recomenda-se expandir $K_{\text{priv}}$ para $512$ bits (ex.: via `HMAC-SHA512`)?
4. **Reuso de $n_{\text{sess}}$ com Mesma Entrada $(x,y)$:** O documento deixa claro que `Dupla-Chave SIV` é determinística para $(x,y,n_{\text{sess}})$ idênticos (não oferecendo IND-CPA sem *nonce* único). A distinção entre proteção SIV contra reuso de $n_{\text{sess}}$ em entradas distintas vs. exigência de *nonce* único para IND-CPA está formulada sem ambiguidade?
5. **Independência da Matriz $B_{K_j}$:** No Teorema 2, $B_{K_j}$ é pública e determinística (derivada da soma de Guinand–Weil e kernel $K_j$). Existe algum cenário de ataque onde o conhecimento de $B_{K_j}$ ajude a distinguir $Y_{\text{pub}}$ após a adição de $u \xleftarrow{\$} \mathbb{Z}_{65537}^{32}$? (Pela prova, a adição modular por $u$ uniforme anula qualquer dependência de $B_{K_j} R_1$.)

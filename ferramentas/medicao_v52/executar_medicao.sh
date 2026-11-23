#!/usr/bin/env bash
# Reproduz as medições da RSD-S v5.2. Uso: ferramentas/medicao_v52/executar_medicao.sh [cpu_fixa] [pasta_de_saida]
# Requisitos: gcc, python3, numpy, scipy (apenas para o comparativo linear). Leva cerca de 10 a 15 minutos.
set -euo pipefail
CPU="${1:-2}"; AQUI="$(cd "$(dirname "$0")" && pwd)"; RAIZ="$(cd "$AQUI/../.." && pwd)"
SAIDA="${2:-$RAIZ/resultados/v5_2/medicao_local}"; mkdir -p "$SAIDA"; TMP="$(mktemp -d)"; export CPU_FIXA="$CPU"
CORE="$RAIZ/implementacao/c_core/rsd_s_v5_ct.c"
{ echo "cpu: $(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2- | xargs)"; echo "gcc: $(gcc --version | head -1)"
  echo "python: $(python3 --version)  numpy: $(python3 -c 'import numpy;print(numpy.__version__)')"
  echo "nucleo_sha256: $(sha256sum "$CORE" | cut -d' ' -f1)"; echo "kernel: $(uname -sr)"; echo "cpu_fixa: $CPU"; } > "$SAIDA/ambiente.txt"
# núcleo sob -Werror, depois harnesses
gcc -O3 -mavx2 -Wall -Wextra -Werror -c "$CORE" -o /dev/null
gcc -O3 -mavx2  "$AQUI/bench_core.c" "$CORE" -o "$TMP/b_avx2"
gcc -O2 -mno-avx2 "$AQUI/bench_core.c" "$CORE" -o "$TMP/b_escalar"
gcc -O0 "$AQUI/bench_core.c" "$CORE" -o "$TMP/b_O0"
gcc -O3 -mavx2 "$AQUI/tvla_core.c" "$CORE" -lm -o "$TMP/tvla"
: > "$SAIDA/latencia_c.jsonl"
for pass in 1 2; do
  for R in 8 4; do echo -n "{\"pass\":$pass,\"cfg\":\"O3_avx2\",\"r\":$R,\"x\":" >> "$SAIDA/latencia_c.jsonl"; taskset -c "$CPU" "$TMP/b_avx2" $R 4000 21 | tr -d '\n' >> "$SAIDA/latencia_c.jsonl"; echo "}" >> "$SAIDA/latencia_c.jsonl"
                  echo -n "{\"pass\":$pass,\"cfg\":\"O2_escalar\",\"r\":$R,\"x\":" >> "$SAIDA/latencia_c.jsonl"; taskset -c "$CPU" "$TMP/b_escalar" $R 600 21 | tr -d '\n' >> "$SAIDA/latencia_c.jsonl"; echo "}" >> "$SAIDA/latencia_c.jsonl"; done
  echo -n "{\"pass\":$pass,\"cfg\":\"O0\",\"r\":8,\"x\":" >> "$SAIDA/latencia_c.jsonl"; taskset -c "$CPU" "$TMP/b_O0" 8 150 21 | tr -d '\n' >> "$SAIDA/latencia_c.jsonl"; echo "}" >> "$SAIDA/latencia_c.jsonl"
done
: > "$SAIDA/tvla.jsonl"; for i in 1 2 3 4 5 6; do for m in 0 1 2; do taskset -c "$CPU" "$TMP/tvla" 100000 $m >> "$SAIDA/tvla.jsonl"; done; done
python3 "$AQUI/medir_python.py" > "$SAIDA/latencia_python.json"
python3 "$AQUI/paridade_c_python.py" > "$SAIDA/paridade_e_falhas.json"
python3 "$AQUI/ataque_square_3r.py" > "$SAIDA/ataque_square_3r.json"
python3 "$AQUI/comparativo_linear.py" > "$SAIDA/comparativo_linear.txt"
echo "Concluído. Saídas em: $SAIDA"

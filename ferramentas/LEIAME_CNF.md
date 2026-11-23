# Fórmulas CNF grandes

Os arquivos abaixo têm mais de 1 MB e **não ficam na árvore** do repositório. Cada release os publica como *asset* (`rsd-s-cnf-assets.tar.gz`), com a soma SHA-256 de cada arquivo conforme a tabela.

Eles também podem ser regenerados pelos scripts de `implementacao/` (`rsd_round_cnf.py`, `rsd_differential_cnf.py`, `analise_duas_rodadas.py`, `mds_xor_synthesis.py`). O arquivo pequeno `gf16_inverse.cnf` permanece na árvore.

| Arquivo | Bytes | SHA-256 |
| :--- | ---: | :--- |
| `mds_512.cnf` | 3.654.766 | `6d3caf8f6e2698519b368bdfa96a70e9667631b0da9d9f0724f6c0606a5898a4` |
| `rsd_diff_round1_compact_sat.cnf` | 3.778.893 | `ef123496395fbee9ff0b8bbf25c533d2a969d471abd6cc2a66fbd66dd2ca493d` |
| `rsd_diff_round1_compact_unsat.cnf` | 3.778.891 | `90bcab19b408602716975920caa30e72ae148e0c6dbd369b86b4e292f2be87a4` |
| `rsd_diff_round1_sat.cnf` | 10.563.299 | `d6712e9fa3d3fbad4e1a8b174788bb3606d4195690e07e1db9e6c9ca20121c25` |
| `rsd_diff_round1_unsat.cnf` | 10.563.298 | `4849c616c8975865b7abe6f4df5b4f903d5e4462275713ce7d6b9f4990113045` |
| `rsd_diff_round2_layer_sat.cnf` | 2.425.223 | `444e192bf7c6f701354c283f01bf1a6bbb5497820a86bda3bafe5986b7e1767e` |
| `rsd_diff_round2_layer_unsat.cnf` | 2.425.223 | `3139c9410baf9f1597d851c48495c6afd5288a23a73ce733734578d6503836a5` |
| `rsd_round1_fixed.cnf` | 5.046.780 | `4c74bc7e3beef34a4ae8ffd21694c4f606f33b659a0da00de54b6eab453fb977` |
| `rsd_round1_kat_sat.cnf` | 5.054.603 | `47640475214fe44978d5f8a187dc43839dfa328d77d0467f990398dd58e35d0b` |
| `rsd_round1_kat_unsat.cnf` | 5.054.604 | `efc75a1577a075d8aeac3de253e34e18d0710795356bb436ea12851015f1de6e` |

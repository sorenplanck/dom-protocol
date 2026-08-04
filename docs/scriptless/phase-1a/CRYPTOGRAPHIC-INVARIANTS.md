# Invariantes criptográficos de G1a

- Curva, scalars, pontos, parser SEC1, challenge, Schnorr, agregação, serialização e verificação vêm dos crates autoritativos da DOM.
- Nenhuma biblioteca ou implementação criptográfica paralela pode ser adicionada para substituir a DOM.
- O transcript e todas as pré-imagens precisam de encoding canônico congelado antes da implementação.
- Binding de dois nonces precisa comprometer todos os campos normativos e impedir substituição/reordenação silenciosa.
- Funding, Claim e Refund usam purposes fechados, versionados e separados por domínio.
- Todo hash passa pelo `blake2b_256_tagged` autoritativo e por tags presentes no registro congelado.
- Comparações de material secreto são constant-time; nonces, shares e segredos são zeroizados.
- Tipos secretos não implementam `Debug`, `Clone` ou serialização genérica salvo decisão explícita, estreita e auditada.
- Adaptação e extração são inversas somente sob as condições normativas congeladas e nunca aceitam scalar/ponto não canônico.
- A assinatura adaptada final precisa passar pelo verificador real da DOM.
- Fuzz, testes de fronteira e mutações falham fechados e não podem causar panic.

Nenhum desses invariantes é marcado como implementado nesta missão.

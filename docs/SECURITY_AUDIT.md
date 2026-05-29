# DOM Protocol — Auditoria de Segurança Pré-Mainnet
# Revisão Técnica v6.1 — Relatório Completo

---

## SEÇÃO 1 — CORREÇÃO CRIPTOGRÁFICA

---

### [CRÍTICO] — RFC-0001 — Schnorr: R_x ambíguo abre vetor de forjamento

**Problema técnico:**
A especificação define o challenge Schnorr como:

```
challenge = Blake2b-256(u16_le(len(tag)) || tag || R_x || public_key || message)
```

onde `R_x` é descrito como "x-coordinate of R". Porém, dois pontos distintos na curva secp256k1
compartilham o mesmo valor x (R e -R, diferindo apenas no bit de paridade y). A especificação
não define:
1. Se `R_x` são os 32 bytes da coordenada x (big-endian? little-endian?)
2. Se deve ser incluído o parity bit (bit 02/03 do encoding comprimido) ou só os 32 bytes
3. Como lidar com R.y = 0 (infinitamente improvável, mas precisa ser especificado)

Se duas implementações interpretarem R_x diferentemente (uma usa os 32 bytes crus da coordenada,
outra usa os 33 bytes do encoding comprimido), os challenges serão incompatíveis. Isso não é
forjamento direto, mas causa falha de verificação cruzada entre implementações — quebrando o
pressuposto de "independente reproduce" do genesis.

Mais grave: se R_x for tratado como 32 bytes sem paridade, um adversário que controla a mensagem
pode encontrar colisões onde R e -R produzem o mesmo challenge. Em protocolos Schnorr mal
especificados isso é explorado via "Wagner's generalized birthday attack" em cenários multi-party.

**Risco:** Incompatibilidade de implementação → fork de consenso silencioso. Em cenário MuSig2,
má definição de R_x pode abrir ataques de forjamento via manipulation de nonce commitment.

**Correção:**
```
R_x DEVE ser os 33 bytes do encoding comprimido SEC1 de R (incluindo parity byte 02 ou 03).
A especificação DEVE ser:

challenge = Blake2b-256(
  u16_le(len(tag)) ||
  tag ||
  R_compressed[33 bytes, SEC1] ||
  public_key_compressed[33 bytes, SEC1] ||
  message
)

R com y == 0 DEVE ser rejeitado durante signing (não pode ocorrer em prática mas
DEVE ser documentado como consensus-invalid nonce).
```

---

### [CRÍTICO] — RFC-0001 — MuSig2: transcript incompleto, vetor de Wagner

**Problema técnico:**
O MuSig2 transcript lista os campos a vincular mas não especifica:
1. A **ordem exata** de serialização dos campos no transcript
2. O **encoding** de cada campo (comprimento prefixado? fixo? variável?)
3. O **algoritmo de geração de nonce** para cada participante
4. O **número de rounds** (MuSig2 padrão usa 2 rounds de nonce, algumas variantes usam 1)

A omissão do algoritmo de nonce é crítica. MuSig2 com geração incorreta de nonce é vulnerável
ao ataque de Wagner: se um adversário pode fazer um signatário honesto assinar múltiplas sessões
concorrentes com nonces correlacionados, pode recuperar a chave privada.

RFC-0001 diz "partial signatures MUST NOT enter the mempool" mas não define o que constitui
uma "sessão" para fins de isolamento de nonce, nem como detectar reutilização de nonce.

**Risco:** Recuperação de chave privada via ataque de Wagner em cenário multi-signer.
Isso afeta diretamente qualquer carteira que use MuSig2 para construção interativa de transações.

**Correção:**
Adotar o MuSig2 paper (Nick, Ruffing, Seurin 2021) com geração de nonce determinística:
```
nonce_i = HKDF-SHA256(
  ikm = secret_key || aggregated_pubkey || message || session_id,
  info = "DOM:musig2-nonce:v1"
)
```
Especificar explicitamente: 2-round protocol, nonce binding to session_id, max 1 concurrent session
per key unless using different session_id.

---

### [CRÍTICO] — RFC-0001 / RFC-0000 — Coinbase sem Pedersen commitment: inflação silenciosa possível

**Problema técnico:**
A especificação define Pedersen commitments para outputs de transações normais mas não especifica
o tratamento de outputs de **coinbase** (block reward). Dois problemas distintos:

**Problema A — Commitment do coinbase:**
Em Mimblewimble, o minerador deve criar um output com commitment `C = r*G + v*H` onde `v` é o
valor do reward. Mas nenhum documento especifica:
- Qual é o blinding factor `r` para o output coinbase?
- Como é derivado de forma que o minerador prove ownership sem revelar `r` publicamente?
- O coinbase kernel é especial? Tem features flag diferente de kernels normais?

**Problema B — Verificação do valor coinbase:**
A equação de balanço do bloco é:
```
sum(output_commitments) - sum(input_commitments) = sum(kernel_excesses) + coinbase_commitment
```

Se `coinbase_commitment` não estiver especificado com precisão, um minerador pode criar um
commitment que esconde mais valor do que `INITIAL_BLOCK_REWARD >> epoch`. Isso é **inflação
silenciosa** — o mais grave dos ataques a uma criptomoeda.

RFC-0007 step 13 menciona "aggregate block balance equation" mas não especifica como o
coinbase value é incorporado na equação.

**Risco:** Inflação silenciosa arbitrária. Um minerador com conhecimento da lacuna pode
criar blocos com reward maior que o permitido.

**Correção:**
```
Definir explicitamente:

1. Coinbase kernel DEVE ter features = COINBASE_FLAG (ex: 0x01)
2. Coinbase kernel DEVE incluir explicit_value = block_reward (como u64, não commitado)
3. Equação de balanço do bloco:
   sum(output_commitments) - sum(input_commitments) - coinbase_output_commitment
   = sum(kernel_excesses) + r_offset * G
   
   Onde coinbase_output_commitment encobre exatamente explicit_value do coinbase kernel.
   
4. Validadores DEVEM verificar:
   coinbase_kernel.explicit_value == block_reward(block_height)
   
5. COINBASE_MATURITY = 1000 já está definido mas a regra de maturidade
   precisa estar explicitamente na seção de validação de INPUTS, não apenas como constante.
```

---

### [CRÍTICO] — RFC-0001 — Hash-to-Curve: expand_message_xmd com qual hash?

**Problema técnico:**
RFC-0001 e HashToCurve_RFC especificam:
- Método: `RFC9380-compatible hash_to_curve`
- DST: `DOM:h2c:secp256k1:v6.1`
- Expand message: `expand_message_xmd`

Mas **RFC9380 requer que expand_message_xmd seja parametrizado com um hash function específica**.
A especificação não define se usa SHA-256, SHA-512, ou Blake2b-256 para o expand_message.

RFC9380 Section 5.3 define:
```
expand_message_xmd(msg, DST, len_in_bytes, H)
```
onde H é o hash function. Para secp256k1, o hash recomendado pelo RFC9380 é SHA-256.

Se uma implementação usa SHA-256 e outra usa Blake2b-256, os valores de H serão diferentes —
todos os Pedersen commitments serão inválidos entre as implementações.

**Risco:** Fork de consenso na geração de H. Dado que H é o gerador para Pedersen commitments,
uma discrepância aqui invalida **todos os outputs** de uma das implementações.

**Correção:**
```
H DEVE ser gerado via:
hash_to_curve(
  msg = b"",  // empty message, conforme convenção para gerador estático
  DST = b"DOM:h2c:secp256k1:v6.1",
  hash_function = SHA-256,  // ESPECIFICAR EXPLICITAMENTE
  method = "simplified_swu_secp256k1"  // método correto para secp256k1 no RFC9380
)

Nota: secp256k1 usa o método "simplified SWU with isogeny" definido em RFC9380 Appendix G.
Não é o método genérico hash_to_curve — é o specializado para a curva.
```

---

### [CRÍTICO] — RFC-0001 — Bulletproofs+: crate não especificada, binding incompleto

**Problema técnico:**
RFC-0001 menciona "Bulletproofs+" e define range `0 <= value <= 2^64 - 1` mas não especifica:

1. Qual crate Rust implementa Bulletproofs+? (existe diferença entre `bulletproofs` da Dalek
   e implementações específicas para secp256k1 — elas NÃO são intercambiáveis)
2. O **transcript** do Bulletproof não está especificado. Bulletproofs usam Fiat-Shamir via
   transcript (Merlin ou protocolo ad-hoc). Se o transcript não for idêntico entre implementações,
   provas geradas por uma não serão verificáveis por outra.
3. O **aggregation factor**: Bulletproofs+ podem ser agregados (múltiplos outputs, uma prova).
   A especificação não define se DOM usa provas individuais por output ou agregadas por transação.
4. O **gerador H** usado no Bulletproof DEVE ser o mesmo H do Pedersen commitment. Se o Bulletproof
   usa um H interno diferente, o range proof não vincula ao commitment correto.

**Risco:** Provas geradas por uma implementação rejeitadas por outra → fork de consenso.
Pior: se o H do Bulletproof difere do H do Pedersen commitment, é possível criar commitments
que passam no range check mas encobrem valores fora do range → inflação.

**Correção:**
```
Especificar explicitamente:
1. Usar secp256k1-zkp (libsecp256k1 com módulo zkp) para Bulletproofs+
2. O gerador H nos Bulletproofs DEVE ser o mesmo H derivado via hash-to-curve
3. Transcript: definir exatamente a sequência de labels e dados no transcript Merlin
4. Provas são individuais por output (não agregadas) na versão 1.0
5. MAX_PROOF_SIZE = 4096 bytes: verificar se é suficiente para Bulletproofs+ simples
   (uma prova Bulletproofs+ para range [0, 2^64) em secp256k1 tem ~672 bytes,
   então 4096 é adequado, mas DEVE ser documentado)
```

---

### [IMPORTANTE] — RFC-0001 — Schnorr: ausência de "nonce reuse detection"

**Problema técnico:**
A especificação não define nenhum mecanismo para detectar ou prevenir reutilização de nonce
em assinaturas Schnorr de kernel simples (não-MuSig2). Nonce reuse em Schnorr é **catastrophic**:
se o mesmo `k` é usado duas vezes com mensagens diferentes:
```
s1 = k + c1 * sk   (mod n)
s2 = k + c2 * sk   (mod n)
s1 - s2 = (c1 - c2) * sk  (mod n)
sk = (s1 - s2) * inverse(c1 - c2)  (mod n)
```
A chave privada é recuperada diretamente.

**Risco:** Recuperação de chave se a implementação de carteira reutilizar nonce.

**Correção:**
Especificar geração de nonce determinística RFC 6979 para todos os kernels:
```
k = RFC6979-HMAC-SHA256(sk, message || chain_id)
```
E documentar como CONSENSUS RULE que kernels com assinaturas inválidas (inclui reutilização
detectável a posteriori via análise) são rejeitados.

---

### [IMPORTANTE] — RFC-0001 — Pedersen: offset não está definido como binding

**Problema técnico:**
A estrutura Transaction inclui um campo `offset` (32 bytes) que é o "kernel offset" de
Mimblewimble. O propósito do offset é separar a relação entre inputs/outputs e kernels para
prevenir graph analysis. Mas a especificação não define:

1. Como o `offset` é gerado (aleatório? derivado?)
2. Como o `offset` se acumula no `total_kernel_offset` do BlockHeader
3. A equação de balanço **com offset** explicitamente:
   ```
   sum(output_commits) - sum(input_commits) = sum(kernel_excesses) + offset * G
   ```
4. Se o offset do coinbase é zero (deve ser)

Sem o offset bem especificado, implementações podem omiti-lo, quebrando a privacidade do
graph analysis protection que é um dos pontos-chave do Mimblewimble.

**Correção:**
```
Definir:
1. tx.offset é gerado uniformemente aleatório em [1, n-1] pelo sender
2. block.total_kernel_offset = sum(tx.offset for tx in block) mod n
3. Equação de balanço do bloco DEVE incluir o offset:
   sum(outputs) - sum(inputs) = sum(kernel_excesses) + total_kernel_offset * G
4. Coinbase tx.offset DEVE ser zero (ou ausente)
```

---

## SEÇÃO 2 — CONSISTÊNCIA DO PROTOCOLO

---

### [CRÍTICO] — RFC-0007 vs v6.1_Validation_Pipeline — Ordens de validação contraditórias

**Problema técnico:**
Dois documentos definem a ordem de validação de transações com ordens **diferentes**:

**RFC-0007 (normativo):**
1. canonical decode
2. primitive validation
3. scalar validation
4. point validation
5. duplicate detection
6. Bulletproofs+ validation
7. kernel signature validation
8. fee calculation
9. weight calculation
10. transaction balance equation

**v6.1_Validation_Pipeline (arquivo):**
1. decode
2. scalar validation
3. Bulletproof validation
4. signature validation
5. balance equation
6. duplicate rejection
7. weight validation

As diferenças são:
- Duplicate detection: step 5 no RFC-0007, step 6 na Pipeline
- Balance equation: step 10 no RFC-0007, step 5 na Pipeline
- Weight validation: step 9 no RFC-0007, step 7 na Pipeline
- Fee calculation: existe no RFC-0007, **ausente** na Pipeline

Um desenvolvedor lendo apenas o Pipeline implementará validação fora de ordem, criando
divergência de consenso com implementações que seguem RFC-0007.

**Risco:** Fork de consenso. Dois nós podem aceitar/rejeitar a mesma transação dependendo
de qual documento seguiram.

**Correção:**
Deprecar explicitamente v6.1_Validation_Pipeline e marcar RFC-0007 como único normativo.
Adicionar ao RFC-0007: "Este documento supersede DOM_v6_1_Validation_Pipeline.md".

---

### [CRÍTICO] — RFC-0000 — MAX_BLOCK_WEIGHT sem definição de "weight unit"

**Problema técnico:**
`MAX_BLOCK_WEIGHT = 40000` e `MAX_TX_WEIGHT = 4000` estão definidos mas a especificação
**nunca define o que é um "weight unit"**. Como calcular o weight de:
- Um input?
- Um output (com range proof)?
- Um kernel?
- O block header?

Bitcoin define weight como: `base_size * 3 + total_size`. Sem uma definição equivalente
para DOM, cada implementação inventará sua própria fórmula, tornando os limites
não-determinísticos → fork de consenso.

**Risco:** Um nó aceita um bloco como válido (weight calculado de uma forma) enquanto
outro rejeita (weight calculado diferente). Fork de consenso imediato.

**Correção:**
```
Definir explicitamente:
weight(input) = 1
weight(output) = 21  // commitment(33) + proof overhead
weight(kernel) = 3   // features(1) + fee(8) + lock_height(8) + excess(33) + sig(65)
weight(tx) = sum(weight(input)) + sum(weight(output)) + sum(weight(kernel))

Ou usar serialized_bytes / 100 como proxy simples.
QUALQUER definição é aceitável, mas DEVE existir uma definição única.
```

---

### [RESOLVIDO] — RFC-0000 — DOM-ASERT-288 half-life definido por blocos

**Estado atual:**
`TARGET_SPACING = 120 seconds`.
`ASERT_HALF_LIFE_BLOCKS = 288`.
`ASERT_HALF_LIFE = 34,560 seconds`.

O parâmetro ativo agora é derivado por blocos, não por uma duração herdada.
Isso mantém a regra pública DOM-ASERT-288 explícita: 288 blocos de 120 segundos
por half-life. O anchor ASERT também é determinístico:
- `anchor_height = 0`
- `anchor_timestamp = GENESIS_TIMESTAMP` da rede
- `anchor_target = GENESIS_TARGET` da rede

**Risco residual:** mudanças futuras em `TARGET_SPACING` devem revisar
`ASERT_HALF_LIFE_BLOCKS` e o valor derivado em segundos no mesmo conjunto de
mudanças, porque ambos são consenso crítico.

**Correção aplicada:**
```
1. Publicar ASERT_HALF_LIFE_BLOCKS = 288.
2. Derivar ASERT_HALF_LIFE = TARGET_SPACING * ASERT_HALF_LIFE_BLOCKS.
3. Validar que o valor final é ASERT_HALF_LIFE = 34,560 seconds.
```

---

### [IMPORTANTE] — RFC-0000 / RFC-0007 — COINBASE_MATURITY sem regra de aplicação

**Problema técnico:**
`COINBASE_MATURITY = 1000` está definido em RFC-0000 mas **nenhuma seção de validação**
menciona como e quando aplicá-la. RFC-0007 lista os passos de validação de transação mas
nenhum passo verifica se um input está gastando um coinbase imaturo.

A maturidade deve ser verificada em: step 2 (primitive validation) ou step 3 (scalar validation)?
Qual erro retornar — `Invalid` ou `TemporarilyInvalid`? (Deveria ser `TemporarilyInvalid` pois
o output se tornará válido após 1000 blocos.)

**Risco:** Um nó que não verifica maturidade aceita gastos prematuros de coinbase,
permitindo double-spends de recompensas.

**Correção:**
Adicionar ao RFC-0007 step 2 (primitive validation):
```
Para cada input:
  SE input.commitment referencia coinbase output:
    SE current_height - coinbase_block_height < COINBASE_MATURITY:
      RETORNAR TemporarilyInvalid("coinbase not yet mature")
```

---

### [IMPORTANTE] — RFC-0007 — "Total difficulty validation" (step 7) não está definida

**Problema técnico:**
O passo 7 do block validation é "total difficulty validation" mas a especificação nunca
define como calcular ou verificar `total_difficulty`. Questões abertas:
1. Como é o `total_difficulty` do bloco genesis? (1? target_to_difficulty(genesis_target)?)
2. Como se acumula? (`prev.total_difficulty + difficulty(block.target)`?)
3. Como converter compact target para difficulty? (inverse of target value?)
4. É chain selection por maior `total_difficulty` ou por maior `total_work`?

**Risco:** Implementações diferentes calcularão `total_difficulty` diferente, causando
chain selection incorreta em reorganizações.

**Correção:**
```
Definir:
difficulty(target) = MAX_TARGET / target  (256-bit integer division)
block_difficulty = difficulty(block.target)
block.total_difficulty = parent.total_difficulty + block_difficulty
genesis.total_difficulty = difficulty(genesis_target)

Chain selection: escolher a cadeia com maior total_difficulty.
```

---

### [MENOR] — RFC-0004 — PMMR: separação entre output_root, kernel_root e rangeproof_root ausente

**Problema técnico:**
O BlockHeader tem três PMMR roots: `output_root`, `kernel_root`, `rangeproof_root`. Mas
RFC-0004 define apenas um PMMR genérico. A especificação não define:
1. Qual é o payload de cada PMMR (o que é hasheado como folha em cada um?)
2. Os três PMMRs usam os mesmos tags ou tags distintos?
3. A relação entre output_root e rangeproof_root (são sincronizados? mesmos índices?)

**Correção:**
```
output PMMR leaf = leaf_hash(pos, output.commitment_bytes[33])
kernel PMMR leaf = leaf_hash(pos, kernel.serialized_bytes)
rangeproof PMMR leaf = leaf_hash(pos, output.proof_bytes)

Todos os três PMMRs usam as mesmas tags definidas em RFC-0004.
Indices são sincronizados: output[i] e rangeproof[i] correspondem ao mesmo output.
```

---

## SEÇÃO 3 — SEGURANÇA DA REDE P2P

---

### [CRÍTICO] — RFC-0005 — Handshake Noise_XX sem binding ao chain_id no KDF

**Problema técnico:**
RFC-0005 especifica `Noise_XX_25519_ChaChaPoly_BLAKE2s` mas não define como o `chain_id`
é vinculado ao handshake criptográfico. O documento diz "Rejeitar invalid chain_id" mas
isso implica que o chain_id é enviado **em cleartext** e rejeitado depois do handshake,
não que está vinculado criptograficamente ao canal Noise.

Um adversário pode fazer um MITM attack:
1. Interceptar a conexão entre dois nós DOM
2. Completar o handshake Noise (sem chain_id binding criptográfico)
3. Encaminhar mensagens modificadas

O Noise protocol suporta "prologue" que pode incluir o chain_id como parte do KDF,
fazendo com que qualquer modificação seja detectável. A especificação não usa isso.

**Risco:** Man-in-the-middle attack na rede P2P. Não quebra o consenso diretamente
mas permite eclipse attacks e manipulação de propagação de transações.

**Correção:**
```
Usar Noise prologue para binding criptográfico:
prologue = "DOM" || u32_le(PROTOCOL_VERSION) || u32_le(network_magic) || chain_id[32]

O prologue é incluído no KDF do Noise handshake, tornando qualquer modificação
detectável como falha de verificação do MAC.
```

---

### [CRÍTICO] — RFC-0005 — Eclipse attack: ausência de peer diversity requirements

**Problema técnico:**
RFC-0005 não define nenhum requisito de diversidade de peers para proteção contra eclipse
attacks. Especificamente ausentes:
1. Número mínimo de outbound connections
2. Distribuição por /16 ou ASN para evitar concentração
3. Proteção contra "addr flooding" (um adversário envia milhares de endereços controlados)
4. Eviction policy para slots de peers

Dado que DOM é uma moeda nova com poucos nós, eclipse attacks são extremamente fáceis:
controlar 8 conexões de um nó é suficiente para isolá-lo completamente.

**Risco:** Eclipse attack → apresentar ao nó eclipsado uma chain falsa → double-spend
em transações de alto valor.

**Correção:**
```
Especificar:
MIN_OUTBOUND_CONNECTIONS = 8
MAX_INBOUND_CONNECTIONS = 125
MAX_PEERS_SAME_SLASH_16 = 2  // máximo 2 peers da mesma /16
ADDR_RATE_LIMIT = 100 addrs/hour per peer
FEELER_CONNECTIONS = 2  // conexões periódicas para testar novos peers
```

---

### [IMPORTANTE] — RFC-0005 — DNS seeds: único ponto de falha e vetor de ataque

**Problema técnico:**
A especificação menciona "DNS seeds" mas não define:
1. Quais são os DNS seeds (domínios hardcoded)
2. Quantos seeds mínimos para não ser SPOF
3. DNSSEC está sendo usado?
4. Mecanismo de fallback se todos os DNS seeds estiverem inacessíveis
5. Seeder authority: quem controla os DNS seeds? (centralização!)

Para uma moeda que rejeita toda autoridade central, seeds DNS controlados por uma
entidade são uma contradição arquitetural e um ponto único de ataque.

**Risco:** Atacante que controla os DNS seeds pode envenenar o processo de discovery
e conectar novos nós apenas a peers hostis (eclipse at bootstrap).

**Correção:**
```
1. Definir mínimo 5 DNS seeds controlados por entidades independentes
2. Adicionar seed list hardcoded (IP addresses de nós conhecidos) como fallback
3. Implementar addr-based peer exchange (GETADDR/ADDR) para autonomia pós-bootstrap
4. Documentar processo de governance para adicionar/remover DNS seeds
```

---

### [IMPORTANTE] — Ausência total de especificação de "headers-first sync"

**Problema técnico:**
A especificação define GET_HEADERS e HEADERS no wire protocol mas não especifica o
**algoritmo completo de Initial Block Download (IBD)**. Questões não respondidas:
1. Como um novo nó baixa a blockchain? (headers-first? blocks-first?)
2. Qual é o critério para considerar um headers chain "válido o suficiente" para
   começar baixar blocos?
3. Como o nó sabe qual é a "melhor cadeia" antes de baixar todos os blocos?
4. Existe checkpoint hardcoded para acelerar o IBD inicial?
5. Como o nó detecta que atingiu o "chain tip"?

**Risco:** Sem IBD bem definido, um nó novo pode ser enganado para baixar e verificar
uma cadeia longa de baixo trabalho (low-work chain) — ataque de CPU DoS.

**Correção:**
Adicionar RFC sobre IBD definindo:
- Headers-first sync obrigatório
- Minimum work checkpoint (hardcoded total_difficulty no genesis)
- Download paralelo de blocos após verificação de headers
- Stalling detection (peer que não responde em N segundos → disconnect)

---

## SEÇÃO 4 — MODELO MIMBLEWIMBLE

---

### [CRÍTICO] — Cut-Through: kernels não são mencionados na equação de validação pós-cut-through

**Problema técnico:**
A definição de cut-through no Glossário é:
"Removal of matching spent-created outputs while preserving kernels and offsets."

RFC-0007 step 10 é "deterministic cut-through" mas não especifica a equação de
verificação **após** o cut-through. O problema: após o cut-through, o balanço da
transação residual deve ainda satisfazer:

```
sum(remaining_outputs) - sum(remaining_inputs) = sum(ALL_kernels_excesses) + total_offset * G
```

Mas se outputs e inputs foram removidos mas os kernels correspondentes foram preservados,
a equação muda. A especificação não documenta isso explicitamente.

Mais crítico: RFC-0007 step 9 é "duplicate detection across block" e step 10 é
"deterministic cut-through". Mas a ordem está errada: você deve fazer cut-through
**antes** de detectar duplicatas, ou detectar duplicatas na set **antes e depois**?

RFC-0000 diz "Reject duplicates before and after cut-through" — mas qual RFC-0007
implementa isso? Step 9 é só uma vez, não duas.

**Risco:** Uma implementação que detecta duplicatas apenas antes do cut-through
aceita uma transação que cria o mesmo output duas vezes (uma é cortada, mas a
outra sobrevive) — potencial vetor de inflação.

**Correção:**
```
Reorganizar RFC-0007 steps 9 e 10:
  9. Duplicate detection ANTES do cut-through
  10. Deterministic cut-through
  10b. Duplicate detection APÓS o cut-through  ← adicionar este step
  11. PMMR update
  12. ...
  
E definir explicitamente a equação de balanço pós-cut-through.
```

---

### [CRÍTICO] — Stealth Addresses: não especificadas

**Problema técnico:**
O whitepaper DOM menciona "Stealth Addresses" como feature de privacidade. RFC-0001 e
todos os documentos técnicos **não contêm nenhuma especificação de stealth addresses**.

Questões completamente abertas:
1. DOM usa stealth addresses? (DH key exchange para derivação de endereço único por tx?)
2. Qual é o protocolo exato? (ECDH com curva secp256k1? qual KDF?)
3. Como o recipient scana a blockchain para encontrar seus outputs?
4. O "scan key" e o "spend key" são separados?

Mimblewimble puro não tem endereços — as transações são interativas (wallet slate).
Mas a interatividade remove a possibilidade de pagamentos não-interativos (onchain
address scanning). A especificação não resolve essa tensão fundamental.

**Risco:** Sem stealth addresses especificadas, a única forma de receber pagamentos
é via interactive wallet slate — inaceitável para adoção como moeda real (não dá
para dar um "endereço de pagamento" estático).

**Correção:**
Decidir explicitamente entre:
```
Opção A: Pure Mimblewimble (sem stealth addresses, apenas interactive)
  - Documentar que todos os pagamentos são interativos via slate
  - Definir o protocolo de slate completo

Opção B: Stealth addresses via ECDH (como Grin usa)
  - Definir: spend_pubkey, scan_pubkey (derivados de seed)
  - Definir: one-time address derivation via ECDH(scan_key, sender_nonce)
  - Definir: scanning protocol (how receiver finds their outputs)
  
Opção C: Non-interactive payments via receiver-published nonces
  - Definir completamente
```

---

### [IMPORTANTE] — Transaction Interactivity: wallet slate incompleta

**Problema técnico:**
O Wallet Slate RFC define apenas "minimum fields":
- amount, fee, participant data, partial signatures, kernel excess

Mas não define:
1. O **protocolo de troca** (quantos rounds? round 1: sender propõe, round 2: receiver assina?)
2. O **formato de serialização** da slate (JSON? binário? qual versão?)
3. Como prevenir **slate replay** (um slate assinado pode ser reenviado múltiplas vezes?)
4. Como o receiver valida que o sender não está propondo outputs que conflitam com UTXOs existentes?
5. **Timeout**: se o receiver não responde, os blinding factors do sender ficam "presos"?

**Risco:** Sem protocolo de slate completo, implementações de carteiras serão
incompatíveis entre si. Isso fragmenta o ecossistema antes de começar.

---

### [IMPORTANTE] — Fungibilidade: vetor de rastreamento residual via kernel

**Problema técnico:**
Mimblewimble garante que o grafo de transações é irrecuperável após cut-through.
Mas **kernels sobrevivem para sempre**. Os kernels contêm:
- `lock_height`: se não zero, revela informação temporal
- `fee`: o fee de cada transação fica permanentemente visível
- `features`: distingue coinbase de transações normais

Um adversário que monitora a rede P2P durante a propagação pode correlacionar
timestamps de chegada de transações com kernels — antes do cut-through acontecer.
Esta é a "timing attack on Mimblewimble" documentada na literatura.

Mais específico: a especificação não define **dandelion++ routing** para transações.
Sem dandelion, a fonte de uma transação é trivialmente identificável pelo timing de
propagação na rede.

**Risco:** Quebra parcial de privacidade via correlação temporal. Não é catastrófico
mas contradiz a promessa de "untraceable" do whitepaper.

**Correção:**
```
Adicionar RFC para Dandelion++ routing:
- Stem phase: encaminhar para 1 peer aleatório com probabilidade de transição
- Fluff phase: broadcast normal
- Stem timeout: se stem phase demora muito, transitar para fluff automaticamente
```

---

## SEÇÃO 5 — IMPLEMENTABILIDADE EM RUST

---

### [CRÍTICO] — Crates incompatíveis: secp256k1 vs secp256k1-zkp para Bulletproofs

**Problema técnico:**
O workspace Cargo.toml usa `secp256k1 = "0.28"` para operações de chave. Mas
Bulletproofs+ em secp256k1 requer `secp256k1-zkp` (o fork da Blockstream com
módulos criptográficos adicionais). Estes são **crates distintos** com APIs distintas
e não podem ser usados simultaneamente sem wrapper cuidadoso.

O `secp256k1 = "0.28"` não expõe:
- Pedersen commitment arithmetic
- Bulletproof generation/verification
- Surjection proofs

Sem `secp256k1-zkp`, é impossível implementar os Pedersen commitments e Bulletproofs
necessários para o protocolo. A implementação atual em `dom-crypto/src/pedersen.rs`
tem um `Commitment` type mas NENHUMA aritmética de commitment — você não pode fazer
`C1 + C2` ou `v*H + r*G` com a crate atual.

**Risco:** A estrutura do projeto como definida não pode compilar um nó DOM funcional.
Todo o modelo de privacidade requer aritmética que está ausente das dependências declaradas.

**Correção:**
```toml
# Adicionar ao Cargo.toml
secp256k1-zkp = { version = "0.9", features = [
    "global-context",
    "rand-std",
    "use-serde",
    "musig",
    "bulletproofs",
    "pedersen",
] }
```

---

### [CRÍTICO] — RandomX: crate não especificada em nenhum documento

**Problema técnico:**
O algoritmo de PoW é RandomX (documentado no whitepaper e nos RFCs) mas **nenhum
documento técnico menciona qual crate Rust usar para RandomX**. As opções são:
1. `randomx-rs` — binding do C++ original, auditado, mas depende de build system complexo
2. Implementação pura Rust — não existe ainda (RandomX é extremamente complexo)

`randomx-rs` tem dependências de build que podem ser problemáticas no WSL2 do Windows.
Além disso, a versão do RandomX usada DEVE ser fixada (RandomX teve mudanças de consenso
em seu histórico).

A especificação também não define:
1. Qual é o RandomX seed para o genesis block?
2. Como o seed muda ao longo da cadeia? (RandomX usa um seed que muda a cada N blocos)
3. Qual é o intervalo de rekey do RandomX seed?

**Risco:** Sem RandomX especificado, a validação de PoW não pode ser implementada.
Sem seed schedule, nós podem ter datasets diferentes → rejeição cruzada de blocos válidos.

**Correção:**
```
Adicionar RFC para RandomX:
1. Crate: randomx-rs (com versão pinada)
2. Seed = Blake2b-256 do hash do bloco N-2048 (ou genesis hash para primeiros 2048 blocos)
3. Seed rotation: a cada 2048 blocos
4. Full mode vs Light mode: nós completos usam Full mode (2GB RAM), light clients usam Light mode
```

---

### [IMPORTANTE] — LMDB/RocksDB: storage backend não especificado

**Problema técnico:**
`dom-store` é um stub. Nenhum documento especifica qual storage backend usar.
Para consenso, o storage é crítico: um crash durante um write pode corromper o estado.
O requisito de "atomic state commit" (RFC-0007 step 14) exige transações ACID no storage.

LMDB tem semântica MVCC mas não suporta transações que cruzam múltiplos databases bem.
RocksDB é mais comum em blockchains mas a API Rust (`rocksdb` crate) tem overhead.

**Correção:**
Especificar storage backend, schema de chaves, e protocolo de recovery após crash.

---

### [IMPORTANTE] — Dependências circulares potenciais no workspace

**Problema técnico:**
A ordem de dependências no workspace tem um problema potencial:
- `dom-consensus` depende de `dom-pmmr`, `dom-crypto`, `dom-pow`
- `dom-chain` (stub) precisará de `dom-consensus` E `dom-store`
- `dom-mempool` precisará de `dom-consensus` E `dom-chain`

Mas a relação entre `dom-chain` e `dom-tx` não está clara. Se `dom-tx` (construção
de transações) precisar de informações do estado atual (para verificar UTXOs),
ele precisará de `dom-chain` → potencial ciclo se `dom-chain` importar `dom-tx`.

**Correção:**
Definir explicitamente o DAG de dependências antes de implementar os stubs.

---

## SEÇÃO 6 — LACUNAS E OMISSÕES CRÍTICAS

---

### [CRÍTICO] — Ausência completa de especificação de "chain_id"

**Problema técnico:**
`chain_id` é mencionado em pelo menos 8 lugares diferentes nos RFCs como campo
crítico para replay protection e peer filtering. Mas **nenhum documento define**:
1. O que é o `chain_id` (32 bytes? hash do genesis?)
2. Como é calculado
3. Quando é calculado (antes ou depois do genesis?)
4. Como está disponível antes do genesis ser finalizado

RFC-0006 lista `chain_id` como campo obrigatório do genesis artifact mas não define
como derivá-lo. RFC-0001 diz que o MuSig2 transcript "MUST bind chain_id" — mas se
chain_id não está definido, o transcript não pode ser implementado.

**Correção:**
```
chain_id = Blake2b-256(
  network_magic || genesis_timestamp || genesis_target || "DOM:chain-id:v1"
)

Calculado deterministicamente dos parâmetros do genesis.
Disponível após finalização do genesis artifact.
```

---

### [CRÍTICO] — Ausência de especificação de "fee" no contexto Mimblewimble

**Problema técnico:**
Em Mimblewimble, a fee está no kernel (visível publicamente). Mas a especificação não define:
1. Como a fee é **verificada** — como o validador sabe que a fee declarada no kernel
   corresponde à diferença entre inputs e outputs?
2. Quem recebe a fee? (o minerador? como?)
3. A fee entra no coinbase commitment?

A equação de balanço Mimblewimble com fee é:
```
sum(outputs) - sum(inputs) = excess + fee * H
```
Mas se `fee * H` for omitido da equação, um usuário pode declarar fee = X mas
na verdade a equação balança com fee = 0, pagando zero fee para o minerador.

**Risco:** Zero-fee transactions que aparecem como fee-paying → mineradores não
têm incentivo real para incluir transações.

**Correção:**
```
Definir explicitamente:
1. Equação de balanço inclui fee:
   sum(outputs) - sum(inputs) = sum(kernel_excesses) + total_offset * G + total_fee * H
   
2. Minerador inclui sum(all_tx_fees) no valor do coinbase kernel.
3. Validadores verificam: coinbase.explicit_value == block_reward(height) + sum(tx_fees)
```

---

### [IMPORTANTE] — Ausência de especificação de "lock_height" e "relative timelock"

**Problema técnico:**
`lock_height` está no kernel (especificado) mas as regras de validação não definem:
1. Um kernel com `lock_height > current_height` deve causar `TemporarilyInvalid` ou `Invalid`?
2. Existe relative timelock (N blocos após criação do output) além de absolute timelock?
3. Como lock_height interage com COINBASE_MATURITY?

**Correção:**
Adicionar ao RFC-0007 step 2:
```
Para cada kernel com lock_height > 0:
  SE lock_height > current_height:
    RETORNAR TemporarilyInvalid("kernel locked until height {lock_height}")
```

---

### [IMPORTANTE] — Ausência de "compact block" e propagação eficiente

**Problema técnico:**
Com blocos de 30 minutos e até 5000 transações por bloco, um bloco pode ter
múltiplos megabytes. O wire protocol só define `GET_BLOCK`/`BLOCK` sem nenhuma
forma de propagação compacta. Nós que já têm as transações no mempool
receberão o bloco completo novamente.

Bitcoins "compact blocks" (BIP 152) reduzem a propagação de blocos em ~98%.
Sem algo equivalente, DOM terá alta latência de propagação de blocos —
aumentando orphan rate e favorecendo pools grandes.

---

### [IMPORTANTE] — Ausência de definição de "script" / "kernel features"

**Problema técnico:**
`kernel.features` é um campo u8 mas os valores possíveis nunca são definidos:
- 0x00 = plain kernel?
- 0x01 = coinbase?
- 0x02 = height-locked?
- outros?

Sem esta tabela, implementações criarão valores incompatíveis.

**Correção:**
```
KERNEL_FEAT_PLAIN     = 0x00
KERNEL_FEAT_COINBASE  = 0x01  
KERNEL_FEAT_HEIGHT_LOCKED = 0x02
KERNEL_FEAT_NO_RECENT_DUPLICATE = 0x04  (para relative timelock futuro)

Valores não listados: consensus-invalid.
```

---

## AVALIAÇÃO FINAL

---

### Maturidade da Especificação: 4/10

A especificação tem uma base sólida em algumas áreas (PMMR, serialização, constantes)
mas tem lacunas críticas que tornam uma implementação segura impossível no estado atual.

**Problemas que impedem qualquer implementação segura:**
1. Equação de balanço Mimblewimble incompleta (sem fee, sem offset)
2. Coinbase commitment não especificado (vetor de inflação)
3. Hash-to-curve com hash function não especificada
4. chain_id não definido
5. Weight units não definidos

**Os 3 Problemas Mais Urgentes (resolver antes de qualquer implementação):**

**#1 — Inflação Silenciosa via Coinbase Não Especificado**
É o único vetor que pode destruir completamente a moeda. Um minerador pode criar
coins em excesso se a equação de balanço do coinbase não estiver explicitamente
definida com verificação do explicit_value. Prioridade absoluta.

**#2 — Equação de Balanço Incompleta (fee e offset ausentes)**
Sem a equação completa com fee e offset, o modelo Mimblewimble não funciona
corretamente. Todo o modelo de privacidade e fungibilidade depende desta equação
estar correta.

**#3 — Hash-to-Curve: hash function não especificada**
H é o gerador de todos os Pedersen commitments. Se duas implementações gerarem
H diferentes (uma com SHA-256, outra com Blake2b), todos os commitments serão
incompatíveis. Este é o primeiro problema a resolver pois bloqueia todos os outros.

---

### Esta Especificação Está Pronta para um Desenvolvedor Rust Sênior?

**Não.**

Um desenvolvedor Rust sênior com experiência em blockchain conseguiria implementar
os módulos de serialização, PMMR e constantes com o que existe. Mas não conseguiria
implementar um nó funcional e seguro porque:

1. A equação de balanço central do protocolo não está completa
2. As primitivas criptográficas têm ambiguidades que causariam fork de consenso
3. O protocolo P2P tem lacunas de segurança que tornariam o nó trivialmente eclipsável
4. O coinbase não está especificado — qualquer implementação seria vulnerável a inflação

O que está pronto para entrega a um desenvolvedor sênior:
- dom-core (constantes)
- dom-serialization (encoding)
- dom-pmmr (com os vetores obrigatórios)
- A estrutura do workspace

O que requer trabalho de especificação adicional antes de implementação:
- Todo o modelo criptográfico Mimblewimble
- O algoritmo ASERT completo (lookup table)
- O protocolo P2P completo
- O protocolo de slate/carteira

**Estimativa para chegar a spec-ready: 6-8 semanas de trabalho de especificação.**

---

## SEÇÃO 7 — INTERNAL HARDENING FINDINGS (post-audit)

---

### [CRÍTICO — RESOLVED] DOM-PMMR-001 — Silent Leaf Mutation in `Pmmr::push`

**Severidade:** CONSENSUS-CRITICAL — silent chainstate corruption primitive.

**Componente:** `crates/dom-pmmr/src/lib.rs::Pmmr::push` + `node_height`.

**Status:** ✅ RESOLVED — commits `bcd59ad` (fix), `91f78ed` (adversarial
suite), `151acbe` (miner / validator contract), `2994048` (pinned vectors),
RFC-0004 normative spec (this commit).

**Problema técnico:**

Duas defeitos colaboravam para reduzir `root()` de qualquer MMR multi-folha a
uma única peak hash dependendo apenas da última folha:

1. `node_height(pos)` lia `pos.trailing_ones()` diretamente. A altura postorder
   correta é o índice do most-significant bit após left-jumping até
   `is_all_ones`. Alturas em posições 1, 3, 5, 7, … saíam um nível alto demais,
   fazendo o check de altura-igual dentro de `merge_peaks` falhar sempre e
   suprimindo todo merge.

2. `push` colocava cada nova folha na posição igual à *contagem pós-insert* de
   nós. Isso equipara a folha nova ao slot de parent que deveria ter sido
   produzido pelo merge — e o merge é suprimido por (1).

Combinados, o `bag_peaks` reduzia ao final a uma única peak que carregava só
informação da última folha. Qualquer minerador podia reescrever folhas
históricas (UTXO set / kernel set) sem alterar os roots committados — primitive
direto de forjamento de chainstate.

**Vetor de explotação (assumindo PMMR bugado em produção):**

- Atacante mineira um bloco com tx forjada (gastando UTXO que não possui).
- Roots no header se baseiam só na última folha de cada MMR.
- Nó honesto recomputa roots → bate (porque ambos usam o mesmo algoritmo
  bugado).
- Forgia aceita, supply violada, balance equation impossível de verificar
  independentemente.

**Correção:**

Substituição direta do algoritmo de altura por Grin's `bintree_postorder_height`
(jump_left até `is_all_ones`, retorna `msb_pos - 1`). `leaf_pos` agora é
`nodes_before(n) + 1` calculado da contagem *pré*-insert. `set_node` adicionou
guard contra overwrite — append-only é invariante de consenso e overwrite
silencioso é tratado como `DomError::Internal`.

**Evidência de validação:**

| Item | Cobertura | Crate / arquivo |
|---|---|---|
| Reproducer determinístico (Phase A) | 7 testes | `dom-pmmr/tests/silent_mutation_reproducer.rs` |
| Adversarial suite com oráculo independente (Phase D) | 10 testes, ~42s | `dom-pmmr/tests/adversarial_suite.rs` |
| Tabela postorder pinada (1..=15) | 1 teste | `dom-pmmr/src/lib.rs::tests::node_height_matches_postorder_table` |
| Overwrite guard | 1 teste | `dom-pmmr/src/lib.rs::tests::set_node_overwrite_is_rejected` |
| Contrato miner ↔ validator (Phase C) | 5 testes | `dom-consensus/src/lib.rs::tests::*pmmr_roots*` |
| Pinned RFC-0004 hex vectors (Phase E) | 1 teste, 9 vetores | `dom-test-vectors/src/pmmr_vectors.rs::tests::vectors_match_pinned_hex` |

**Gaps remanescentes (uncertainty-tracked):** ver RELEASE_BLOCKERS.md sob
"DOM-PMMR-001 deferred validation". Cross-platform equivalence (Phase 1.4),
interrupted-flush PMMR-specific harness (Phase 3.2 extension) e long-running
replay-after-restart re-execution na implementação corrigida (replay_determinism
sobre VPS dedicado) não são executáveis na infraestrutura atual e estão
documentados como gaps explícitos, não fechados.

**Confidence:**
- **Confirmed:** o bug existia, foi reproduzido, a correção altera todos os
  roots multi-folha para os valores corretos hand-computed.
- **Confirmed:** o algoritmo Grin-derived produz a tabela postorder canônica
  e atende todos os property tests do oráculo independente.
- **Likely:** replay determinism preservada — o algoritmo é puramente
  determinístico em (`leaf_count`, `payloads`), igual antes; o que mudou foi o
  layout interno. Confirmação empírica requer rerun de `replay_determinism`
  em ambiente capaz de mining sustentado.
- **Theoretical (sem evidência empírica nesta sessão):** equivalência
  cross-platform entre Linux x86_64 / Windows / macOS / ARM64.

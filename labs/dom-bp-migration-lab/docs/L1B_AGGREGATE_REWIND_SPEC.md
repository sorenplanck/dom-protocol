# L1-B — especificação e experimento de rewind agregado

## Escopo e resultado

Esta análise trata somente do formato de consenso vivo: Bulletproof clássico
Grin, `nbits=64`, `n_commits=2`, 739 bytes, gerador `H_DOM` e commitments
`[C0, C1]`. Nenhum backend, símbolo C, parser, verificador ou arquivo de
produção foi modificado.

**CONFIRMADO:** o formato agregado vivo não é recuperável de modo total para
`(value, r, metadata)` sob a API de recovery proposta. A classificação desta
fase é `B_NOT_RECOVERABLE_FROM_CURRENT_AGGREGATION`.

O impedimento matemático é independente de implementação:

```
C0 = vH + rG
C1 = (M-v)H - rG

blind_term(taux) = z²r + z³(-r) = z²(1-z)r.
```

O verificador só rejeita `z=0`; ele não rejeita `z=1`. Para `z=1`, o termo de
`r` em `taux` é zero, portanto nenhum cálculo a partir de `proof`, commitments,
nonces e transcript pode recuperar `r`: `taux` é independente de `r` depois de
remover as máscaras `tau1*x + tau2*x²`. Recomputar `C0` exige o log discreto de
`C0-vH` na base `G`, que é inviável por desenho. O modelo falha fechado nesse
caso.

## Formato DOM e evidência de código

`crates/dom-crypto/src/bulletproof_bp.rs:44-58` fixa 739 bytes, 64 bits e dois
commitments. `:363-379` constrói `value=[v, M-v]` e `blind=[r,-r]` com
`checked_sub`; `:533-558` recompõe `C1=M*H-C0` e chama o verificador com dois
commitments. `M=2^52-1` vem de `crates/dom-crypto/src/bulletproof.rs`.

O backend vivo é `grin_secp256k1zkp 0.7.15`, Bulletproof clássico. A API de
rewind é explicitamente de um commitment em
`.../include/secp256k1_bulletproofs.h:106-135`; a API de prove agregado recebe
`n_commits`, `nonce`, `private_nonce` e `message` em `:137-182`.

## Transcript, nonces e equações executadas

Em `rangeproof_impl.h:478-510`, o backend inicializa o transcript com os
commitments, o gerador de valor e `extra_commit` quando fornecido. Em DOM o
verificador passa `extra_commit=NULL` (`bulletproof_bp.rs:423-436`).

Em `rangeproof_impl.h:512-513`:

```
(alpha, rho) = ChaCha20(nonce, counter 0)
(tau1, tau2) = ChaCha20(private_nonce, counter 1).
```

DOM deriva esses dois seeds distintos a partir da seed externa, sob tags
separadas, em `bulletproof_bp.rs:464-501`. O rewind upstream, em contraste,
deriva ambos de **um único** `nonce` em `rangeproof_impl.h:749-750`; logo ele
não é uma API aplicável diretamente à prova DOM determinística de dois nonces.
Uma extração experimental agregada teria de rederivar ambos os valores por essas
mesmas tags e jamais aceitar somente um resultado parcial.

O prover constrói `A=alpha*G + bits*Gi` e `S=rho*G + sL*Gi + sR*Hi` em
`:542-568`. Ele deriva `y,z` de `A,S` em `:571-585`, deriva `t0,t1,t2` pelo
gerador `l,r` em `:587-633`, e constrói

```
T1 = t1*H + tau1*G
T2 = t2*H + tau2*G
x  = H(transcript, T1, T2)
```

em `:635-665`. `t_hat=l(x)·r(x)` é serializado pelo inner-product proof iniciado
em `:711-719`; a verificação completa do inner product é chamada em
`rangeproof_impl.h:317-340`.

O cálculo de `taux` efetivamente executado é `:667-676`:

```
taux = tau1*x + tau2*x²
for i = 0..n_commits:
    taux += z^(i+2) * blind[i]
```

Assim, para DOM:

```
taux = tau1*x + tau2*x² + z²r + z³(-r)
     = tau1*x + tau2*x² + z²(1-z)r.
```

O backend serializa `-taux` em bytes `0..31`, `-mu` em `32..63`, e `A,S,T1,T2`
em `64..192` (`:693-709`). Os bytes restantes são o inner-product proof. O
verificador inclui `proof[0..64]` no transcript desse inner product (`:283-338`),
portanto mudar `taux`, `mu` ou metadata transportada por `mu` sem regenerar uma
prova válida falha no verify integral.

## Rewind upstream e seus limites

`rangeproof_impl.h:724-848` lê somente `taux`, `mu`, `A,S,T1,T2` (bytes
`0..192`) para extrair. Ele não chama a verificação do inner-product proof; os
bytes posteriores não são autenticados por essa rotina. Consequentemente a
ordem obrigatória de qualquer desenho futuro é:

```
verify integral -> extrair -> validar metadata externa -> recomputar C0 e C1.
```

Após recomputar `x,z`, o rewind single-commit recupera o pacote de `mu` em
`:815-833` e divide o resíduo de `taux` por `z²` em `:835-846`. Isso funciona
somente para `n_commits=1`, cujo termo de blind é `z²r`.

O rewind upstream não recebe `n_commits`, nem o segundo commitment; portanto
não pode reconstruir o transcript DOM agregado. A declaração pública confirma
essa limitação de assinatura (`secp256k1_bulletproofs.h:106-135`).

## Derivação de recuperação agregada

Se `k=z²(1-z)` for inversível e os dois nonces forem conhecidos, uma rotina
nova poderia calcular, a partir do `taux` serializado `tau_s=-taux`:

```
r = -(tau_s + tau1*x + tau2*x²) * k^-1.
```

Os coeficientes são públicos: `z²` e `z³` vêm do transcript. Para `z!=0,1`, a
recuperação algébrica de `r` é confirmada pelo modelo para 10.000 vetores
determinísticos, inclusive `r=1` e `r=n-1` na ordem real de secp256k1.

Para `z=1`, `k=0`; há infinitos `r` compatíveis com o mesmo `taux` residual.
Esse desafio não viola nenhuma guarda do backend: prove e verify somente testam
zero para `z` (`rangeproof_impl.h:580-584`, `:255-259`). **CONFIRMADO:** a
inversão total de `r` é refutada no formato agregado atual.

## Value e metadata de 20 bytes

O código upstream somente injeta value/message em `alpha` quando
`n_commits==1` (`rangeproof_impl.h:526-540`). O formato exato é:

```
bytes 0..3  = 0
bytes 4..23 = message[0..20]
bytes 24..31 = value em big-endian
alpha <- alpha - scalar(bytes)
```

Para teste L1-B, `message` foi definido canonicamente como:

```
0: output version
1: network id
2..5: account u32 big-endian
6: branch
7..10: index u32 big-endian
11..19: binding digest truncado
```

Uma alteração experimental do prover que aplicasse esse mesmo deslocamento de
`alpha` para `n_commits=2` caberia nos campos existentes e o modelo confirma
recuperar value/20 bytes para `k!=0`. `A` e `mu` mudariam de forma consistente;
o verificador atual autentica suas alterações por suas equações e pelo
inner-product transcript. Nenhum byte adicional seria necessário.

Isso não autentica a semântica de metadata contra um prover que escolhe uma
metadata arbitrária ao criar uma nova prova: o verificador DOM atual não passa
`extra_commit`. A wallet deve recomputar e comparar a metadata canônica após
verify e rewind. Uma metadata adulterada em uma prova já emitida não passa o
verify integral se `mu`/A for alterado sem regenerar a prova; o modelo também
rejeita mismatch de metadata após recuperação.

## Veredito de viabilidade

* **REFUTADO:** a prova DOM atual contém value ou metadata recuperáveis; o
  ramo de empacotamento é exclusivo de `n_commits=1`.
* **CONFIRMADO:** a extensão de `alpha` pode transportar value e 20 bytes sem
  aumentar 739 bytes e permanece coberta por verify integral.
* **REFUTADO:** `r` é recuperável para todos os transcripts agregados atuais.
  `z=1` elimina a única combinação de blinding disponível.
* **CONFIRMADO:** não foi criado protótipo C/FFI. A condição necessária de
  recuperação total falhou na derivação; forçar um prover não demonstraria os
  requisitos centrais.

Para obter uma garantia total, a recuperação precisa de uma nova regra que
elimine deterministicamente `z=1` com informação recuperável, ou de um formato
versionado/backend que exponha informação independente sobre `r`. Essa regra
não existe no formato de consenso atual e não foi implementada nesta fase.

Material sensível do modelo é efemeramente zeroizado. Um desenho futuro deve
usar tipos zeroizing para `r`, `alpha`, `rho`, `tau1`, `tau2`, seeds e buffers
de recuperação; retornos com nonce errado, challenge inválido, coeficiente
inversível ausente, mismatch de metadata ou mismatch de commitment devem ser
`None`/erro fechado, jamais valor parcial.

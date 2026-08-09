# Esquema de dois nonces — candidato controlado

Estado: **CONSTRUÇÃO/BINDING CONGELADOS; IMPLEMENTAÇÃO NÃO INICIADA**. A
derivação secreta e a validação independente permanecem bloqueadas.

## Equações candidatas (DOCUMENTO NORMATIVO, EM §6.6)

```text
(k_i1, k_i2) <- nonces secretos independentes
R_i1 = k_i1 G
R_i2 = k_i2 G
b = H_to_scalar(binding_transcript)
R_i = R_i1 + b R_i2
R = sum_i R_i
R_hat = R + T
e = DOM_kernel_challenge(R_hat, X, kernel_message)
s_i_hat = k_i1 + b k_i2 + e x_i
s_i_hat G = R_i + e X_i
s_hat = sum_i s_i_hat
s_hat G = R_hat + eX - T
s = s_hat + t
t = s - s_hat; require tG = T
```

## Ordem obrigatória

1. reservar durablemente ambos os nonces no vault;
2. persistir commitment antes de exportá-lo;
3. aceitar todos os commitments;
4. revelar `R_i1,R_i2` e validar cada commitment;
5. calcular um único binding sobre listas ordenadas;
6. verificar cada partial antes de agregar;
7. consumir/tombstonar antes de exportar material irreversível;
8. retry retorna bytes idênticos, nunca novos nonces.

## Condições de rejeição congeladas

- scalar zero/`>=n`, ponto não canônico/infinito, purpose desconhecido;
- participantes duplicados ou ordem inconsistente;
- commitment divergente, template/transcript/chain/session diferentes;
- `R_i`, `R`, `R_hat`, partial ou soma degenerados;
- assinatura final recusada pelo verificador DOM;
- extração que não satisfaz `tG=T`.

## Bloqueios antes de código

| Bloqueio | Evidência faltante |
|---|---|
| derivação dos nonces | KDF/expander/contexto byte-exato ratificado; não substituir por nonce fornecido pela aplicação |
| API aritmética | extensão estreita autoritativa em `dom-crypto`, conforme ADR-0009 |
| independência | vetores produzidos por implementação diferente e revisada |

O binding já está congelado por ADR-0013: digest BE direto em `[1,n-1]`, sem
redução/retry, e gramática condicional de `T` por purpose.

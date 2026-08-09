# Fronteira de implementação — Fase 3-SNV/G1b

Nomenclatura: ADR-0015. Direção de dependência: ADR-0002 e ADR-0016.

| Componente | Responsabilidades | Não pode fazer |
|---|---|---|
| `dom-crypto` | curva, scalars, pontos, hash, challenge e verificador DOM | conhecer Wallet, sessão ou storage |
| `dom-adaptor` | tipos opacos G1a, erros e futura trait semântica do Nonce Vault | depender da Wallet, abrir banco/arquivo ou implementar witness |
| Store/Nonce Vault da Wallet | transação durável, secrets cifrados, tombstones, journal, budgets, âncora e receipts | redefinir criptografia G1a ou exportar antes do receipt |
| Cliente de testemunha Wallet | protocolo remoto idempotente, validação de receipt e modo auto-hospedado | receber identidade/contrato/valor/endereço/purpose/tx hash |
| Fase 3-SM | ordenar mensagens e chamar a trait por estados explícitos | acessar storage do vault ou fabricar retries/nonces |
| Transação comum Wallet | fluxo DOM atual | consultar/avançar budget, âncora ou witness adaptor |

O segundo agente recebe **Fase 3-SNV/G1b**: contrato e implementação futura de
Store/Nonce Vault, não a máquina de estados Fase 3-SM. Pode desenvolver em
paralelo com G1a usando tipos opacos e fixtures de interface claramente não
produtivas; integração só ocorre quando ambos os lados estabilizarem.

Nenhuma funcionalidade foi implementada nesta missão.

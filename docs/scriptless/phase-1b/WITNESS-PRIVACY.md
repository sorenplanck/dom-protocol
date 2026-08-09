# Privacidade e metadados da testemunha

A testemunha deve receber apenas o mínimo necessário para manter uma cadeia monotônica pseudônima e emitir receipts assinados. Ela não deve receber identidade da pessoa, contrato, valor, endereço, purpose, hash de transação, preimagem, chave de gasto ou conteúdo da sessão.

Vazamento residual inevitável da baseline: a testemunha observa uma cadeia pseudônima de atualizações e seus horários. Dependendo do transporte, também pode existir metadado de rede no operador da infraestrutura; mitigação e retenção precisam ser avaliadas antes de produção.

Rotação e encerramento de época devem limitar correlação sem permitir rollback ou ressurreição. Nenhuma técnica, prazo de retenção ou encoding é escolhido nesta missão.

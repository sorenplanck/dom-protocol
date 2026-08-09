# ADR-0008 — requisito online restrito a sessões adaptor

Status: aceito.

## Decisão

Uma sessão adaptor exige conectividade com a testemunha e receipt assinado duravelmente persistido antes da exportação de material. Não há modo offline ou fallback local silencioso para essa etapa.

Transações comuns da Wallet não usam orçamento, âncora ou testemunha e não avançam a cadeia monotônica. A indisponibilidade do serviço não pode impedir pagamentos comuns.

Restauração em outro dispositivo começa em `RESTORE_QUARANTINED`; somente sessões adaptor ficam bloqueadas enquanto a reconciliação não for comprovada.

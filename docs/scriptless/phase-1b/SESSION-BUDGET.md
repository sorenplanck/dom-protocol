# Orçamento de sessões de G1b

O sistema deverá aplicar orçamento global por chave, orçamento secundário por contraparte, limite de sessões concorrentes e limite por janela. Reserva e consumo são transacionais; abortos contam integralmente e não devolvem capacidade.

Backup, restauração, retry, rotação ou mudança de dispositivo não podem aumentar o orçamento nem reviver uma sessão consumida. A testemunha/âncora precisa tornar o retrocesso detectável.

Nenhum valor numérico, janela, unidade ou política de rotação é escolhido nesta missão. Todos dependem de medição, análise normativa e congelamento independente.

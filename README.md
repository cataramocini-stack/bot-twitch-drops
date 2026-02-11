🎮 Twitch Drops Monitor (The "CUWITCH" Edition)
⚠️ Status do Projeto: ABANDONADO (A Twitch Venceu)
Este bot foi criado com a nobre intenção de avisar drops ativos no Discord, mas descobrimos que a Twitch trata desenvolvedores independentes como se fossem vilões de filme do James Bond.

💀 Por que este repositório está morto?
Tentamos todas as abordagens possíveis, e o resultado foi uma batalha de 10x0 para a Twitch:

GQL Puro (API Pública): Funcionou por 48 horas. Depois, a Twitch decidiu que consultar campanhas públicas agora exige um "Token de Integridade" que só faltou pedir minha árvore genealógica.

Persisted Queries: Eles mudam os hashes das consultas mais rápido do que eu mudo de meia.

Playwright/Selenium (Navegador Automação): A Twitch detecta o rastro de automação e mete um erro de "Navegador não suportado". Eles basicamente instalaram uma cerca elétrica no código.

Login Persistente: Mesmo tentando usar cookies reais, o sistema de segurança deles (Integrity Service) bloqueia qualquer tentativa de login que não venha de um humano clicando fisicamente em botões.

😤 A Conclusão
Manter este bot funcionando exigiria:

Um servidor com 16GB de RAM só pra rodar um Chrome aberto 24/7.

Resolver Captchas e logar manualmente a cada 3 dias.

Paciência de um monge budista para lidar com as atualizações diárias da "CUWITCH".

Resumo: O sistema de drops da Twitch foi feito para te escravizar na frente de uma live de 4 horas pra ganhar uma skin de pistola que parece ter sido pintada no Paint. Não vale o esforço de automação.

🛠️ O que tem aqui?
O código atual (na branch master) é um monumento à nossa insistência. Ele usa Playwright e tenta simular um humano, mas provavelmente vai te dar um erro de login ou de integridade em 5 minutos.


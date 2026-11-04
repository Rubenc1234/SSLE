### Modelo de Atacante (*Threat Model*)

#### Perfil e Posição na Rede

O atacante é um agente malicioso que controla um ou mais contentores Incus ligados à rede `incus-default`, partilhada pelos microsserviços da arquitetura SOA. Embora não possua privilégios administrativos sobre o host ou acesso à gestão global do Incus, encontra-se dentro do domínio de comunicação dos serviços, podendo comunicar diretamente com os endpoints acessíveis na rede interna.

Assume-se que o atacante conhece os nomes hierárquicos dos serviços, os endereços IP, as portas utilizadas e a topologia básica da arquitetura.

#### Contexto Tecnológico e Fronteira de Confiança

A arquitetura é composta pelos microsserviços Registry, Ingestion, Storage e Analytics, bem como por sensores, implementados em Python/Flask e executados em contentores Incus individuais. Os dados são armazenados numa base de dados SQLite, utilizada pelo serviço Storage.

As comunicações entre os microsserviços são realizadas através de HTTP, sem implementação de TLS na arquitetura base. Todos os contentores se encontram ligados à mesma bridge `incus-default`, permitindo comunicação direta entre os serviços.

A bridge partilhada constitui uma fronteira de confiança relevante, uma vez que um contentor controlado pelo atacante pode interagir com os endpoints internos dos restantes serviços, caso estes estejam acessíveis e não existam mecanismos adequados de autenticação, autorização ou segmentação de rede.

#### Capacidades do Atacante

Assume-se que o atacante possui as seguintes capacidades:

- Enviar pedidos HTTP arbitrários para os endpoints acessíveis dos microsserviços, incluindo `/ingest`, `/register` e `/store`.
- Conhecer e utilizar os nomes dos serviços, endereços IP e portas expostas na rede interna.
- Explorar vulnerabilidades de lógica e mecanismos de segurança ausentes, como a falta de autenticação no Registry, ausência de *rate-limiting* e validação insuficiente de entradas.
- Manipular os metadados enviados nos pedidos, incluindo o campo `source_ip`, quando este é utilizado sem validação adequada.
- Gerar tráfego elevado e enviar *payloads* excessivamente grandes, procurando esgotar recursos computacionais.
- Controlar múltiplos sensores ou contentores com diferentes endereços IP na bridge, permitindo simular ataques distribuídos e contornar mecanismos de limitação baseados exclusivamente no IP.
- Registar serviços ou sensores não legítimos e tentar comprometer a descoberta de serviços através do Registry.

#### Limitações do Atacante

Para delimitar o âmbito da análise, assume-se que o atacante:

- Não possui privilégios de `root` no host que aloja os contentores.
- Não possui acesso administrativo ao daemon ou à gestão global do Incus.
- Não possui acesso direto aos ficheiros, logs ou bases de dados internos dos restantes contentores.
- Não consegue realizar *container escapes* nem comprometer diretamente o kernel ou o host.
- Não possui acesso físico à infraestrutura.

Estas limitações constituem pressupostos do modelo experimental e não garantias absolutas de segurança da plataforma.

#### Ativos a Proteger

Os principais ativos da arquitetura são:

- **Disponibilidade dos microsserviços:** assegurar o funcionamento contínuo dos serviços Ingestion, Storage, Analytics e Registry.
- **Integridade dos dados:** garantir que as leituras de temperatura armazenadas correspondem a medições legítimas e não foram manipuladas.
- **Autenticidade dos serviços:** garantir que os registos do Registry correspondem a serviços legítimos e que os mecanismos de descoberta não são manipulados.
- **Confiabilidade dos resultados analíticos:** assegurar que os resultados produzidos pelo Analytics refletem dados legítimos e consistentes.

#### Objetivos do Atacante e Mapeamento CIA / STRIDE

Os cenários de ataque selecionados procuram comprometer as seguintes propriedades de segurança:

- **Ramo A — Disponibilidade (DoS):** provocar a indisponibilidade do serviço Ingestion através de inundação de pedidos HTTP ao endpoint `/ingest` ou envio de *payloads* excessivos, causando esgotamento de recursos computacionais. Corresponde à categoria **Denial of Service** do STRIDE.

- **Ramo B — Integridade (Sensores Falsos / Ataque Distribuído):** comprometer a integridade dos dados através do registo de sensores não legítimos e da injeção de leituras de temperatura falsas em massa, contaminando a base de dados SQLite e comprometendo os resultados analíticos. Relaciona-se com **Tampering** e **Spoofing** no STRIDE.

- **Ramo C — Autenticidade (Registry Hijacking / Spoofing):** comprometer a autenticidade dos serviços através da usurpação de identidades no Registry, sobrescrevendo registos existentes ou manipulando a descoberta de serviços para redirecionar comunicações para endpoints controlados pelo atacante. Corresponde principalmente a **Spoofing**, podendo também envolver **Tampering**.

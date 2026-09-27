# Aviso de Privacidade — HuGR CoreLink

**Versão:** 1.0.0
**Publicado em:** 2026-05-13
**Contato DPO:** privacy@hugr.dev

---

## 1. Identidade e Dados do Responsável

**Responsável pelo Tratamento:** HuGR Labs Ltda. ("HuGR", "nós")
**DPO Interino:** privacy@hugr.dev

---

## 2. Categorias de Dados Coletados

Coletamos as seguintes categorias de dados pessoais:

- **Dados de identificação:** nome, endereço de e-mail, UUID do titular.
- **Dados de autenticação:** tokens PAT (Personal Access Token), credenciais WebAuthn.
- **Dados de uso:** logs de chamadas de API, metadados de artefatos de build (hash BLAKE3, tamanho, timestamps).
- **Dados de faturamento:** informações de pagamento processadas via Stripe (não armazenamos número de cartão completo).
- **Dados de telemetria:** logs de infraestrutura (Loki), métricas de performance (Prometheus/Grafana).

---

## 3. Finalidades do Tratamento

Tratamos seus dados para as seguintes finalidades:

1. **Execução contratual:** fornecimento do serviço CoreLink (cache CAS, pipeline de build, faturamento).
2. **Cumprimento de obrigação legal:** registros fiscais (LGPD Art. 16), auditoria regulatória (retenção 7 anos).
3. **Legítimo interesse:** monitoramento de abuso, detecção de fraude, segurança da plataforma.
4. **Consentimento:** analytics de uso (opt-in; revogável a qualquer momento).

---

## 4. Base Legal

| Finalidade | Base Legal (LGPD) | Base Legal (GDPR) |
|---|---|---|
| Execução contratual | Art. 7 V | Art. 6.1(b) |
| Obrigação legal | Art. 7 II | Art. 6.1(c) |
| Legítimo interesse | Art. 7 IX | Art. 6.1(f) |
| Consentimento (analytics) | Art. 7 I | Art. 6.1(a) |

---

## 5. Sub-processadores

Utilizamos os seguintes sub-processadores para prestar o serviço:

| Sub-processador | Finalidade | Região |
|---|---|---|
| Cloudflare Inc. | CDN, Workers, R2, D1, Pages | Global |
| Stripe Inc. | Processamento de pagamentos | US/EU |
| Neon Inc. | Banco de dados PostgreSQL | US |
| Grafana Labs | Monitoramento (Loki/Prometheus) | EU |

Para alterações em sub-processadores, você será notificado com no mínimo 30 dias de antecedência.

---

## 6. Transferências Internacionais

Seus dados podem ser processados nos seguintes países/regiões:
- **Brasil (SAM):** região primária.
- **Estados Unidos (WNAM/ENAM):** Cloudflare, Stripe, Neon.
- **União Europeia (WEUR):** Cloudflare EU, Grafana Labs.

As transferências para fora do Brasil são amparadas por: (a) países com nível de proteção adequado reconhecido pela ANPD; (b) cláusulas contratuais padrão (SCCs) conforme GDPR Art. 46.

---

## 7. Retenção de Dados

| Categoria | Período de Retenção | Base |
|---|---|---|
| Dados de conta | Enquanto vigente o contrato + 5 anos | LGPD Art. 16 fiscal |
| Logs de auditoria | 7 anos | R2 Object Lock (regulatório) |
| Logs de build (artefatos) | Conforme configuração do titular | Contratual |
| Dados de faturamento | 5 anos (fiscal) | LGPD Art. 16 |
| Consentimentos | 7 anos | LGPD Art. 8 (regime de consentimento) + GDPR Art. 7(1) (demonstrabilidade) |

---

## 8. Direitos do Titular (LGPD Art. 18)

Você tem os seguintes direitos:

- **Confirmação e Acesso** (Art. 18 I, II): confirmar a existência de tratamento e acessar seus dados.
- **Correção** (Art. 18 III): solicitar correção de dados incompletos ou inexatos.
- **Anonimização, Bloqueio ou Eliminação** (Art. 18 IV): solicitar eliminação de dados desnecessários.
- **Portabilidade** (Art. 18 V): receber seus dados em formato estruturado (JSON).
- **Revogação do Consentimento** (Art. 18 IX, c/c Art. 8 §5): revogar consentimento a qualquer momento.
- **Oposição** (Art. 18 §II — parágrafo de oposição, conforme Lei 13.853/2019): opor-se ao tratamento com base em legítimo interesse.
- **Informação sobre compartilhamento** (Art. 18 VII): saber com quem compartilhamos seus dados.

Para exercer seus direitos, acesse: **POST /v1/privacy/dsr/{direito}** (API self-service).
Prazo de resposta: até 15 dias úteis (acesso/portabilidade); 5 dias úteis (correção/revogação em ≤ 5 min).

---

## 9. Segurança

Implementamos as seguintes medidas de segurança:

- Criptografia em trânsito (TLS 1.2 mínimo; TLS 1.3 negociado quando houver suporte).
- Criptografia em repouso (R2 + Neon encryption at rest).
- Controle de acesso com autenticação multifator (WebAuthn FIDO2).
- Auditoria append-only com cadeia de hash (BLAKE3).
- Testes regulares de segurança (SOC 2 Type II em preparação).

---

## 10. Cookies e Rastreamento

Utilizamos cookies funcionais estritamente necessários para a operação do serviço. Não utilizamos cookies de rastreamento de terceiros sem seu consentimento explícito.

---

## 11. Menores

O CoreLink é um serviço B2B destinado a desenvolvedores profissionais. Não coletamos intencionalmente dados de menores de 18 anos.

---

## 12. Alterações neste Aviso

Qualquer alteração **material** (nova categoria de dados, novo sub-processador, nova finalidade) será notificada com antecedência e exigirá novo consentimento (**bump de versão maior**).

Alterações de esclarecimento (correção tipográfica, atualização de contato) são publicadas silenciosamente (**bump de versão menor**) com diff disponível em `/privacy/changelog`.

---

## 13. Contato

**DPO Interino:** privacy@hugr.dev
**Responsável:** HuGR Labs Ltda.

Para reclamações junto à ANPD: [www.gov.br/anpd](https://www.gov.br/anpd)

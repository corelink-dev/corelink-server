---
id: "BREACH-TMPL-ANPD-PT-BR"
type: "breach_notification_template"
doc_status: "DRAFT"
jurisdiction: "BR"
authority: "ANPD"
language: "pt-BR"
legal_basis: "LGPD Art. 48 + ANPD Resolução CD/ANPD nº 15/2024"
version: "1.0.0"
created: "2026-05-13"
owner: "Privacy Officer (Gustavo Schneiter interim)"
legal_review_status: "PENDING"
legal_review_evt_044_path: "r2://evidence-legal/breach-notification/lgpd-anpd-template-legal-review.pdf"
privacy_officer_review: false
template_variables:
  - "{{breach_id}}"
  - "{{breach_detected_at}}"
  - "{{data_categories_affected}}"
  - "{{count_subjects_affected}}"
  - "{{containment_actions}}"
  - "{{mitigation_offered}}"
  - "{{contact_email}}"
  - "{{breach_severity}}"
---

# Comunicação de Incidente de Segurança à ANPD
## (Conforme LGPD Art. 48 + ANPD Res. CD/ANPD nº 15/2024)

**INSTRUÇÃO DE PREENCHIMENTO**: Este template é pré-redigido. Antes de enviar:
1. Preencha TODAS as variáveis `{{...}}` com dados reais do incidente.
2. Remova estas instruções de preenchimento.
3. Revise com Legal externo (≤ 2h buffer adicional).
4. Envie para: comunicacao@anpd.gov.br
5. Emita evento de audit `breach.notification_dispatched.v1` pós-envio.

---

**ASSUNTO**: Comunicação de Incidente de Segurança — Identificador `{{breach_id}}`

---

**PARA**: Autoridade Nacional de Proteção de Dados (ANPD)
**DE**: HuGR Labs Ltda. — Agente de Tratamento (Controlador)
**DATA DA COMUNICAÇÃO**: *(preencher com data/hora de envio)*
**IDENTIFICADOR DO INCIDENTE**: `{{breach_id}}`
**GRAVIDADE**: `{{breach_severity}}`

---

## 1. Identificação do Controlador

| Campo | Valor |
|---|---|
| **Razão Social** | HuGR Labs Ltda. |
| **CNPJ** | *(a completar pré-GA)* |
| **Endereço** | *(a completar pré-GA)* |
| **E-mail de contato** | `{{contact_email}}` |
| **Encarregado de Dados (DPO)** | Gustavo Schneiter (interim) |
| **E-mail do Encarregado** | `{{contact_email}}` |

---

## 2. Descrição da Natureza do Incidente

*(LGPD Art. 48 §1º I + ANPD Res. CD/ANPD nº 15/2024 Art. 3 I)*

Em `{{breach_detected_at}}` (UTC), a HuGR Labs Ltda. tomou conhecimento de incidente de segurança que pode acarretar risco ou dano relevante aos titulares de dados pessoais. O incidente foi classificado como **`{{breach_severity}}`** conforme os critérios internos de classificação (Runbook RB-BREACH-NOTIF, Seção 2).

**Tipo de incidente**: *(descrever: acesso não autorizado / perda de integridade / indisponibilidade / vazamento de dados)*

**Origem do incidente**: *(descrever como foi descoberto: alerta automatizado / reporte de usuário / monitoramento interno)*

**Estado atual**: *(descrever: contenção aplicada / investigação em andamento / mitigação completa)*

---

## 3. Categorias e Quantidade de Dados Afetados

*(LGPD Art. 48 §1º II + ANPD Res. CD/ANPD nº 15/2024 Art. 3 III)*

**Categorias de dados pessoais afetados**:

`{{data_categories_affected}}`

*(exemplos: nome, endereço de e-mail, dados de uso, metadados de cache, chave pública WebAuthn, dados de faturamento)*

**Dados pessoais sensíveis afetados** (Art. 5 II LGPD): *(Sim/Não — especificar se aplicável)*

**Quantidade aproximada de titulares afetados**: `{{count_subjects_affected}}`

**Jurisdições dos titulares afetados**: *(Brasil / União Europeia / Califórnia-EUA / outras)*

---

## 4. Titulares Afetados

*(LGPD Art. 48 §1º III)*

Os titulares afetados são: *(descrever categorias — ex.: usuários da plataforma CoreLink / clientes pessoa jurídica / subprocessadores)*

---

## 5. Medidas Técnicas e de Segurança

*(LGPD Art. 48 §1º IV)*

**Medidas técnicas de proteção em vigor no momento do incidente**:
- Criptografia em repouso (R2 SSE-S3 + D1/Neon SSE) conforme INV-CONF-AT-REST.
- Piso TLS 1.2 em todos os endpoints, com 1.3 negociado por todo cliente capaz, conforme INV-CONF-IN-FLIGHT (ADR-0072).
- Os controles de integridade da auditoria devem ser verificados para o incidente. A retenção COMPLIANCE de produção do R2 Object Lock e uma garantia de sete anos imposta pelo armazenamento não estão comprovadas; não declare isso sem evidência atual vinculada ao alvo.
- Isolamento de tenant conforme INV-TENANT-ISOLATION.

**Medidas de contenção aplicadas**:

`{{containment_actions}}`

---

## 6. Consequências e Riscos para os Titulares

*(LGPD Art. 48 §1º V + ANPD Res. CD/ANPD nº 15/2024 Art. 3 V)*

*(descrever: risco de acesso indevido / uso indevido de dados / danos financeiros / discriminação / outros)*

**Avaliação de gravidade do impacto**: *(alto / médio / baixo — justificar)*

---

## 7. Medidas Adotadas para Mitigação e Prevenção

*(LGPD Art. 48 §1º VI)*

`{{mitigation_offered}}`

*(exemplos: rotação de credenciais, revogação de tokens, patch de vulnerabilidade, monitoramento reforçado)*

---

## 8. Comunicação aos Titulares Afetados

*(LGPD Art. 48 §1º — comunicação ao titular quando o incidente causar risco ou dano relevante)*

**Comunicação planejada/realizada aos titulares**: *(Sim/Não; data prevista/realizada)*

**Canal de comunicação**: *(e-mail transacional Cloudflare / banner de status page / ambos)*

**Prazo**: *(≤ 72h ou justificativa de extensão)*

---

## 9. Medidas para Comunicação Futura

Comprometemo-nos a:
1. Atualizar esta notificação com informações adicionais à medida que a investigação progride.
2. Notificar individualmente os titulares afetados quando houver risco relevante.
3. Apresentar relatório final de pós-mortem em até 14 dias corridos.
4. Adotar as medidas corretivas identificadas na investigação.

---

## 10. Contato para Esclarecimentos

| Campo | Valor |
|---|---|
| **Encarregado de Dados (DPO)** | Gustavo Schneiter (interim até contratação DPO dedicado) |
| **E-mail** | `{{contact_email}}` |
| **Disponibilidade** | 24/7 para esclarecimentos relacionados a este incidente |

---

*Esta comunicação é efetuada em conformidade com a Lei nº 13.709/2018 (LGPD), Art. 48, e a Resolução CD/ANPD nº 15/2024, que estabelece o regulamento sobre comunicação de incidente de segurança que possa acarretar risco ou dano relevante aos titulares.*

*Identificador do incidente para fins de rastreabilidade: `{{breach_id}}`*

# Aviso de Privacidad — HuGR CoreLink

**Versión:** 1.0.0
**Publicado:** 2026-05-13
**Contacto DPO:** privacy@hugr.dev

---

## 1. Identidad y Datos del Responsable

**Responsable del Tratamiento:** HuGR Labs Ltda. ("HuGR", "nosotros")
**DPO Interino:** privacy@hugr.dev

---

## 2. Categorías de Datos Personales Recopilados

Recopilamos las siguientes categorías de datos personales:

- **Datos de identificación:** nombre, dirección de correo electrónico, UUID del titular.
- **Datos de autenticación:** credenciales PAT (Personal Access Token), llaves WebAuthn.
- **Datos de uso:** registros de llamadas de API, metadatos de artefactos de build (hash BLAKE3, tamaño, marcas de tiempo).
- **Datos de facturación:** información de pago procesada por Stripe (no almacenamos números de tarjeta completos).
- **Datos de telemetría:** registros de infraestructura (Loki), métricas de rendimiento (Prometheus/Grafana).

---

## 3. Finalidades del Tratamiento

Tratamos sus datos para las siguientes finalidades:

1. **Ejecución contractual:** provisión del servicio CoreLink (caché CAS, pipeline de build, facturación).
2. **Cumplimiento de obligación legal:** registros fiscales (retención 5 años), auditoría regulatoria (retención 7 años).
3. **Interés legítimo:** monitoreo de abuso, detección de fraude, seguridad de la plataforma.
4. **Consentimiento:** analítica de uso (opt-in; revocable en cualquier momento).

---

## 4. Base Legal

| Finalidad | Base Legal (LFPDPPP México) | Base Legal (GDPR) |
|---|---|---|
| Ejecución contractual | Art. 10 I | Art. 6.1(b) |
| Obligación legal | Art. 10 III | Art. 6.1(c) |
| Interés legítimo | Art. 10 VI | Art. 6.1(f) |
| Consentimiento (analítica) | Art. 8 | Art. 6.1(a) |

---

## 5. Sub-procesadores

Utilizamos los siguientes sub-procesadores para prestar el servicio:

| Sub-procesador | Finalidad | Región |
|---|---|---|
| Cloudflare Inc. | CDN, Workers, R2, D1, Pages | Global |
| Stripe Inc. | Procesamiento de pagos | US/EU |
| Neon Inc. | Base de datos PostgreSQL | US |
| Grafana Labs | Monitoreo (Loki/Prometheus) | EU |

Será notificado con al menos 30 días de anticipación ante cualquier cambio en la lista de sub-procesadores.

---

## 6. Transferencias Internacionales

Sus datos pueden ser procesados en los siguientes países/regiones:
- **Brasil (SAM):** región primaria.
- **Estados Unidos (WNAM/ENAM):** Cloudflare, Stripe, Neon.
- **Unión Europea (WEUR):** Cloudflare EU, Grafana Labs.

Las transferencias internacionales están amparadas por cláusulas contractuales estándar (SCCs) y mecanismos de adecuación reconocidos.

---

## 7. Retención de Datos

| Categoría | Período de Retención | Base |
|---|---|---|
| Datos de cuenta | Mientras dure el contrato + 5 años | Fiscal |
| Registros de auditoría | 7 años | R2 Object Lock (regulatorio) |
| Logs de build (artefactos) | Según configuración del titular | Contractual |
| Datos de facturación | 5 años (fiscal) | Obligación legal |
| Registros de consentimiento | 7 años | Legislación aplicable |

---

## 8. Derechos del Titular (LFPDPPP Arts. 22-36 / ARCO)

Usted tiene los siguientes derechos ARCO:

- **Acceso:** confirmar el tratamiento y acceder a sus datos.
- **Rectificación:** solicitar la corrección de datos inexactos o incompletos.
- **Cancelación:** solicitar la eliminación de sus datos cuando ya no sean necesarios.
- **Oposición:** oponerse al tratamiento de sus datos para finalidades específicas.
- **Portabilidad:** recibir sus datos en formato estructurado (JSON).
- **Revocación del consentimiento:** revocar el consentimiento en cualquier momento.

Para ejercer sus derechos: **POST /v1/privacy/dsr/{derecho}** (API de autoservicio).
Tiempo de respuesta: hasta 20 días hábiles (acceso); 15 días hábiles (rectificación/cancelación).

---

## 9. Medidas de Seguridad

Implementamos las siguientes medidas de seguridad:

- Cifrado en tránsito (TLS 1.2 mínimo; TLS 1.3 se negocia cuando sea compatible).
- Cifrado en reposo (R2 + Neon).
- Autenticación multifactor (WebAuthn FIDO2).
- Registro de auditoría append-only con cadena de hash (BLAKE3).
- Pruebas regulares de seguridad (SOC 2 Tipo II en preparación).

---

## 10. Cookies y Rastreo

Utilizamos cookies funcionales estrictamente necesarias para la operación del servicio. No utilizamos cookies de rastreo de terceros sin su consentimiento explícito.

---

## 11. Menores de Edad

CoreLink es un servicio B2B dirigido a desarrolladores profesionales. No recopilamos intencionalmente datos de menores de 18 años.

---

## 12. Cambios a este Aviso

Cualquier cambio **material** (nueva categoría de datos, nuevo sub-procesador, nueva finalidad) será notificado con anticipación y requerirá nuevo consentimiento (**incremento de versión mayor**).

Las actualizaciones de aclaración (correcciones tipográficas, actualización de contacto) se publican silenciosamente (**incremento de versión menor**) con diferencias disponibles en `/privacy/changelog`.

---

## 13. Contacto y Autoridad Supervisora

**DPO Interino:** privacy@hugr.dev
**Responsable:** HuGR Labs Ltda.

**México:** Instituto Nacional de Transparencia, Acceso a la Información y Protección de Datos Personales (INAI) — [www.inai.org.mx](https://www.inai.org.mx)

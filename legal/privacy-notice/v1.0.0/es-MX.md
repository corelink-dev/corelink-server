# Aviso de Privacidad — HuGR CoreLink

> **BORRADOR INTERNO PRELANZAMIENTO — NO PUBLICADO NI VIGENTE.** CoreLink no se ha lanzado y no tiene clientes. Las descripciones en presente que siguen se conservan como texto histórico propuesto; no describen prácticas actuales de recopilación, uso, intercambio, retención ni tratamiento, y no crean compromisos vigentes. La revisión jurídica y la aprobación del propietario siguen pendientes antes de cualquier uso futuro con clientes.
>
> **Estado de fuente:** El propietario confirma que CoreLink no se ha lanzado y no tiene clientes. La revisión y aprobación legal de los términos de tratamiento, residencia y transferencia siguen pendientes; este aviso no establece una base de transferencia aprobada.

**Versión:** 1.0.0
**Fecha de fuente histórica (no publicada):** 2026-05-13
**Contacto DPO:** privacy@hugr.dev

---

## 1. Identidad y Datos del Responsable

**Responsable del Tratamiento:** HuGR Labs Ltda. ("HuGR", "nosotros")
**DPO Interino:** privacy@hugr.dev

---

## 2. Categorías de Datos Personales Recopilados

El aviso histórico propuesto enumeraba las siguientes categorías de datos personales; esto no declara una recopilación actual:

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

Actualmente no se ofrece ninguna región a clientes. Los entornos de Worker de producción hacen referencia a una única base D1 global compartida, sin vinculación por tenant. Contiene registros de tenant, membresía, PAT, cuotas, estado de facturación y cola de auditoría. Una consulta de solo lectura con Wrangler 4.145.0 del 2026-09-30 identificó `corelink-prod-d1` (ID `d64742ea-e102-40b2-a844-ff02e3f94562`), con `running_in_region=ENAM`, `jurisdiction=null`, replicación automática de lectura y 162 tablas. La región reportada es metadato, no garantía de ubicación física; esta es la postura técnica prelaunch del propietario raíz, no una aprobación legal. No se ha aprobado una base de transferencia ni medidas complementarias para este D1 compartido. Este aviso es un borrador y no promete procesamiento regional ni transferencia internacional.

---

## 7. Retención de Datos

| Categoría | Período de Retención | Base |
|---|---|---|
| Datos de cuenta | Mientras dure el contrato + 5 años | Fiscal |
| Registros de auditoría | El plazo de retención no se establece aquí | No hay garantía de Object Lock; la retención COMPLIANCE de producción no está disponible ni probada |
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
- Controles de fuente para una cadena de auditoría con evidencia de manipulación; no se establecen inmutabilidad Object Lock ni un plazo fijo de retención.
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

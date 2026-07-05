# auditor_ens_alta v4.0

**Herramienta de verificación técnica activa para auditorías del Esquema Nacional de Seguridad (ENS) - Categoría ALTA.**

Este repositorio contiene la Prueba de Concepto (PoC) desarrollada como parte del Trabajo de Fin de Grado en Ingeniería Informática: *"Diseño de una metodología de auditoría técnica de conformidad con el ENS (RD 311/2022)"*.

La herramienta automatiza 20 comprobaciones técnicas no intrusivas sobre un sistema objetivo, generando evidencias empíricas estructuradas en formatos JSON y CSV, mapeadas directamente contra las medidas del Anexo II del Real Decreto 311/2022.

---

## ⚠️ Aviso Metodológico y Legal

**Esta herramienta es estrictamente una Prueba de Concepto (PoC) académica.**
* **No sustituye** una auditoría ENS completa (que incluye controles físicos, organizativos y de personal).
* **No sustituye** a herramientas comerciales de análisis de vulnerabilidades o *pentesting*.
* Su ejecución opera exclusivamente en modalidad **observacional** (no intrusiva), pero siempre debe ejecutarse con **autorización expresa** de los responsables del sistema auditado y con un alcance claramente delimitado.

---

## ⚙️ Requisitos

El script ha sido diseñado priorizando la portabilidad y la baja intrusividad.
* **Lenguaje:** Python 3.13 o superior.
* **Dependencias:** Ninguna. Utiliza exclusivamente librerías de la biblioteca estándar de Python (`socket`, `ssl`, `urllib.request`, `json`, `csv`, `datetime`, etc.).

---

## 🚀 Instalación y Uso

Al no requerir dependencias externas, la ejecución es directa:

# pos-offline-cryptography-vault 🔒💳

[![GitHub Pages](https://img.shields.io/badge/GitHub%20Pages-Live%20Showcase-cyan?style=for-the-badge&logo=github)](https://alejano.github.io/pos-offline-cryptography-vault/)
[![Python](https://img.shields.io/badge/Python-3.12%2B-blue?style=for-the-badge&logo=python)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)

**Autor:** Alejandro Barragán Jasso  
**Enfoque:** Tech Lead / Mobile & Embedded Payment Systems Engineer

> 🌐 **Página Web Interactiva:** Visita las diapositivas interactivas y prueba el simulador de borrado militar en vivo en [alejano.github.io/pos-offline-cryptography-vault](https://alejano.github.io/pos-offline-cryptography-vault/).

---

## 🎯 Objetivo de la Publicación

¿Cómo almacenar datos financieros de forma segura cuando la terminal de cobro (POS) pierde conexión a internet?

Este repositorio contiene la arquitectura de triple protección para almacenamiento transaccional en contingencia:
1. **Cifrado de Base de Datos:** SQLCipher (AES-256 a nivel de bloque de archivo).
2. **Cifrado Granular por Campo:** AES-256-CBC con vector de inicialización (**IV**) único e independiente por transacción.
3. **Destrucción Militar DoD 5220.22-M:** Sobrescritura en 3 fases (`0x00`, `0xFF` y bytes pseudoaleatorios) antes de purgar los bloques de la memoria Flash.
4. **Anti-Falso Positivo de Red:** Verificación de socket DNS remoto antes de autorizar el cambio a modo offline.

---

## 🚀 Cómo Probar el Código

```bash
python offline_crypto_vault.py
```

---

## 📱 Publicación en LinkedIn
El texto completo, encuesta para el primer comentario y guión del carrusel de 7 diapositivas se encuentran en [POST_LINKEDIN.md](POST_LINKEDIN.md).

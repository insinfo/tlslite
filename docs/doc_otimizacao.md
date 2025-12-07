# Roteiro de Otimização TLS - tlslite

> A ideia é criar versões otimizadas dos algoritmos usados no TLS sem mexer no que já existe e funciona.
referencia C:\MyDartProjects\tlslite\referencias\openssl-master
---
não pode usar BigInt em nada 
criar arquivos em partes 
para evitar loop infinito use: 
 timeout-cli.exe 10 dart test test\montgomery_fast_test.dart
  
## ✅ Otimizações Concluídas

| Algoritmo | Speedup | Técnica | Arquivo |
|-----------|---------|---------|---------|
| **AES (Rijndael)** | **16.7x** | AES-NI shell code | `rijndael_fast_asm_x86_64.dart` |
| **AES-GCM GHASH** | **28-62x** | PCLMULQDQ shell code | `aesgcm_asm_x86_64.dart` |
| **SHA-256** | **3x** | Software otimizado (SHA-NI não disponível na máquina) | `sha256_asm_x86_64.dart` |
| **Poly1305** | **32x** | Base 2^32 limbs (evita BigInt) | `poly1305_fast.dart` |
| **ChaCha20** | **5.3x** | SSE2 shell code (4 palavras em paralelo) | `chacha_asm_x86_64.dart` |

### Throughput Alcançado
- **AES-GCM**: ~500 MB/s (era ~8 MB/s)
- **ChaCha20**: 134 MB/s (era 25 MB/s)
- **Poly1305**: 277 MB/s (era 8.5 MB/s)

---

## 🎯 Próximas Otimizações

### 🔴 Alta Prioridade

#### 1. X25519 (Key Exchange TLS 1.3)
**Problema atual:** `x25519.dart` usa `BigInt` para aritmética de campo em GF(2²⁵⁵ - 19)

```dart
// Código atual - LENTO!
final A = (x2 + z2) % p;
final AA = (A * A) % p;
final E = (AA - BB) % p;
```

**Solução:** Aritmética com limbs base 2^51 ou 2^64
- MULX para multiplicação 64x64→128 bits
- Redução mod p otimizada

**Speedup esperado:** 10-30x

#### 2. Ed25519 (Assinaturas Digitais)
**Problema atual:** `ed25519_edwards.dart` usa `BigInt` para operações de grupo

**Solução:** Mesma técnica de field arithmetic que X25519

**Speedup esperado:** 10-20x

#### 3. RSA Montgomery Multiplication
**Problema atual:** `BigInt.modPow` é lento para exponenciação modular

**Solução:** 
- Montgomery multiplication com MULX/ADCX/ADOX
- Sliding window exponentiation

**Speedup esperado:** 5-15x

### 🟡 Média Prioridade

#### 4. SHA-384/SHA-512
**Problema:** Software puro, 64-bit operations

**Solução:** Unroll loops, usar instruções AVX2 se disponível

**Speedup esperado:** 2-4x

#### 5. HKDF (Key Derivation)
**Problema:** Múltiplas chamadas HMAC sequenciais

**Solução:** Batch processing, reutilização de estado

**Speedup esperado:** 1.5-2x

### 🟢 Baixa Prioridade

| Algoritmo | Notas |
|-----------|-------|
| Triple-DES | Legado, pouco usado |
| RC4 | Obsoleto, não vale otimizar |
| MD5 | Legado, baixo uso |
| DSA | Pouco usado |

---

## 📊 Tabela de Referência - Instruções x86_64

| Instrução | Uso | Disponível desde |
|-----------|-----|------------------|
| AES-NI (AESENC, etc.) | AES encrypt/decrypt | Intel Westmere (2010) |
| PCLMULQDQ | GF(2^128) multiplication | Intel Westmere (2010) |
| SHA-NI | SHA-256 acelerado | Intel Goldmont / AMD Zen |
| SSE2 | SIMD 128-bit | Pentium 4 (2001) |
| AVX2 | SIMD 256-bit | Intel Haswell (2013) |
| MULX | 64x64→128 multiply | Intel Haswell (2013) |
| ADCX/ADOX | Add with carry | Intel Broadwell (2014) |

---

## 🔧 Arquitetura de Otimização

```
lib/src/utils/
├── algoritmo.dart          # Versão original (sempre funciona)
├── algoritmo_fast.dart     # Versão otimizada em Dart puro
└── algoritmo_asm_x86_64.dart  # Versão com shell code x86_64
```

### Convenções:
- `_fast.dart` = Otimização em Dart puro (sem shell code)
- `_asm_x86_64.dart` = Usa shell code x86_64
- Fallback automático para versão original se CPU não suportar

---

## 📈 Impacto no TLS

| Cipher Suite | Algoritmos | Status |
|--------------|------------|--------|
| TLS_AES_128_GCM_SHA256 | AES ✅, GCM ✅, SHA-256 ✅ | **100% otimizado** |
| TLS_AES_256_GCM_SHA384 | AES ✅, GCM ✅, SHA-384 ⏳ | 90% otimizado |
| TLS_CHACHA20_POLY1305_SHA256 | ChaCha20 ✅, Poly1305 ✅, SHA-256 ✅ | **100% otimizado** |
| ECDHE-RSA | X25519 ⏳, RSA ⏳ | Pendente |
| ECDHE-ECDSA | X25519 ⏳, Ed25519 ⏳ | Pendente |

---

## 📝 Histórico de Otimizações

| Data | Algoritmo | Speedup | Notas |
|------|-----------|---------|-------|
| 2024 | AES (Rijndael) | 16.7x | AES-NI shell code |
| 2024 | AES-GCM GHASH | 28-62x | PCLMULQDQ para GF(2^128) |
| 2024 | SHA-256 | 3x | Software otimizado (CPU sem SHA-NI) |
| 2024 | Poly1305 | 32x | Limbs base 2^32, evita BigInt |
| 2024 | ChaCha20 | 5.3x | SSE2 shell code, 134 MB/s |

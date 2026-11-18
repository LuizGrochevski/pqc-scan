# pqc-scan

[English](README.md) | **Português (BR)**

Audita endpoints TLS e certificados X.509 em busca de **criptografia vulnerável a computadores quânticos** e indica o que migrar para os padrões pós-quânticos do NIST (ML-KEM, ML-DSA, SLH-DSA).

Escrito em Rust. Um único binário, saída em JSON e a flag `--fail-on` para barrar um pipeline de CI.

## Por quê

Um computador quântico grande rodando o algoritmo de Shor quebra RSA, ECDSA, EdDSA, ECDH e X25519, não importa o tamanho da chave. As duas metades do problema não têm a mesma urgência:

- **Troca de chaves** é urgente. Um atacante pode gravar tráfego criptografado hoje e decifrar depois ("harvest now, decrypt later"). A correção é uma troca de chaves híbrida pós-quântica, como `X25519MLKEM768`, que já existe em stacks TLS 1.3.
- **Assinaturas / certificados** importam durante o handshake, então o risco é o dia em que um computador quântico conseguir forjá-las. A migração é mais lenta, pois depende de CAs e de ferramentas de PKI, mas chaves de longa duração (raízes, intermediárias, assinatura de código) precisam de um plano desde já.

O `pqc-scan` verifica as duas e mostra qual é qual.

## Instalação

```bash
cargo install --path .
```

Requer uma toolchain Rust estável recente. A stack TLS (`rustls` com o provider `aws-lc-rs`) precisa de um compilador C e, em algumas plataformas, de CMake. No Termux: `pkg install cmake clang make perl` e compile com `cargo build --release`; o build em modo debug (`cargo build` / `cargo test`) pode abortar no linker do Android.

## Uso

```text
pqc-scan host <ALVO> [--timeout SEGUNDOS] [--json] [--fail-on vulnerable|critical]
pqc-scan cert <ARQUIVO>... [--json] [--fail-on vulnerable|critical]
```

`ALVO` pode ser `host`, `host:porta` ou `https://host[:porta]` (porta padrão 443).

### Escanear um endpoint ao vivo

Faz o handshake com o servidor oferecendo o grupo híbrido `X25519MLKEM768` e audita a troca de chaves negociada e todos os certificados da cadeia. Dois scans reais de 17/11/2026 (saída resumida; o resultado depende de como cada servidor está configurado no dia; a saída da ferramenta é em inglês):

```text
$ pqc-scan host cloudflare.com
pqc-scan · cloudflare.com:443
TLSv1.3 · TLS13_AES_256_GCM_SHA384 · key exchange: X25519MLKEM768

Connection
  [QUANTUM-SAFE] key exchange: X25519MLKEM768
      Hybrid post-quantum key exchange: recorded traffic stays protected against future quantum decryption.

Certificate #0 (leaf) — CN=cloudflare.com
  issuer:  C=US, O=Google Trust Services, CN=WE1
  expires: Feb  1 23:47:08 2027 +00:00
  [QUANTUM-VULNERABLE] public key: ECDSA/EC P-256
      Broken by Shor's algorithm on a cryptographically relevant quantum computer, regardless of key size.
      → Plan a migration to ML-DSA (FIPS 204) or SLH-DSA (FIPS 205); use hybrid/composite certificates during the transition.
  [QUANTUM-VULNERABLE] signature: ECDSA with SHA-256
      [...]

[2 intermediate certificates trimmed]

Summary: 0 critical · 6 quantum-vulnerable · 0 info · 1 quantum-safe
```

```text
$ pqc-scan host github.com
pqc-scan · github.com:443
TLSv1.3 · TLS13_AES_128_GCM_SHA256 · key exchange: X25519

Connection
  [QUANTUM-VULNERABLE] key exchange: X25519
      Classical key exchange: traffic recorded today can be decrypted once a quantum computer exists ("harvest now, decrypt later"). The client offered X25519MLKEM768 and the server did not select it.
      → Enable the hybrid X25519MLKEM768 group (TLS 1.3) on the server or TLS terminator.

[certificates trimmed]

Summary: 0 critical · 7 quantum-vulnerable · 0 info · 0 quantum-safe
```

### Escanear arquivos de certificado

Suporta PEM (inclusive bundles com vários certificados) e DER:

```text
$ pqc-scan cert tests/fixtures/rsa2048.pem
pqc-scan · tests/fixtures/rsa2048.pem

Certificate #0 (root) — CN=rsa2048.test
  issuer:  CN=rsa2048.test
  expires: Nov 14 12:27:16 2036 +00:00
  [QUANTUM-VULNERABLE] public key: RSA-2048
      Broken by Shor's algorithm on a cryptographically relevant quantum computer, regardless of key size.
      → Plan a migration to ML-DSA (FIPS 204) or SLH-DSA (FIPS 205); use hybrid/composite certificates during the transition.
  [INFO] signature: RSA with SHA-256
      Self-signature on a trust anchor is not verified by relying parties, so it has no practical effect.

Summary: 0 critical · 1 quantum-vulnerable · 1 info · 0 quantum-safe
```

### Usar no CI

```bash
pqc-scan host api.example.com --json --fail-on critical > pqc-report.json
```

| Exit code | Significado |
|-----------|-------------|
| `0` | Scan concluído e nada atingiu o limite de `--fail-on` (ou nenhum limite foi definido) |
| `1` | Ao menos um achado atingiu o limite de `--fail-on` |
| `2` | Erro: host inacessível, arquivo ilegível, nenhum certificado encontrado |

`--json` sempre imprime um array de relatórios, mesmo para um único alvo, então o schema é estável para scripts.

## Modelo de severidade

| Severidade | Significado | Exemplos |
|------------|-------------|----------|
| `critical` | Fraco até contra atacantes clássicos | RSA < 2048 bits, assinaturas SHA-1 ou MD5, DSA, P-192 |
| `vulnerable` | Seguro hoje, quebrado pelo algoritmo de Shor | RSA ≥ 2048, ECDSA P-256/384/521, Ed25519, troca de chaves X25519 |
| `info` | Algoritmo não reconhecido, ou sem efeito prático | Autoassinatura de uma CA raiz |
| `safe` | Padrão pós-quântico do NIST | ML-KEM, ML-DSA, SLH-DSA, troca de chaves híbrida `X25519MLKEM768` |

## Como funciona

1. O `host` abre uma conexão TCP e faz o handshake TLS com o [rustls](https://github.com/rustls/rustls). O cliente oferece `X25519MLKEM768`, então o grupo negociado mostra se o **servidor** usa troca de chaves pós-quântica. Um teste unitário garante essa premissa.
2. A cadeia de certificados é lida com o [x509-parser](https://github.com/rusticata/x509-parser). Os algoritmos de chave pública e de assinatura são identificados por OID e classificados (`src/classify.rs`).
3. Assinaturas de CAs autoassinadas são reportadas como `info`: quem confia nelas nunca verifica essa assinatura, então um SHA-1 autoassinado em uma raiz não é um achado real. A *chave* da raiz continua sendo reportada.

## Limitações

- **A validação de certificado está desativada de propósito.** É uma ferramenta de auditoria: ela inspeciona o que o servidor apresentar, inclusive certificados expirados, autoassinados ou não confiáveis. Não reutilize esse código de conexão para nada que exija TLS autenticado.
- Um handshake por scan. Ele reporta o que *aquele* handshake negociou, não todos os grupos ou versões que o servidor suporta.
- Só TLS 1.2 e 1.3 são testados, e o TLS 1.2 nunca negocia ML-KEM.
- Ainda sem STARTTLS, SSH ou scan de código-fonte (veja o roadmap).
- As tabelas de OID cobrem os algoritmos comuns; o resto é reportado como `info` para revisão manual.
- Testado contra servidores OpenSSL locais e fixtures de certificado. Resultados em endpoints de produção dependem da stack TLS do servidor.

## Roadmap

- [ ] Auditoria de chave de host e troca de chaves do SSH
- [ ] STARTTLS (SMTP, IMAP)
- [ ] Testar grupos de troca de chaves separadamente para listar tudo que o servidor aceita
- [ ] Escanear árvores de código e lockfiles atrás de uso de criptografia vulnerável
- [ ] Saída em SARIF e CycloneDX CBOM
- [ ] Modo em lote para uma lista de hosts

## Desenvolvimento

```bash
cargo test
cargo clippy --all-targets -- -D warnings
```

As fixtures em `tests/fixtures/` são certificados autoassinados gerados com OpenSSL; as chaves privadas foram descartadas.

## Referências

- [FIPS 203: ML-KEM](https://csrc.nist.gov/pubs/fips/203/final)
- [FIPS 204: ML-DSA](https://csrc.nist.gov/pubs/fips/204/final)
- [FIPS 205: SLH-DSA](https://csrc.nist.gov/pubs/fips/205/final)
- NIST IR 8547, *Transition to Post-Quantum Cryptography Standards*

## Licença

MIT

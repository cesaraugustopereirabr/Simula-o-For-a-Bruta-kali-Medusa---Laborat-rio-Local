# Simulação de Ataques de Força Bruta - Laboratório Local (Kali / Medusa / Serviços Vulneráveis)

> **Aviso ético e legal**: Este repositório/documento foi criado exclusivamente para fins educativos e para uso em **laboratório controlado** (máquinas virtuais que você possui ou possui permissão explícita para testar). **Não execute** ataques, ferramentas ou scripts contra sistemas de terceiros sem autorização expressa. Use redes isoladas (host-only / internal network), snapshots e sempre restaure o ambiente após os testes.

---

## Sumário

1. Objetivo
2. Arquitetura do laboratório (concepção)
3. Cenários estudados
4. Materiais incluídos
5. Como usar (execução local segura)
6. Scripts e códigos (com explicações)

   * gerador de wordlists (Python)
   * `vulnerable_app.py` (Flask) - aplicação de teste vulnerável
   * `secure_app.py` (Flask) - mesma aplicação com mitigação (rate-limit/lockout/log)
   * `test_harness.py` - harness de tentativas controladas
7. Metodologia de teste (passo a passo - laboratório)
8. Observações sobre Medusa / Kali / ferramentas de linha de comando (visão conceitual segura)
9. Logs e análise (exemplos)
10. Recomendações de mitigação
11. Modelo de relatório / resultados simulados
12. Referências e leituras recomendadas

---

## 1. Objetivo

Documentar e fornecer um arquivo único (README) contendo todo o material necessário para estudar ataques de força bruta em ambiente local: conceitos, código para ambientes de teste (web apps), gerador de wordlists, e um test harness que simula tentativas de login de forma controlada. O foco é **entender mecanismos de ataque e, principalmente, as defesas**.

---

## 2. Arquitetura do laboratório (concepção)

* **VM Atacante:** Kali Linux - papel de análise (conceitual).
* **VM Target:** Metasploitable 2 / DVWA / aplicações customizadas (Flask) para testes de autenticação.
* **Rede:** VirtualBox Host-Only ou Internal Network (sem rota para Internet). Snapshots antes de cada etapa.
* **Ferramentas (exemplos):** Medusa (concept), Hydra (concept), Burp Suite (proxy/inspeção), ferramentas IDS (Suricata/Snort) para observação. *Não incluímos comandos operacionais de ataque contra hosts não autorizados.*

---

## 3. Cenários estudados

### 3.1 Força bruta em FTP (conceito)

* Objetivo: testar descoberta de credenciais em serviços FTP com contas fracas.
* Vulnerabilidades típicas: contas com senhas fracas, ausência de lockout, anonimato habilitado.

### 3.2 Força bruta em formulários web (DVWA-like)

* Objetivo: submeter repetidamente POSTs de login contra um formulário.
* Especificidades: CSRF, tokens, comportamento do WAF, respostas que indicam existência de usuário.

### 3.3 Password spraying em SMB (conceito)

* Objetivo: tentar poucas senhas comuns contra muitos usuários para evitar bloqueios automáticos.
* Importância: difícil de detectar se não houver correlação por conta.

---

## 4. Materiais incluídos

* Trechos de código Python para execução local de testes (Flask apps e geradores).
* Exemplos de configuração de logs e de regras de detecção conceituais.
* Modelo de README/relatório com metodologia e recomendações.

---

## 5. Como usar — instruções de execução local segura

1. Copie os blocos de código abaixo para arquivos locais: `wordlist_generator.py`, `vulnerable_app.py`, `secure_app.py`, `test_harness.py`.
2. Crie um ambiente Python (recomendado: `python3 -m venv venv` / `source venv/bin/activate`).
3. Instale dependências mínimas: `pip install flask requests`.
4. Em terminais separados, execute:

   * `python vulnerable_app.py` (porta 5000) — aplicação sem proteções
   * `python secure_app.py` (porta 5001) — aplicação com rate-limiting e bloqueio
5. Execute `python test_harness.py` para simular tentativas de login controladas (apontando para a porta correta no arquivo).
6. Observe os logs gerados (arquivo `auth.log` para `secure_app.py`) e compare comportamentos.

> **Importante:** Todos os exemplos estão configurados para `localhost` (127.0.0.1). Não altere `TARGET` nos scripts para IPs remotos ou que você não possui autorização para testar.

---

## 6. Scripts e códigos (com explicações)

> **Observação sobre formatação:** todos os blocos de código a seguir estão prontos para serem copiados diretamente para arquivos com os nomes sugeridos. Cada bloco tem uma breve explicação do comportamento.

### 6.1 Gerador de wordlists (seguro, educativo)

Arquivo: `wordlist_generator.py`

```python
# wordlist_generator.py
# Gera wordlists pequenas para testes locais e educativos.
# Uso: python wordlist_generator.py

import itertools

verbs = ["admin","user","guest","test"]
numbers = ["", "123", "2023", "2024"]
symbols = ["", "!", "@"]

def generate(out_file="wordlist.txt"):
    combos = []
    for v in verbs:
        for n in numbers:
            for s in symbols:
                pwd = f"{v}{n}{s}"
                if 1 <= len(pwd) <= 32:
                    combos.append(pwd)
    combos = sorted(set(combos))
    with open(out_file, "w", encoding="utf-8") as f:
        for c in combos:
            f.write(c + "\n")
    print(f"Geradas {len(combos)} entradas em {out_file}")

if __name__ == "__main__":
    generate()
```

**Explicação:** gera uma wordlist pequena e determinística contendo variações simples. Útil para aprender impacto de palavras comuns sem distribuir grandes listas.

### 6.2 Aplicação vulnerável (Flask)

Arquivo: `vulnerable_app.py`

```python
# vulnerable_app.py
# App Flask simples com formulário de login sem proteções — APENAS PARA LAB LOCAL

from flask import Flask, request, render_template_string
app = Flask(__name__)
app.secret_key = "dev-secret"

# usuário fixo para teste
USERS = {"admin": "P4ssw0rd!"}

login_page = """
<form method="post">
  Username: <input name="username"><br>
  Password: <input name="password" type="password"><br>
  <input type="submit" value="Login">
</form>
"""

@app.route("/", methods=["GET","POST"])
def login():
    if request.method == "POST":
        u = request.form.get("username","")
        p = request.form.get("password","")
        if USERS.get(u) == p:
            return f"Bem-vindo, {u}!"
        else:
            return "Credenciais inválidas", 401
    return render_template_string(login_page)

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
```

**Explicação:** essa versão NÃO possui rate-limiting, lockout nem logging detalhado. Use-a para observar como ataques simples se comportam sem proteção.

### 6.3 Aplicação com mitigação (Flask)

Arquivo: `secure_app.py`

```python
# secure_app.py
# App Flask com proteções simples: rate-limit por IP, lockout temporário e logging

from flask import Flask, request, render_template_string
from collections import defaultdict
import time
import logging

app = Flask(__name__)
app.secret_key = "dev-secret"

USERS = {"admin": "P4ssw0rd!"}

# Configurações de segurança
MAX_ATTEMPTS = 5            # tentativas antes do cooldown/account lock
LOCKOUT_SECONDS = 300       # 5 minutos
COOLDOWN_WINDOW = 60       # janela de contagem em 60s

attempts = defaultdict(list)   # attempts[ip] = [timestamps]
locked_until = {}              # locked_until[identifier] = timestamp

logging.basicConfig(level=logging.INFO, filename="auth.log", filemode="a",
                    format="%(asctime)s %(message)s")

login_page = """
<form method="post">
  Username: <input name="username"><br>
  Password: <input name="password" type="password"><br>
  <input type="submit" value="Login">
</form>
"""

def is_locked(key):
    t = locked_until.get(key, 0)
    return time.time() < t

@app.route("/", methods=["GET","POST"])
def login():
    ip = request.remote_addr or "local"
    if is_locked(ip):
        return "Bloqueado temporariamente (IP). Tente mais tarde.", 429

    # limpa tentativas antigas
    now = time.time()
    attempts[ip] = [ts for ts in attempts[ip] if now - ts <= COOLDOWN_WINDOW]

    if request.method == "POST":
        u = request.form.get("username","")
        p = request.form.get("password","")
        if USERS.get(u) == p:
            logging.info(f"LOGIN_SUCCESS ip={ip} user={u}")
            attempts[ip] = []  # reset on success
            return f"Bem-vindo, {u}!"
        else:
            attempts[ip].append(now)
            logging.warning(f"LOGIN_FAIL ip={ip} user={u}")
            if len(attempts[ip]) >= MAX_ATTEMPTS:
                locked_until[ip] = now + LOCKOUT_SECONDS
                logging.warning(f"LOCKOUT ip={ip} until={locked_until[ip]}")
                return "Conta bloqueada temporariamente.", 429
            return "Credenciais inválidas", 401
    return render_template_string(login_page)

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5001, debug=False)
```

**Explicação:** adiciona proteção básica e logging em `auth.log`. É intencionalmente simples — em produção use bibliotecas maduras de rate-limiting, hashing de senhas e mecanismos de MFA.

### 6.4 Test harness — simulação controlada de tentativas

Arquivo: `test_harness.py`

```python
# test_harness.py
# Simula tentativas de login de forma controlada contra secure_app.py (porta 5001)

import requests
import time

# Ajuste o TARGET para o serviço local / porta correspondente
TARGET = "http://127.0.0.1:5001/"  # secure_app.py
USERNAME = "admin"
wordlist = ["1234","password","P4ssw0rd!","admin123"]


def try_login(pwd):
    s = requests.Session()
    r = s.post(TARGET, data={"username": USERNAME, "password": pwd})
    return r.status_code, r.text

for p in wordlist:
    code, text = try_login(p)
    print(f"Try {p} -> {code}: {text[:80]}")
    time.sleep(2)  # throttle para evitar flooding
```

**Explicação:** o `test_harness` tenta senhas da pequena wordlist contra a `secure_app`. Observe respostas HTTP e `auth.log` para validar bloqueios.

---

## 7. Metodologia de teste (passo a passo - laboratório)

1. Criar ambiente Python e instalar dependências: `pip install flask requests`.
2. Em um terminal, executar `python vulnerable_app.py` (porta 5000) e, em outro terminal, `python secure_app.py` (porta 5001).
3. Rodar `python wordlist_generator.py` para criar `wordlist.txt` (opcional).
4. Ajustar `test_harness.py` para apontar ao TARGET desejado (`5000` para vulnerable_app e `5001` para secure_app).
5. Executar o harness e observar diferenças: vulnerável aceitará várias tentativas; a versão segura aplicará bloqueio após `MAX_ATTEMPTS`.
6. Anotar tempos, número de tentativas até bloqueio, e entradas em `auth.log`.
7. Restaurar snapshots entre experimentos para repetir medidas com parâmetros diferentes.

---

## 8. Observações sobre Medusa / Kali / outras ferramentas (visão segura)

* **Medusa**: ferramenta de brute-force paralela muito usada em labs. Conceito: tenta autenticar em vários serviços (ftp, ssh, smb) usando combos de usuário/senha. **Não incluir comandos operacionais de ataque aqui**; se você tiver um laboratório com IPs autorizados, consulte a documentação oficial ou materiais de cursos para exemplos.

* **Kali**: distribuição para testes de segurança; sempre use em máquinas que você controla.

* **Hydra / Burp / Metasploit**: ferramentas complementares para avaliação. Em ambiente educacional, use-as apenas com permissão.

---

## 9. Logs e análise (exemplos)

Exemplo de linhas produzidas por `secure_app.py` no arquivo `auth.log`:

```
2025-10-18 23:40:12,345 LOGIN_FAIL ip=127.0.0.1 user=admin
2025-10-18 23:40:20,123 LOCKOUT ip=127.0.0.1 until=1697681460.123
2025-10-18 23:46:20,123 LOGIN_SUCCESS ip=127.0.0.1 user=admin
```

**Exercício de análise**:

* Calcule quantas tentativas um IP fez em 5 minutos.
* Gere alertas conceituais no SIEM com uma query do tipo: `count(LOGIN_FAIL) by ip where count > N in 5m`.

---

## 10. Recomendações de mitigação (detalhadas)

1. **Política de senhas robusta**: força mínima, bloqueio de senhas populares, e hashing forte com sal (bcrypt/argon2).
2. **MFA**: implementação onde for factível (administradores, acesso remoto, VPNs).
3. **Rate limiting**: por IP, por conta e por dispositivo.
4. **Lockout progressivo**: bloqueios temporários que aumentam com tentativas repetidas.
5. **Proteção contra enumeração**: respostas uniformes para usuários inválidos.
6. **Monitoramento centralizado** (SIEM): correlação de falhas por IP, por conta e por período.
7. **Firewall e WAF**: regras para detectar bursts de login e bloqueá-los.
8. **Treinamento de usuários** e revisão periódica de contas e privilégios.

---

## 11. Modelo de relatório / resultados simulados (estrutura)

* **Resumo executivo**: objetivo, escopo, ambiente (VMs, redes), principais achados.
* **Metodologia**: passos executados, scripts usados, cuidados éticos.
* **Resultados**: tabela com número de tentativas, tempo até bloqueio, IPs, logs.
* **Impacto**: risco estimado (BAIXO / MÉDIO / ALTO) se o serviço estivesse em produção.
* **Recomendações técnicas e operacionais**.
* **Apêndice**: scripts, logs, snapshots e instruções de restauração.

---

## 12. Referências e leituras recomendadas

* OWASP Authentication Cheat Sheet (procure no site OWASP)
* Documentação oficial do vsftpd, Samba e do framework Flask
* Materiais introdutórios sobre Medusa/Hydra (apenas em labs autorizados)
* Plataformas para prática autorizada: VulnHub, OWASP Juice Shop, TryHackMe, Hack The Box (respeitar termos de uso)

---

## 13. Observações finais e boas práticas

* Sempre trabalhe em ambientes isolados.
* Documente cada passo (timestamp, snapshot, logs) para reprodutibilidade.
* Não publique wordlists sensíveis ou credenciais reais.
* Use este material para calibrar proteções: por exemplo, testar quantas tentativas dentro de um período seu ambiente tolera sem afetar usuários legítimos.

---

### Anexo: checklist rápido antes de qualquer teste

* [ ] Tenho permissão para testar o alvo (é minha VM ou tenho autorização).
* [ ] Rede isolada (host-only/internal).
* [ ] Snapshots criados.
* [ ] Logs habilitados e coletados.
* [ ] Backup de dados importantes.

---

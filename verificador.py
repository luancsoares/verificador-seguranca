"""
Verificador de Segurança — versão orientada a objetos (GABARITO)

Tente fazer o exercício antes de abrir este arquivo!

Conceitos usados:
- Abstração      -> classe base Verificacao (só diz O QUE fazer: executar)
- Herança        -> cada checagem herda de Verificacao
- Polimorfismo   -> o Verificador chama v.executar() sem saber qual classe é
- Encapsulamento -> métodos/atributos com "_" são de uso interno da classe

Dependências: pip install requests python-whois
"""

import socket
import ssl
from datetime import datetime, timezone

import requests


# ----------------------------------------------------------------------
# ABSTRAÇÃO: a classe base define o "contrato" que toda checagem segue
# ----------------------------------------------------------------------
class Verificacao:
    nome = "Verificação genérica"

    def executar(self, site):
        """Deve devolver um dicionário: {"status": ..., "detalhe": ...}
        status pode ser "ok", "atencao" ou "critico"."""
        raise NotImplementedError("Cada verificação precisa implementar executar()")

    def emoji(self, status):
        return {"ok": "🟢", "atencao": "🟡", "critico": "🔴"}[status]


# ----------------------------------------------------------------------
# HERANÇA: cada checagem "é uma" Verificacao
# ----------------------------------------------------------------------
class VerificacaoHeaders(Verificacao):
    nome = "Headers de segurança"

    # atributo de classe: a lista é a mesma para todos os objetos
    HEADERS = [
        "Strict-Transport-Security",
        "Content-Security-Policy",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Referrer-Policy",
    ]

    def executar(self, site):
        resposta = requests.get(f"https://{site}", timeout=10)
        presentes = [h for h in self.HEADERS if h in resposta.headers]
        pontos = len(presentes)

        if pontos >= 4:
            status = "ok"
        elif pontos >= 2:
            status = "atencao"
        else:
            status = "critico"

        return {"status": status, "detalhe": f"{pontos}/5 headers presentes"}


class VerificacaoCertificado(Verificacao):
    nome = "Certificado TLS"

    # ENCAPSULAMENTO: método interno (o "_" avisa: não chame de fora)
    def _dias_restantes(self, site):
        contexto = ssl.create_default_context()
        with socket.create_connection((site, 443), timeout=10) as sock:
            with contexto.wrap_socket(sock, server_hostname=site) as conexao:
                cert = conexao.getpeercert()
        expira = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
        expira = expira.replace(tzinfo=timezone.utc)
        return (expira - datetime.now(timezone.utc)).days

    def executar(self, site):
        try:
            dias = self._dias_restantes(site)
        except ssl.SSLCertVerificationError:
            return {"status": "critico", "detalhe": "certificado inválido ou expirado"}

        if dias < 7:
            status = "critico"
        elif dias < 30:
            status = "atencao"
        else:
            status = "ok"
        return {"status": status, "detalhe": f"expira em {dias} dias"}


class VerificacaoWhois(Verificacao):
    nome = "Idade do domínio (WHOIS)"

    def executar(self, site):
        import whois  # pacote python-whois

        dados = whois.whois(site)
        criado = dados.creation_date
        if isinstance(criado, list):  # alguns registros devolvem várias datas
            criado = criado[0]
        if criado is None:
            return {"status": "atencao", "detalhe": "data de criação não informada"}

        if criado.tzinfo is None:
            criado = criado.replace(tzinfo=timezone.utc)
        idade = (datetime.now(timezone.utc) - criado).days

        if idade < 30:
            return {"status": "critico", "detalhe": f"domínio com {idade} dias (possível phishing)"}
        return {"status": "ok", "detalhe": f"domínio com {idade} dias"}


class VerificacaoIP(Verificacao):
    nome = "IP e localização"

    def executar(self, site):
        ip = socket.gethostbyname(site)
        info = requests.get(f"https://ipinfo.io/{ip}/json", timeout=10).json()
        local = f"{info.get('city', '?')}, {info.get('country', '?')}"
        return {"status": "ok", "detalhe": f"{ip} — {local} — {info.get('org', '?')}"}


# ----------------------------------------------------------------------
# POLIMORFISMO: o Verificador não sabe (nem precisa saber) qual
# checagem está rodando. Só chama executar().
# ----------------------------------------------------------------------
class Verificador:
    def __init__(self, verificacoes):
        self._verificacoes = verificacoes  # encapsulado: lista interna

    def analisar(self, site):
        print(f"\n🔍 Analisando {site}\n" + "-" * 40)
        for v in self._verificacoes:
            try:
                r = v.executar(site)
            except Exception as erro:  # uma falha não derruba as outras checagens
                r = {"status": "atencao", "detalhe": f"erro: {erro}"}
            print(f"{v.emoji(r['status'])} {v.nome}: {r['detalhe']}")


if __name__ == "__main__":
    site = input("Digite o domínio (ex.: google.com): ").strip()
    verificador = Verificador([
        VerificacaoHeaders(),
        VerificacaoCertificado(),
        VerificacaoWhois(),
        VerificacaoIP(),
    ])
    verificador.analisar(site)
from datetime import datetime, timezone
import socket
import ssl

import requests


HEADERS_IMPORTANTES = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
]


def verificar_headers(url):
    try:
        resposta = requests.get(url, timeout=10)
    except requests.RequestException as erro:
        print("Falha ao acessar o site:", erro)
        return 0

    print("Status HTTP:", resposta.status_code)
    pontos = 0

    for header in HEADERS_IMPORTANTES:
        if header in resposta.headers:
            print("✅", header)
            pontos += 1
        else:
            print("❌", header, "(faltando)")

    return pontos


def verificar_tls(site):
    contexto = ssl.create_default_context()

    try:
        with socket.create_connection((site, 443), timeout=10) as conexao:
            with contexto.wrap_socket(
                conexao,
                server_hostname=site,
            ) as tls:
                print("TLS negociado:", tls.version())
                print("Cifra:", tls.cipher()[0])

                certificado = tls.getpeercert()
                validade = datetime.fromtimestamp(
                    ssl.cert_time_to_seconds(certificado["notAfter"]),
                    tz=timezone.utc,
                )

                dias_restantes = (
                    validade - datetime.now(timezone.utc)
                ).total_seconds() / 86400

                print(
                    "Certificado vence em:",
                    validade.strftime("%d/%m/%Y %H:%M UTC"),
                )
                print(f"Dias restantes: {dias_restantes:.1f}")

                if dias_restantes <= 0:
                    print("❌ Certificado vencido")
                elif dias_restantes <= 30:
                    print("⚠️ Certificado vence em até 30 dias")
                else:
                    print("✅ Certificado válido por mais de 30 dias")

    except (OSError, ssl.SSLError) as erro:
        print("Falha na conexão TLS ou na validação do certificado:", erro)


def main():
    site = input("Qual site? Digite apenas o domínio: ").strip()

    if not site:
        print("Informe um domínio.")
        return

    url = "https://" + site
    pontos = verificar_headers(url)
    print("Nota dos headers:", pontos, "de", len(HEADERS_IMPORTANTES))

    verificar_tls(site)


if __name__ == "__main__":
    main()
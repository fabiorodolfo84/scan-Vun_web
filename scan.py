import requests
from requests.auth import HTTPBasicAuth
from datetime import datetime

def verifica_site(url, username=None, password=None):
    report = {"URL": url, "Data e Hora da Verificação": str(datetime.now())}
    try:
        if username and password:
            response = requests.get(url, auth=HTTPBasicAuth(username, password), verify=True)
        else:
            response = requests.get(url, verify=True)
        
        # Verifica se a requisição foi bem sucedida (código 200)
        if response.status_code == 200:
            # Verifica se o conteúdo da página contém palavras-chave indicativas de malware ou vírus
            if "malware" in response.text.lower() or "virus" in response.text.lower():
                report["Status"] = "Potencialmente Perigoso"
                print("O site pode conter malware ou vírus.")
            else:
                report["Status"] = "Seguro"
                print("O site parece estar seguro.")
            
            # Analisa os headers HTTP da resposta
            headers = response.headers
            report["Headers HTTP"] = headers
            
            # Verifica a presença de políticas de segurança de conteúdo (CSP) e cabeçalhos de segurança HTTP estritos (HSTS)
            if "content-security-policy" not in headers:
                report["CSP"] = "Ausente"
                print("\nO site não possui uma política de segurança de conteúdo (CSP).")
            else:
                report["CSP"] = headers["content-security-policy"]
            if "strict-transport-security" not in headers:
                report["HSTS"] = "Ausente"
                print("\nO site não possui um cabeçalho de segurança HTTP estrito (HSTS).")
            else:
                report["HSTS"] = headers["strict-transport-security"]
            
            # Integração com a API do Google Safe Browsing para verificar se o site é reportado como malicioso
            api_key = "SUA_API_KEY_DO_GOOGLE_SAFE_BROWSING"  # Substitua pela sua própria API key
            safe_browsing_api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
            payload = {
                "client": {
                    "clientId": "MeuCliente",
                    "clientVersion": "1.0"
                },
                "threatInfo": {
                    "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "MALICIOUS_BINARY", "POTENTIALLY_HARMFUL_APPLICATION"],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": url}]
                }
            }
            response = requests.post(safe_browsing_api_url, json=payload)
            if response.status_code == 200:
                data = response.json()
                if "matches" in data:
                    report["Google Safe Browsing"] = "Reportado como malicioso"
                    print("\nO site foi reportado como malicioso por outras fontes.")
                else:
                    report["Google Safe Browsing"] = "Não reportado como malicioso"
                    print("\nO site não foi reportado como malicioso por outras fontes.")
            else:
                report["Google Safe Browsing"] = "Falha na verificação"
                print("\nFalha ao acessar a API do Google Safe Browsing.")
        else:
            report["Status"] = "Falha ao acessar o site"
            print("Falha ao acessar o site. Código de status:", response.status_code)
    except requests.exceptions.SSLError:
        report["Status"] = "Erro de SSL/TLS"
        print("Ocorreu um erro de SSL/TLS ao tentar acessar o site. Certifique-se de que o certificado SSL do site é válido.")
    except Exception as e:
        report["Status"] = "Erro"
        print("Ocorreu um erro ao tentar acessar o site:", str(e))
    finally:
        # Geração do relatório
        with open("relatorio_verificacao.txt", "w") as file:
            for key, value in report.items():
                file.write(f"{key}: {value}\n")

# URL do site a ser verificado
url = "https://www.caraguatatuba.sp.gov.br/pmc/"
username = "seu_usuario"
password = "sua_senha"
verifica_site(url, username, password)

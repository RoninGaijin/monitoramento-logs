import csv
import os
import time
from datetime import datetime

LOG_AUTH = "/var/log/auth.log"
ARCHIVE_CSV = "logs_seguranca.csv"
ARQUIVOS_CRITICOS = ["/etc/passwd", "/etc/shadow"]

def registrar_evento(tipo, mensagem):
    with open(ARCHIVE_CSV, "a", newline="") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow([datetime.now(), tipo, mensagem])

def monitorar_login_invalido():
    if not os.path.exists(LOG_AUTH):
        return
    
    with open(LOG_AUTH, "r") as f:
        linhas = f.readlines()

    for linha in linhas:
        if "Failed password" in linha:
            registrar_evento("LOGIN_INVALIDO", linha.strip())

def monitorar_arquivos_criticos():
    for arquivo in ARQUIVOS_CRITICOS:
        if os.path.exists(arquivo):
            timestamp = os.path.getmtime(arquivo)
            registrar_evento("MOD_ARQUIVO_CRITICO", f"{arquivo} modificado - timestamp {timestamp}")

def monitorar_execucoes_suspeitas():
    comandos_sensiveis = ["nmap", "netcat", "nc", "hydra", "chmod 777"]
    history_file = os.path.expanduser("~/.bash_history")
    
    if not os.path.exists(history_file):
        return
    
    with open(history_file, "r") as f:
        linhas = f.readlines()

    for linha in linhas:
        for cmd in comandos_sensiveis:
            if cmd in linha:
                registrar_evento("EXECUCAO_SUSPEITA", linha.strip())

def main():
    print("[INFO] Iniciando monitoramento...")
    registrar_evento("INICIO", "Script iniciado")

    monitorar_login_invalido()
    monitorar_arquivos_criticos()
    monitorar_execucoes_suspeitas()

    print("[INFO] Monitoramento finalizado. Eventos registrados em logs_seguranca.csv")

if __name__ == "__main__":
    main()
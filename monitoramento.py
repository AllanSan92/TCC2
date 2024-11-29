import os
import time
import smtplib
from email.mime.text import MIMEText

# Configurações de email para alertas
EMAIL_REMETENTE = "allansantander@gmail.com"
EMAIL_SENHA = "Naty2816*"
EMAIL_DESTINO = "allansantander9210@gmail.com"
SMTP_SERVER = "smtp.gmail.com"  # Ex.: smtp.gmail.com
SMTP_PORT = 587

# Endereço IP do dispositivo IoT a ser monitorado
IP_DISPOSITIVO_IOT = "192.168.0.100"

# Função para enviar alerta por email
def enviar_alerta(mensagem):
    msg = MIMEText(mensagem)
    msg['Subject'] = 'Alerta de Disponibilidade IoT'
    msg['From'] = EMAIL_REMETENTE
    msg['To'] = EMAIL_DESTINO

    with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
        server.starttls()
        server.login(EMAIL_REMETENTE, EMAIL_SENHA)
        server.sendmail(EMAIL_REMETENTE, EMAIL_DESTINO, msg.as_string())

# Função para monitorar o dispositivo IoT
def monitorar_dispositivo():
    while True:
        resposta = os.system(f"ping -c 1 {IP_DISPOSITIVO_IOT}")
        if resposta == 0:
            print("Dispositivo IoT está online")
        else:
            print("Dispositivo IoT offline! Enviando alerta...")
            enviar_alerta(f"Dispositivo IoT com IP {IP_DISPOSITIVO_IOT} está offline.")
        
        # Intervalo de verificação (em segundos)
        time.sleep(60)  # Verifica a cada minuto

# Iniciar monitoramento
if __name__ == "__main__":
    monitorar_dispositivo()

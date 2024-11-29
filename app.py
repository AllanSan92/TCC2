import requests
from flask import Flask, render_template, request, jsonify, redirect, url_for, session
import mysql.connector
import pyotp
import bcrypt
import re
from mfrc522 import SimpleMFRC522
import RPi.GPIO as GPIO
from cryptography.fernet import Fernet
from multi_trust_core import MultiTrustCore
from datetime import datetime, timedelta
from dotenv import load_dotenv
import os
import subprocess
import threading
from queue import Queue
from scapy.all import sniff, IP, TCP, UDP

# Carregar as variáveis do arquivo .env
load_dotenv()

GPIO.setwarnings(False)  # Desabilita as advertências de uso dos pinos GPIO

app = Flask(__name__)

# Configurar a chave secreta a partir do .env
app.secret_key = os.getenv('FLASK_SECRET_KEY')

# Configuração do banco de dados
db_config = {
    'user': 'root',
    'password': '2816',
    'host': 'localhost',
    'database': 'iot_security',
}

# Carregar a chave de criptografia
with open("chave.key", "rb") as chave_arquivo:
    chave = chave_arquivo.read()

fernet = Fernet(chave)
reader = SimpleMFRC522()  # Inicializa o leitor RFID

# Inicialização do Multi-Trust Core
secure_channel = MultiTrustCore(path_to_executable='./workspace/multosI2CInterface')

# Função para validar a força da senha
def validar_senha(senha):
    padrao = r'^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$'
    return bool(re.match(padrao, senha))

# Função para criptografar a senha
def criptografar_senha(senha):
    return fernet.encrypt(senha.encode('utf-8')).decode('utf-8')

# Função para descriptografar a senha
def descriptografar_senha(senha_criptografada):
    return fernet.decrypt(senha_criptografada.encode('utf-8')).decode('utf-8')

# Função para registrar tentativa de login
def registrar_tentativa_login(usuario, sucesso, ip_usuario):
    try:
        db = mysql.connector.connect(**db_config)
        cursor = db.cursor()
        cursor.execute("INSERT INTO tentativas_login (usuario, sucesso, data_tentativa, ip_usuario) VALUES (%s, %s, %s, %s)",
                       (usuario, sucesso, datetime.now(), ip_usuario))
        db.commit()
    except mysql.connector.Error as err:
        print(f"Erro ao registrar tentativa de login: {err}")
    finally:
        if db.is_connected():
            cursor.close()
            db.close()

# Função para contar tentativas de login falhas nos últimos 10 minutos
def contar_tentativas_falhas(usuario, ip_usuario):
    try:
        db = mysql.connector.connect(**db_config)
        cursor = db.cursor()
        limite_tempo = datetime.now() - timedelta(minutes=10)
        cursor.execute("""
            SELECT COUNT(*) FROM tentativas_login 
            WHERE usuario = %s AND ip_usuario = %s AND sucesso = FALSE AND data_tentativa > %s
        """, (usuario, ip_usuario, limite_tempo))
        tentativas_falhas = cursor.fetchone()[0]
        return tentativas_falhas
    except mysql.connector.Error as err:
        print(f"Erro ao contar tentativas de login falhas: {err}")
        return 0
    finally:
        if db.is_connected():
            cursor.close()
            db.close()

# Função para validar o token do reCAPTCHA
def verificar_recaptcha(token):
    secret_key = '6Le5NIMqAAAAABuAWDFLd-q8fXVyzMu1IJr1nEDN'  # Chave secreta para a verificação
    url = 'https://www.google.com/recaptcha/api/siteverify'
    payload = {
        'secret': secret_key,
        'response': token
    }
    response = requests.post(url, data=payload)
    result = response.json()
    print("Resposta do reCAPTCHA:", result)  # Log para depuração
    return result.get('success', False)  # Verifica se a resposta do reCAPTCHA foi bem-sucedida

# Função para autenticar o usuário
def autenticar_usuario(rfid_id, senha, codigo_2fa, recaptcha_token, ip_usuario):
    print(f"Verificando reCAPTCHA para o usuário {rfid_id}...")
    if not verificar_recaptcha(recaptcha_token):
        print("Falha na verificação do reCAPTCHA.")
        return {"status": "failure", "message": "Falha na verificação do reCAPTCHA."}

    try:
        db = mysql.connector.connect(**db_config)
        cursor = db.cursor()

        # Verificar tentativas falhas
        cursor.execute("SELECT tentativas_falhas, ultima_tentativa FROM logs_tentativas WHERE rfid_id = %s", (rfid_id,))
        log_tentativa = cursor.fetchone()

        if log_tentativa:
            tentativas_falhas, ultima_tentativa = log_tentativa
            tempo_bloqueio = 10 * 60  # 10 minutos
            tempo_decorrido = (datetime.now() - ultima_tentativa).total_seconds()

            if tentativas_falhas >= 3 and tempo_decorrido < tempo_bloqueio:
                print("Usuário bloqueado devido a tentativas falhas.")
                return {"status": "failure", "message": "Acesso bloqueado. Tente novamente em alguns minutos."}

        # Buscar dados do usuário
        cursor.execute("SELECT id, nome, rfid_id, senha, segredo_2fa FROM usuarios WHERE rfid_id = %s", (rfid_id,))
        usuario = cursor.fetchone()

        if usuario:
            id_usuario, nome, rfid_id_db, senha_armazenada, segredo_2fa = usuario
            print(f"Usuário encontrado: {nome}. Verificando senha...")

            # Comparação de senha criptografada
            senha_armazenada = descriptografar_senha(senha_armazenada)
            if senha == senha_armazenada:
                print("Senha correta. Verificando código 2FA...")
                
                # Verificação do código 2FA
                totp = pyotp.TOTP(segredo_2fa)
                if totp.verify(codigo_2fa):
                    print("Código 2FA correto. Login bem-sucedido.")
                    # Login bem-sucedido, resetar tentativas falhas
                    cursor.execute("DELETE FROM logs_tentativas WHERE rfid_id = %s", (rfid_id,))
                    db.commit()
                    session['usuario'] = {'id': id_usuario, 'nome': nome}  # Salva o usuário na sessão
                    return {"status": "success", "message": f"Login bem-sucedido para {nome}!"}
                else:
                    print("Código 2FA incorreto.")
                    return registrar_tentativa_falha(cursor, db, rfid_id, "Código 2FA inválido.")
            else:
                print("Senha incorreta.")
                return registrar_tentativa_falha(cursor, db, rfid_id, "Senha incorreta.")
        else:
            print("Usuário não encontrado.")
            return registrar_tentativa_falha(cursor, db, rfid_id, "Usuário não encontrado!")
    except mysql.connector.Error as err:
        print(f"Erro ao conectar ao banco de dados: {err}")
        return {"status": "error", "message": f"Erro ao conectar ao banco de dados: {err}"}
    finally:
        if db.is_connected():
            cursor.close()
            db.close()

def registrar_tentativa_falha(cursor, db, rfid_id, mensagem):
    cursor.execute("""
        INSERT INTO logs_tentativas (rfid_id, tentativas_falhas, ultima_tentativa)
        VALUES (%s, 1, NOW())
        ON DUPLICATE KEY UPDATE tentativas_falhas = tentativas_falhas + 1, ultima_tentativa = NOW()
    """, (rfid_id,))
    db.commit()
    return {"status": "failure", "message": mensagem}

# Função para realizar ping em um único IP
def ping_ip(ip, dispositivos):
    try:
        resultado = subprocess.run(
            ["ping", "-c", "1", "-w", "1", ip],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        if resultado.returncode == 0:  # Dispositivo respondeu ao ping
            dispositivos.append({"ip": ip, "status": "online"})
    except Exception as e:
        print(f"Erro ao verificar o IP {ip}: {e}")

# Função para listar dispositivos conectados à mesma rede usando threads
def listar_dispositivos():
    sub_rede = "172.20.10."  # Altere para a sub-rede da sua rede local
    dispositivos = []
    threads = []
    queue = Queue()

    def scan_dispositivo(ip):
        nm = nmap.PortScanner()
        try:
            nm.scan(hosts=ip, arguments='-sn')  # -sn faz um "ping scan" sem escanear portas
            if nm.all_hosts():
                dispositivos.append({
                    'ip': ip,
                    'status': nm[ip].state()
                })
        except Exception as e:
            print(f"Erro ao escanear {ip}: {e}")

    # Criar threads para varrer os IPs
    for i in range(1, 255):
        ip = f"{sub_rede}{i}"
        thread = threading.Thread(target=ping_ip, args=(ip, dispositivos))
        threads.append(thread)
        thread.start()

    # Aguardar todas as threads concluírem
    for thread in threads:
        thread.join()

    return dispositivos

# Lista para armazenar dispositivos monitorados
dispositivos_monitorados = []

# Função para iniciar a captura de pacotes na interface especificada
def capturar_trafego():
    def analisar_pacote(pacote):
        # Filtra pacotes TCP/UDP/IP
        if pacote.haslayer(IP):
            ip_origem = pacote[IP].src
            ip_destino = pacote[IP].dst
            porta_destino = pacote[TCP].dport if pacote.haslayer(TCP) else pacote[UDP].dport if pacote.haslayer(UDP) else None
            
            # Exclua o próprio IP do Raspberry Pi
            ip_local = requests.get('https://api64.ipify.org').text
            if ip_origem == ip_local or ip_destino == ip_local:
                return

            # Log básico no console
            print(f"[CAPTURA] De {ip_origem} para {ip_destino} na porta {porta_destino}")
            
            # Identificar atividades suspeitas (exemplo: porta não usual)
            portas_conhecidas = [80, 443, 22]  # HTTP, HTTPS, SSH
            if porta_destino not in portas_conhecidas:
                with open("logs_suspeitos.txt", "a") as log:
                    log.write(f"Atividade suspeita: {ip_origem} para {ip_destino} na porta {porta_destino}\n")
                print(f"[ALERTA] Tráfego suspeito detectado de {ip_origem} para {ip_destino} na porta {porta_destino}")
    
    # Inicia a captura
    print("[INFO] Captura de tráfego iniciada!")
    sniff(prn=analisar_pacote, store=False)

def bloquear_ip(ip):
    try:
        subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)
        subprocess.run(["sudo", "iptables", "-A", "FORWARD", "-s", ip, "-j", "DROP"], check=True)
        print(f"[AÇÃO] IP {ip} bloqueado com sucesso.")
        return True
    except subprocess.CalledProcessError as e:
        print(f"[ERRO] Falha ao bloquear IP {ip}: {e}")
        return False

# Defina o caminho do arquivo de logs
LOGS_PATH = "logs.txt"

# Função para ler logs
def ler_logs():
    """Lê os logs do arquivo e retorna como uma lista de dicionários."""
    logs = []
    if os.path.exists(LOGS_PATH):  # Verifica se o arquivo de logs existe
        with open(LOGS_PATH, "r") as f:
            for linha in f:
                # Dividir o log em partes (Ex.: Data, IP, Ação)
                partes = linha.strip().split(" - ")
                if len(partes) == 3:  # Certifique-se de que o log está no formato correto
                    logs.append({"data": partes[0], "ip": partes[1], "acao": partes[2]})
    return logs
    
# Função para adicionar um log
def adicionar_log(mensagem):
    """Adiciona uma nova mensagem ao arquivo de log."""
    with open(LOGS_PATH, "a") as f:
        f.write(mensagem + "\n")

# Função para listar os logs
def listar_logs():
    """Retorna os logs em formato de lista de dicionários."""
    logs = []
    if os.path.exists(LOGS_PATH):
        with open(LOGS_PATH, "r") as f:
            for linha in f:
                partes = linha.strip().split(" - ")
                if len(partes) == 3:
                    logs.append({"data": partes[0], "ip": partes[1], "acao": partes[2]})
    return logs

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/ler_rfid', methods=['POST'])
def ler_rfid():
    try:
        print("Lendo o cartão RFID...")
        rfid_id, _ = reader.read()  # Leitura do cartão RFID
        print(f"ID do RFID lido: {rfid_id}")
        return jsonify({'status': 'success', 'rfid_id': rfid_id})
    except Exception as e:
        print(f"Erro ao ler o cartão RFID: {e}")
        return jsonify({'status': 'failure', 'message': 'Erro ao ler o cartão RFID'})

@app.route('/home')
def home():
    # Verifica se o usuário está autenticado e renderiza a página inicial
    if 'usuario' in session:
        return render_template('home.html', usuario=session['usuario'])
    return redirect(url_for('index'))

@app.route('/login', methods=['POST'])
def login():
    rfid_id = request.form['rfid_id']
    senha = request.form['senha']
    codigo_2fa = request.form['codigo_2fa']
    recaptcha_token = request.form['recaptcha_token']
    ip_usuario = request.remote_addr

    autenticacao_resultado = autenticar_usuario(rfid_id, senha, codigo_2fa, recaptcha_token, ip_usuario)

    if autenticacao_resultado["status"] == "success":
        return jsonify(autenticacao_resultado)
    else:
        return jsonify(autenticacao_resultado), 400

@app.route('/visualizar_logs', methods=['GET'])
def visualizar_logs():
    """Retorna os logs em formato JSON ou uma mensagem de erro se não houver logs."""
    try:
        logs = ler_logs()  # Chama a função para ler os logs
        if not logs:
            return jsonify({"erro": "Nenhum log encontrado."}), 404  # Retorna 404 se não houver logs
        return jsonify(logs)  # Retorna os logs em formato JSON
    except Exception as e:
        return jsonify({"erro": str(e)}), 500  # Retorna 500 se ocorrer algum erro

@app.route('/listar_dispositivos', methods=['GET'])
def listar_dispositivos_ajax():
    dispositivos = listar_dispositivos()  # Realiza a varredura na rede
    return jsonify(dispositivos)  # Retorna os dispositivos como JSON
    
@app.route('/logout', methods=['GET'])
def logout():
    session.clear()  # Limpa todos os dados da sessão
    return redirect(url_for('index'))  # Redireciona para a página de login

@app.route('/capturar_trafego', methods=['GET'])
def capturar_trafego():
    # Inicia a captura de pacotes em uma thread separada
    thread = threading.Thread(target=iniciar_captura, args=("eth0",))
    thread.daemon = True  # Permite que o programa principal encerre a thread
    thread.start()
    return jsonify({"status": "success", "message": "Captura de tráfego iniciada!"})

@app.route('/bloqueios', methods=['GET'])
def listar_bloqueios():
    bloqueios = subprocess.check_output(["sudo", "iptables", "-L", "-n"]).decode("utf-8")
    return render_template('bloqueios.html', bloqueios=bloqueios)

@app.route('/desbloquear', methods=['POST'])
def desbloquear_ip():
    ip = request.form['ip']
    try:
        subprocess.run(["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"], check=True)
        subprocess.run(["sudo", "iptables", "-D", "FORWARD", "-s", ip, "-j", "DROP"], check=True)
        return jsonify({"status": "success", "message": f"IP {ip} desbloqueado com sucesso."})
    except subprocess.CalledProcessError as e:
        return jsonify({"status": "failure", "message": f"Erro ao desbloquear IP {ip}: {e}"})



if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)

    #app.run(debug=True)

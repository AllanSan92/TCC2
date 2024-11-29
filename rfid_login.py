import mysql.connector
import pyotp
import qrcode
from mfrc522 import SimpleMFRC522
import time
import getpass
import bcrypt

# Configuração do banco de dados
db_config = {
    'user': 'root',
    'password': '2816',  # Alterar para a sua senha de root no MariaDB
    'host': 'localhost',
    'database': 'iot_security',
}

# Função para registrar um novo usuário
def registrar_usuario(nome, rfid_id, senha):
    try:
        # Gerar segredo 2FA
        totp = pyotp.TOTP(pyotp.random_base32())  # Gerar segredo aleatório
        segredo_2fa = totp.secret
        print(f"Segredo 2FA gerado para {nome}: {segredo_2fa}")
        
        # Criar o código QR para o aplicativo de autenticação
        uri = totp.provisioning_uri(nome, issuer_name="IoT Security")
        qr = qrcode.make(uri)
        qr.show()  # Exibe o QR code para o aplicativo de autenticação

        # Hash da senha
        senha_hash = bcrypt.hashpw(senha.encode('utf-8'), bcrypt.gensalt())

        # Conectar ao banco de dados
        db = mysql.connector.connect(**db_config)
        cursor = db.cursor()

        # Inserir o novo usuário no banco de dados
        cursor.execute("INSERT INTO usuarios (nome, rfid_id, senha, segredo_2fa) VALUES (%s, %s, %s, %s)",
                       (nome, rfid_id, senha_hash, segredo_2fa))
        db.commit()
        print(f"Usuário {nome} registrado com sucesso!")

    except mysql.connector.Error as err:
        print(f"Erro ao conectar ao banco de dados: {err}")
    finally:
        if db.is_connected():
            cursor.close()
            db.close()

# Função para autenticar o usuário
def autenticar_usuario(rfid_id):
    try:
        # Conectar ao banco de dados
        db = mysql.connector.connect(**db_config)
        cursor = db.cursor()

        # Buscar os dados do usuário com o RFID
        cursor.execute("SELECT id, nome, rfid_id, senha, segredo_2fa FROM usuarios WHERE rfid_id = %s", (rfid_id,))
        usuario = cursor.fetchone()

        if usuario:
            id_usuario, nome, rfid_id_db, senha_armazenada, segredo_2fa = usuario
            print(f"Usuário encontrado: {nome}")
            senha = getpass.getpass("Digite sua senha: ")

            # Verificar a senha
            if bcrypt.checkpw(senha.encode('utf-8'), senha_armazenada.encode('utf-8')):
                print("Senha correta!")
                print("Por favor, insira o código de autenticação de dois fatores (2FA):")
                codigo_2fa = getpass.getpass("Código 2FA: ")

                # Verificar o código 2FA
                totp = pyotp.TOTP(segredo_2fa)
                if totp.verify(codigo_2fa):
                    print(f"Login bem-sucedido para {nome}!")
                    return True
                else:
                    print("Código 2FA inválido. Tente novamente.")
                    return False
            else:
                print("Senha incorreta!")
                return False
        else:
            print("Usuário não encontrado!")
            return False
    except mysql.connector.Error as err:
        print(f"Erro ao conectar ao banco de dados: {err}")
        return False
    finally:
        if db.is_connected():
            cursor.close()
            db.close()

# Função principal para iniciar o processo de login ou registro
def main():
    reader = SimpleMFRC522()

    while True:
        print("Escolha uma opção:")
        print("1. Registrar novo usuário")
        print("2. Login com RFID e 2FA")
        opcao = input("Digite sua opção: ")

        if opcao == '1':
            nome = input("Digite o nome do novo usuário: ")
            senha = getpass.getpass("Digite a senha para o novo usuário: ")
            print("Aproxime um cartão RFID...")
            id, text = reader.read()
            print(f"ID do cartão lido: {id}")
            registrar_usuario(nome, id, senha)

        elif opcao == '2':
            print("Aproxime um cartão RFID...")
            id, text = reader.read()
            print(f"ID do cartão lido: {id}")

            # Chamar a função de autenticação
            if autenticar_usuario(id):
                break

if __name__ == "__main__":
    main()

from cryptography.fernet import Fernet

# Gere e armazene a chave de criptografia
chave = Fernet.generate_key()
cipher = Fernet(chave)

# Função para criptografar dados
def criptografar_dados(mensagem):
    mensagem_bytes = mensagem.encode()
    mensagem_criptografada = cipher.encrypt(mensagem_bytes)
    print("Dados Criptografados:", mensagem_criptografada)
    return mensagem_criptografada

# Função para descriptografar dados
def descriptografar_dados(dados_criptografados):
    dados_descriptografados = cipher.decrypt(dados_criptografados)
    print("Dados Descriptografados:", dados_descriptografados.decode())
    return dados_descriptografados.decode()

# Teste de criptografia
mensagem = "Mensagem sensível do dispositivo IoT"
dados_criptografados = criptografar_dados(mensagem)

# Teste de descriptografia
descriptografar_dados(dados_criptografados)
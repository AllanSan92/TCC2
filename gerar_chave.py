from cryptography.fernet import Fernet

# Gerar uma chave secreta para o sistema
chave = Fernet.generate_key()

# Armazenar a chave de forma segura (não compartilhe!)
with open("chave.key", "wb") as chave_arquivo:
    chave_arquivo.write(chave)

print("Chave gerada e salva em chave.key")

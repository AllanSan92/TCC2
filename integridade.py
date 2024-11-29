import hashlib

# Função para gerar o hash dos dados
def gerar_hash(dados):
    hash_obj = hashlib.sha256(dados.encode())
    return hash_obj.hexdigest()

# Função para verificar a integridade dos dados
def verificar_integridade(dados, hash_original):
    hash_calculado = gerar_hash(dados)
    if hash_calculado == hash_original:
        print("Integridade verificada com sucesso! Dados não alterados.")
        return True
    else:
        print("Falha na verificação de integridade! Dados podem ter sido alterados.")
        return False

# Exemplo de uso
mensagem = "Dados Sensíveis do IoT"
hash_mensagem = gerar_hash(mensagem)

# Simulando envio e verificação no lado receptor
print(f"Hash original: {hash_mensagem}")
verificar_integridade(mensagem, hash_mensagem)

# Teste de falha de integridade (modifique a mensagem para simular alteração)
mensagem_alterada = "Dados Sensíveis Alterados do IoT"
verificar_integridade(mensagem_alterada, hash_mensagem)

import pyotp

# Crie uma chave secreta única para o usuário (pode ser armazenada em um banco de dados)
chave_secreta = pyotp.random_base32()
print(f"Chave secreta (armazene com segurança): {chave_secreta}")

# Inicialize o gerador TOTP com a chave secreta
totp = pyotp.TOTP(chave_secreta)

# Gere o código OTP atual
otp_code = totp.now()
print(f"Código OTP atual: {otp_code}")

# Verifique o código OTP (usado pelo usuário)
def verificar_codigo(otp_input):
    if totp.verify(otp_input):
        print("Código OTP verificado com sucesso!")
    else:
        print("Código OTP incorreto.")

# Exemplo de uso
codigo_do_usuario = input("Digite o código OTP: ")
verificar_codigo(codigo_do_usuario)

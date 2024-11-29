import RPi.GPIO as GPIO
from mfrc522 import SimpleMFRC522

# Definindo os IDs dos cartões válidos
cartoes_validos = [366485449239, 590560146330]  # Substitua com os IDs reais dos seus cartões

reader = SimpleMFRC522()

try:
    print("Aproxime um cartão RFID...")
    id, text = reader.read()
    
    print(f"ID do cartão: {id}")
    
    # Verificando se o ID lido é válido
    if id in cartoes_validos:
        print("Cartão válido!")
    else:
        print("Cartão inválido!")

except Exception as e:
    print(f"Erro: {e}")
finally:
    GPIO.cleanup()
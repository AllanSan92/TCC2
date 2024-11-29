import RPi.GPIO as GPIO
from mfrc522 import SimpleMFRC522

reader = SimpleMFRC522()

try:
    print("Aproxime um cartão RFID...")
    id, text = reader.read()
    print(f"ID do cartão: {id}")
    print(f"Texto: {text}")
except Exception as e:
    print(f"Erro: {e}")
finally:
    GPIO.cleanup()

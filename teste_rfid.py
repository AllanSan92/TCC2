from mfrc522 import SimpleMFRC522

reader = SimpleMFRC522()

try:
    print("Aproxime o cartão RFID...")
    id, text = reader.read()
    print(f"ID: {id}")
    print(f"Texto: {text}")
except Exception as e:
    print(f"Erro ao ler o RFID: {e}")
finally:
    GPIO.cleanup()

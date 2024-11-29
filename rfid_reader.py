import RPi.GPIO as GPIO
from mfrc522 import SimpleMFRC522
import time

# Inicializando o leitor RFID
reader = SimpleMFRC522()

# Caminho do arquivo para armazenar o ID do RFID
rfid_file = "/home/pi/rfid_id.txt"

try:
    print("Aproxime um cartão RFID...")
    while True:
        id, text = reader.read()
        print(f"ID do cartão: {id}")
        # Escreve o ID do cartão RFID no arquivo
        with open(rfid_file, "w") as file:
            file.write(str(id))
        time.sleep(1)  # Evita múltiplas leituras rápidas
except KeyboardInterrupt:
    print("Processo interrompido.")
finally:
    GPIO.cleanup()

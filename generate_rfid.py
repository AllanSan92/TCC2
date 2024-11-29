import json
import random

# IDs de cartões RFID de exemplo
rfid_ids = ["366485449239", "590560146330"]

# Simula a leitura de um ID de RFID aleatório
rfid_id = random.choice(rfid_ids)

# Cria um arquivo JSON para armazenar o ID do RFID
data = {'rfid_id': rfid_id}

# Salva o ID em um arquivo JSON
with open('rfid_data.json', 'w') as json_file:
    json.dump(data, json_file)

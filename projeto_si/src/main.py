import os
import hashlib
import json
import hmac
import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from getpass import getpass
import base64
from rich.console import Console
from rich.prompt import Prompt
from rich.table import Table

console = Console()

project_dir = os.path.dirname(os.path.abspath(__file__))

# Função para derivar a chave - PBKDF2
def derive_key(password, salt, length=32):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    return key

# Função para cifrar dados usando a cifra AES-128 no modo CBC
def encrypt(data, key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padding_length = 16 - len(data) % 16
    data += bytes([padding_length]) * padding_length
    encrypted_data = encryptor.update(data) + encryptor.finalize()
    return iv + encrypted_data

# Função para decifrar dados usando a cifra AES-128 no modo CBC 
def decrypt(encrypted_data, key):
    iv = encrypted_data[:16]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    data = decryptor.update(encrypted_data[16:]) + decryptor.finalize()
    padding_length = data[-1]
    return data[:-padding_length]

# Função para calcular o hash SHA256
def calculate_hash(file_path):
    sha256 = hashlib.sha256()
    try:
        with open(file_path, 'rb') as f:
            while chunk := f.read(4096):
                sha256.update(chunk)
    except FileNotFoundError:
        console.print(f"[red]O ficheiro não foi encontrado: {file_path}[/red]")
        return None
    return sha256.hexdigest()

# Função para calcular o hash da palavra-passe
def calculate_password_hash(password):
    sha256 = hashlib.sha256()
    sha256.update(password.encode())
    return sha256.hexdigest()

# Função para assinar dados - RSA
def sign_data(data, private_key):
    signature = private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

# Função para verificar a assinatura - RSA
def verify_signature(data, signature, public_key):
    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        console.print(f"[red]A Verificação da assinatura falhou: {e}[/red]")
        return False

# Função para criar o par de chaves RSA
def generate_rsa_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

# Função para guardar a chave privada cifrada
def save_encrypted_private_key(private_key, password, directory):
    salt = os.urandom(16)
    key = derive_key(password, salt, length=32)
    private_key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    encrypted_private_key = encrypt(private_key_bytes, key)
    with open(os.path.join(directory, 'private_key.enc'), 'wb') as f:
        f.write(salt + encrypted_private_key)

# Função para carregar a chave privada cifrada
def load_encrypted_private_key(password, directory):
    with open(os.path.join(directory, 'private_key.enc'), 'rb') as f:
        salt = f.read(16)
        encrypted_private_key = f.read()
    key = derive_key(password, salt, length=32)
    private_key_bytes = decrypt(encrypted_private_key, key)
    private_key = serialization.load_pem_private_key(
        private_key_bytes,
        password=None,
        backend=default_backend()
    )
    return private_key

# Função para criar a base de dados
def create_database(directory, password):
    password_hash = calculate_password_hash(password)
    password_hash_path = os.path.join(directory, "password_hash.txt")

    if os.path.exists(password_hash_path):
        with open(password_hash_path, 'r') as f:
            stored_password_hash = f.read().strip()
        if stored_password_hash != password_hash:
            console.print("[red]A diretoria já foi cifrada com uma palavra-passe diferente. Usa a palavra-passe correta para verificar a integridade dos ficheiros.[/red]")
            return

    private_key, public_key = generate_rsa_key_pair()
    save_encrypted_private_key(private_key, password, directory)
    db_path = os.path.join(directory, "file_integrity_db.json")

    file_data = {}
    for root, dirs, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            # Ignorar o próprio ficheiro da base de dados
            if file_path == db_path or file_path.endswith("password_hash.txt") or file_path.endswith("private_key.enc"):
                continue
            file_hash = calculate_hash(file_path)
            if file_hash is None:
                continue
            signature = sign_data(file_hash.encode(), private_key)
            file_data[file_path] = {
                'hash': file_hash,
                'signature': base64.b64encode(signature).decode('utf-8')
            }

    with open(db_path, 'w') as f:
        json.dump(file_data, f)
    with open(password_hash_path, 'w') as f:
        f.write(password_hash)
    console.print("[green]Base de dados criada com sucesso.[/green]")

# Função para verificar a integridade dos ficheiros
def check_integrity(directory, password):
    password_hash = calculate_password_hash(password)
    password_hash_path = os.path.join(directory, "password_hash.txt")
    
    if not os.path.exists(password_hash_path):
        console.print("[red]Base de dados não encontrada. Por favor, cria a base de dados primeiro.[/red]")
        return
    
    with open(password_hash_path, 'r') as f:
        stored_password_hash = f.read().strip()
    
    if stored_password_hash != password_hash:
        console.print("[red]Palavra-passe incorreta.[/red]")
        return

    private_key = load_encrypted_private_key(password, directory)
    public_key = private_key.public_key()

    db_path = os.path.join(directory, "file_integrity_db.json")
    if not os.path.exists(db_path):
        console.print("[red]Base de dados não encontrada. Por favor, cria a base de dados primeiro.[/red]")
        return

    with open(db_path, 'r') as f:
        file_data = json.load(f)

    for file_path, stored_values in file_data.items():
        current_hash = calculate_hash(file_path)
        if current_hash is None:
            continue
        signature = base64.b64decode(stored_values['signature'])
        if current_hash != stored_values['hash'] or not verify_signature(stored_values['hash'].encode(), signature, public_key):
            console.print(f"[red]Alteração detetada no ficheiro: {file_path}[/red]")
            file_data[file_path]['hash'] = current_hash
            file_data[file_path]['signature'] = base64.b64encode(sign_data(current_hash.encode(), private_key)).decode('utf-8')

    with open(db_path, 'w') as f:
        json.dump(file_data, f)
    console.print("[green]Verificação da integridade concluída. Base de dados atualizada com sucesso.[/green]")

# Classe para a manipulação de eventos das alterações dos ficheiros
class Watcher(FileSystemEventHandler):
    def __init__(self, directory, password):
        self.directory = directory
        self.password = password

    def on_modified(self, event):
        if not event.is_directory:
            console.print(f"[yellow]Ficheiro modificado: {event.src_path}[/yellow]")
            check_integrity(self.directory, self.password)

def start_monitoring(directory, password):
    event_handler = Watcher(directory, password)
    observer = Observer()
    observer.schedule(event_handler, directory, recursive=True)
    observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

# Função de help
def show_help():
    table = Table(title="Help - ESTOU-TA-VER: um Monitor para Integridade para Diretorias")

    table.add_column("Comando", style="cyan", no_wrap=True)
    table.add_column("Descrição", style="magenta")

    table.add_row("1", "Cria uma nova base de dados de integridade para a diretoria especificada.")
    table.add_row("2", "Verifica a integridade dos ficheiros na diretoria especificada comparando com a base de dados existente.")
    table.add_row("3", "Inicia o monitoramento em tempo real das alterações nos ficheiros da diretoria especificada.")
    table.add_row("4", "Exibe esta ajuda detalhada.")
    table.add_row("5", "Sai do programa.")

    console.print(table)

# Menu interativo
def main():
    while True:
        console.print("\n[bold blue]Menu:[/bold blue]")
        console.print("1. Criar base de dados de integridade")
        console.print("2. Verificar integridade dos ficheiros")
        console.print("3. Iniciar monitoramento em tempo real")
        console.print("4. Ajuda")
        console.print("5. Sair")
        choice = Prompt.ask("Escolha uma opção")

        if choice == '1':
            directory = Prompt.ask("Digite o caminho da diretoria a monitorizar")
            password = getpass("Digite a palavra-passe: ")
            create_database(directory, password)
        elif choice == '2':
            directory = Prompt.ask("Digite o caminho da diretoria a monitorizar")
            password = getpass("Digite a palavra-passe: ")
            check_integrity(directory, password)
        elif choice == '3':
            directory = Prompt.ask("Digite o caminho da diretoria a monitorizar")
            password = getpass("Digite a palavra-passe: ")
            start_monitoring(directory, password)
        elif choice == '4':
            show_help()
        elif choice == '5':
            console.print("[bold blue]A Sair...[/bold blue]")
            break
        else:
            console.print("[red]Opção inválida. Por favor, escolhe novamente.[/red]")

if __name__ == "__main__":
    main()

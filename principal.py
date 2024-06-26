from Crypto.Cipher import DES, PKCS1_OAEP #biblioteca para criptografia DES e RSA
from Crypto.PublicKey import RSA #bliblioteca para criptografia RSA
from Crypto.Util.Padding import pad, unpad #biblioteca para padding
from Crypto.Random import get_random_bytes
import binascii
import os

#função para ajustar a chave DES
def ajustar_chave_des(chave):
    chave_ajustada = chave[:8].ljust(8, '\0')
    return chave_ajustada.encode()

#função para criptografar a mensagem
def des_encrypt(mensagem, chave):
    chave = ajustar_chave_des(chave) #ajusta a chave DES
    cipher = DES.new(chave, DES.MODE_ECB) #cria um objeto DES com a chave e o modo de operação
    ct_bytes = cipher.encrypt(pad(mensagem.encode(), DES.block_size)) #criptografa a mensagem
    ct = binascii.hexlify(ct_bytes).decode('utf-8') #converte a mensagem criptografada para hexadecimal
    return ct #retorna a mensagem criptografada

def des_decrypt(ct, chave): #descriptografa a mensagem
    chave = ajustar_chave_des(chave) #ajusta a chave DES
    ct_bytes = binascii.unhexlify(ct) #converte a mensagem criptografada de hexadecimal para bytes
    cipher = DES.new(chave, DES.MODE_ECB)
    pt = unpad(cipher.decrypt(ct_bytes), DES.block_size) #descriptografa a mensagem
    return pt.decode('utf-8')

def rsa_encrypt(mensagem, chave_publica):  #criptografa a mensagem
    encryptor = PKCS1_OAEP.new(chave_publica) #cria um objeto RSA com a chave pública
    encrypted = encryptor.encrypt(mensagem.encode()) #criptografa a mensagem
    return binascii.hexlify(encrypted).decode('utf-8') #converte a mensagem criptografada para hexadecimal

def rsa_decrypt(encrypted, chave_privada):  #descriptografa a mensagem
    decryptor = PKCS1_OAEP.new(chave_privada) #cria um objeto RSA com a chave privada
    decrypted = decryptor.decrypt(binascii.unhexlify(encrypted.encode())) #descriptografa a mensagem
    return decrypted.decode('utf-8') #retorna a mensagem descriptografada

def verificar_ou_criar_chaves_rsa(): #verifica se as chaves RSA já existem, caso contrário, cria
    if not os.path.exists("public.pem") or not os.path.exists("private.pem"): #verifica se as chaves já existem
        key = RSA.generate(2048) #gera um par de chaves RSA
        private_key = key.export_key() #exporta a chave privada
        with open("private.pem", "wb") as f:   #salva a chave privada em um arquivo
            f.write(private_key) 
        public_key = key.publickey().export_key() #exporta a chave pública
        with open("public.pem", "wb") as f:
            f.write(public_key)

#função principal
def main():
    escolha = input("Escolha o método criptográfico (1 para Simétrico/DES, 2 para Assimétrico/RSA): ")
    operacao = input("Escolha a operação (1 para Criptografar, 2 para Descriptografar): ")
    mensagem = input("Digite a mensagem: ")

    if escolha == '1':  # DES
        chave = input("Digite a chave (8 caracteres): ")
        if operacao == '1':
            print("Mensagem criptografada:", des_encrypt(mensagem, chave))
        elif operacao == '2':
            print("Mensagem descriptografada:", des_decrypt(mensagem, chave))
    elif escolha == '2':  # RSA
        verificar_ou_criar_chaves_rsa()
        if operacao == '1':
            chave_publica = RSA.import_key(open("public.pem", "rb").read())
            print("Mensagem criptografada:", rsa_encrypt(mensagem, chave_publica))
        elif operacao == '2':
            chave_privada = RSA.import_key(open("private.pem", "rb").read())
            print("Mensagem descriptografada:", rsa_decrypt(mensagem, chave_privada))

if __name__ == "__main__":
    main()
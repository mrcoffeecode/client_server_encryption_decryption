'''
Created on Apr 27, 2022

@author: Axell Martinez & Chance Merrill 
'''
import socket
from Crypto.Cipher import AES

IP = socket.gethostbyname(socket.gethostname())
PORT = 4326
ADDR = (IP, PORT)
FORMAT = "utf-8"
SIZE = 1024
CIPHER_KEY=b'PdSgVkYp3s5v8y/B'
data =""

def data_decryption(plain_text):
    decryption = ""
    ascii_text = ""
    
    for i,v in enumerate(plain_text):
        binary_array = v.encode("raw_unicode_escape")
        ascii_value = int.from_bytes(binary_array, "big") 
        
        binary_sum = bin(ascii_value)
        flipB = flipbit('{:0>7}'.format(binary_sum[2:])) # Flip bits
        ascii_value = int(flipB,2)
        
        ascii_value = ascii_value + int("0b00000111",2) # add 7
        
        binary_sum = bin(ascii_value)
        flipB = flipbit('{:0>7}'.format(binary_sum[2:])) # Flip bits
        ascii_value = int(flipB,2)
        
        ascii_value = ascii_value - int("0b00000101",2) # sub 5
        binary_sum = bin(ascii_value) # Represent the ASCII code of the character in 8-bit binary format
        binary_sum = rotate_bit_right('{:0>7}'.format(binary_sum[2:]),1) # rotate to the right 1 bit
        ascii_value = int(binary_sum,2)
        
        ascii_value = ascii_value - int("0b00000010",2) # sub 2
        
        binary_array = ascii_value.to_bytes(1, "big")
        ascii_text = binary_array.decode()
        decryption += str(ascii_text)
    return decryption

def rotate_bit_left(s,d): 
    Lfirst = s[0 : d] 
    Lsecond = s[d :] 
    return (Lsecond + Lfirst)

def rotate_bit_right(s,d): 
    Rfirst = s[0 : (len(s))-d] 
    Rsecond = s[len(s)-d : ]  
    return (Rsecond + Rfirst)
    
def flipbit(bit_s):
    a = bit_s
    c = ''.join('1' if x == '0' else '0' for x in a)
    return c

def main():
    print("[STARTING] Server is starting.")
    # Staring socket.
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
 
    # Bind the IP and PORT
    server.bind(ADDR)
 
    # Server is listening ; standing by.
    server.listen()
    print("[LISTENING] Server is listening.")
 
    while True:
        # Server has accepted the connection from the client.
        conn, addr = server.accept()
        print(f"[NEW CONNECTION] {addr} connected.")
 
        # Receiving the filename from the client.
        filename = conn.recv(SIZE).decode(FORMAT)
        print(f"[RECV] Receiving the filename.")
        file = open("serverdata/"+filename, "w")
        conn.send("Filename received.".encode(FORMAT))

        #Receiving the file data and nonce from the client.
        data = conn.recv(SIZE)
        nonce= conn.recv(SIZE)
        print(f"[RECV] Receiving the file data.")
        print(" ")
        print("Cipher Validation (Receive from Client): ",nonce)
        # Decryption Process
        ciphertext=data.decode(FORMAT)
        cipher2 = AES.new(CIPHER_KEY, AES.MODE_EAX, nonce = nonce)
        plaintext = data_decryption(ciphertext)
        Message = plaintext
        
        #file.write(str(data))
        print(" ")
        file.write(Message)
        print("Data Decryption:",Message)
        print(" ")
        conn.send("File data received".encode(FORMAT))
 
        #Close the file.
        file.close()
 
        # Close the connection from the client.
        conn.close()
        print(f"[DISCONNECTED] {addr} disconnected.")
 
if __name__ == "__main__":
    main()
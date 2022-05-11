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

def data_encryption(plain_text):
    encryption = ""
    ascii_text = ""
    
    for i,v in enumerate(plain_text):
        binary_array = v.encode("raw_unicode_escape")
        # Represent the ASCII code of the character in 8-bit binary format or easier in ASCII value
        ascii_value = int.from_bytes(binary_array, "big")
        
        binary_form = ascii_value + int("0b00000010",2) # add 2
        
        binary_sum = bin(binary_form)
        binary_sum =rotate_bit_left('{:0>7}'.format(binary_sum[2:]),1) # rotate to the left 1 bit
        ascii_value = int(binary_sum,2)
        
        ascii_value = ascii_value + int("0b00000101",2) # add 5
        
        binary_sum = bin(ascii_value)
        flipB = flipbit('{:0>7}'.format(binary_sum[2:]))  # Flip bits
        ascii_value = int(flipB,2)
        
        ascii_value = ascii_value - int("0b00000111",2) # sub 7 
        
        binary_sum = bin(ascii_value)
        flipB = flipbit('{:0>7}'.format(binary_sum[2:]))  # Flip bits
        ascii_value = int(flipB,2)
        
        binary_array = ascii_value.to_bytes(1, "big")
        ascii_text = binary_array.decode()
        encryption += str(ascii_text)
    return encryption

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
    # Staring socket.
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
 
    # Connecting to the server.
    client.connect(ADDR)
 
    # Open & read the data from file.
    file = open("clientdata/chat.txt", "r")
    data = file.read()
    
    # Get Secret Message from file 
    Secret_Message= bytes(data, 'utf-8')
    Message = Secret_Message.decode()
    print("Secret_Message ( Before Sent To Server): ")
    print(Message)
    print(" ")
    # Create cipher object and encrypt the data 
    CIPHER = AES.new(CIPHER_KEY, AES.MODE_EAX)
    
    sc = data_encryption(data)
    print("Data Encryption: ")
    print(sc)
    print(" ")
    # The recipient can obtain the original message using the same key 
    # and the incoming triple (nonce, ciphertext, tag)
    nonce = CIPHER.nonce
    print("Cipher Validation (Sent To Server): ",nonce)
    print(" ")
    # Encrypt and digest to get the ciphered data and tag
    ciphertext, tag = CIPHER.encrypt_and_digest(Secret_Message)

    # Open and write 'wb' to write bytes
    file2 = open("clientdata/topsecretmessage.txt", "wb")
    data2 = sc.encode(FORMAT)
    [ file2.write(x) for x in (CIPHER.nonce, tag, data2) ]
    #file2.write(data2)
    
    #Send the filename to the server and check if receive.
    client.send("topsecretmessage.txt".encode(FORMAT))
    msg = client.recv(SIZE).decode(FORMAT)
    print(f"[SERVER]: {msg}")
    
    #Send the file data and nonce to the server check if receive.
    client.send(data2)
    client.send(nonce)
    msg = client.recv(SIZE).decode(FORMAT)
    print(f"[SERVER]: {msg}")
 
    #Close the files.
    file.close()
    file2.close()
 
    #Close the connection from the server.
    client.close()
    
    #Main
if __name__ == "__main__":
    main()
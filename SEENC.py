import tkinter
from tkinter import *
from tkinter import ttk, messagebox
import sys
import os
import ecdsa
from ecies.utils import generate_eth_key, generate_key
from ecies import encrypt, decrypt
from tkinter.filedialog import askopenfilename
from tkinter import filedialog
import matplotlib.pyplot as plt
import numpy as np

main = tkinter.Tk()
main.title("SE-Enc: A Secure and Efficient Encoding Scheme Using Elliptic Curve Cryptography")
main.geometry("900x900")

global filedata
global privateKey
global publicKey
global total_blocks
global messageEncoding
blocks = []
start = 0
end = 0

global ec_publicKey,ec_privateKey
global signature
global mapped_encrypted_points
global decryptedData
global plainText
existing = []
propose = []

#function to generate public and private key where publickey is used to encrypt mapped points and private keys used to decryptmessage
def generateKey():
  eth_k = generate_eth_key()
  private_key = eth_k.to_hex()
  public_key = eth_k.public_key.to_hex()
  return private_key, public_key

#calling generate Key function to generate public and private key
def keyAgreement():
   text.delete('1.0', END)
   global privateKey, publicKey
   privateKey,publicKey = generateKey()
   tf1.insert(END,str(publicKey))
   tf2.insert(END,str(privateKey))
   text.insert(END,"Public and private key sharing generated\n")

#function to encode message by dividing message into blocks
def messageEncode():
   blocks.clear()  # clearning old blocks
   text.delete('1.0', END)
   global filedata, total_blocks
   filename = filedialog.askopenfilename() #uploading plain text file

   with open(filename, 'r', encoding='utf8',errors='ignore') as f:
      filedata = f.read() #reading plain text from uploaded file
      f.close()
      length = len(filedata) #calculating file length
      total_blocks = int(length / 23) + 1 #dividing file into number of blocks

      for i in range(0, total_blocks):  # arranging entire file data into generate blocks
         start = 0
         end = total_blocks

      if total_blocks<len(filedata):
                 block_data = filedata[start:total_blocks]
                 blocks.append(block_data)
                 start = total_blocks
                 end = end + total_blocks
                 remain = len(filedata) - total_blocks
                 if remain > 0:
                      block_data = filedata[total_blocks:len(filedata)]
                      blocks.append(block_data)
                      text.insert(END,"Message Encoding process completed\n\n")
                      text.insert(END,"Total blocks generated are : "+str(total_blocks)+"\n")

#function to perform xor operation between old and new block data and then each block points will be encrypted using EC algorithm
def mappingEncryption():
     global existing
     global propose
     existing.clear()
     propose.clear()
     global publicKey
     text.delete('1.0', END)
     global blocks
     global messageEncoding
     global mapped_encrypted_points  #initializing all global variables
     messageEncoding = ''  #initializxing empty message encoding variable
     xor = 0
     orig = ''
     for i in range(len(blocks)):
         block_data = blocks[i]  #reading blocks data
     if len(block_data.strip()) > 0:
         arr = block_data.strip().split(" ")
     for k in range(len(arr)):
      existing.append((len(arr[k]) *3))
      propose.append((len(arr[k]) *2))

     for j in range(len(block_data)):  #reading characters from each block data
         xor = 8
         char1 = ord(block_data[j])  # perfrom same xor operations for next characters
         xor = xor ^ char1
         messageEncoding += str(xor) + " "
         orig += str(char1) + " "
         binary = '{0:08b}'.format(xor)
         text.insert(END, str(binary) + "")

     if j == 0:

          iv = 8   #performing xor operation for first character with default IV value
          char1 = ord(block_data[j])  #reading first charcater from block
          xor = char1 ^ iv  #perform xor operation
          messageEncoding+=str(xor)+" "
          orig+=str(char1)+" "
          binary = '{0:08b}'.format(xor)  # add binary values to encoding variable
          text.insert(END, str(binary) + "")
     else:
            mapped_encrypted_points = encrypt(publicKey, messageEncoding.encode())
            # this encrypt function mapped each encode point and then perform encryption with public key
            text.insert(END, "\n\nEncrypted Points " + str(mapped_encrypted_points) + "\n\n")


#function to sign encrypted points using ECDSA algorithm and this sign signature can be use by receiver to check message integrity
def pointsSigning():
  text.delete('1.0', END)
  global mapped_encrypted_points
  global ec_publicKey,ec_privateKey, signature
  ec_publicKey	=ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)  #creatingsigningkey
  ec_privateKey = ec_publicKey.get_verifying_key()
  signature = ec_publicKey.sign(mapped_encrypted_points)  #generating signature on encrypted points
  text.insert(END,"Signing EC Hash Code on Encrypted Points:"+str(signature)+"\n")
  text1.delete('1.0',END)
  text1.insert(END,"Received Encrypted Data :"+str(mapped_encrypted_points))

#function to perform verification on encrypted data and received signature
def verification():
  text1.delete('1.0', END)
  global mapped_encrypted_points
  global ec_privateKey, signature
#this function will taken crypted points and received signature and then generate new signature on received encrypted points and thencompare
#received signature with newly generated signature and both signature are not matched then verification failed
  verify = ec_privateKey.verify(signature, mapped_encrypted_points)
  if verify == True:
     text1.insert(END,"Verification Successful")
  else:
     text1.insert(END,"Verification Failed")
#fucntion to decrypt encrypted points
def decryptPoints():
         text1.delete('1.0', END)
         global decryptedData
         global privateKey
         global mapped_encrypted_points
         decryptedData = decrypt(privateKey, mapped_encrypted_points)
         decryptedData = decryptedData.decode()
         text1.insert(END,"Decrypted Mapped Points : "+str(decryptedData)+"\n\n")

#function to extract decimal values from decrypted points and then convert decimal values to plaintext
def decodeMappedPoints():
  text1.delete('1.0', END)
  global plainText
  global decryptedData
  plainText = ''
  decryptedData = decryptedData.strip().split(" ")
  for i in range(len(decryptedData)):
      xor = 8
      char1 = int(decryptedData[i])
      xor = xor ^ char1
      plainText += str(chr(xor))
  if i == 0:
      xor = 8
      char1 = int(decryptedData[i])
      xor = char1 ^ xor
      plainText+=str(chr(xor))
  else:
      text1.insert(END,"Mapped Points decoding process completed")

#function to display decrypted plain text
def plainText():
   text1.delete('1.0', END)
   global plaintext
   text1.insert(END,plainText)

def graph():
   global existing      
   global propose
   # propose = np.asarray(propose)
   # existing = np.asarray(existing)
   # propose = propose[0:20]
   # existing = existing[0:20]
   print(propose)
   print(existing)
   plt.figure(figsize=(10, 6))
   plt.grid(True)
   plt.xlabel('Message Length')
   plt.ylabel('Operations')
   plt.plot(existing, 'o-', color='green')
   plt.plot(propose, 'o-', color='orange')
   plt.legend(['Existing Singh', 'Propose SE-Enc'], loc='upper left')  # plt.xticks(wordloss.index)
   plt.title('Message Encoding Operations Graph')
   plt.show()

font1 = ('times', 13, 'bold')
l1 = Label(main, text='Public Key:')
l1.config(font=font1,fg='orange')
l1.place(x=50,y=10)

tf1 = Entry(main,width=100)
tf1.config(font=font1)
tf1.place(x=180,y=10)

l3 = Label(main, text='Private Key')
l3.config(font=font1, fg='orange')
l3.place(x=50,y=60)

tf2 = Entry(main,width=100)
tf2.config(font=font1)
tf2.place(x=180,y=60)

keyButton=Button(main,text="Run Key Agreement Algorithm",foreground='green', command=keyAgreement)
keyButton.place(x=10,y=110)
keyButton.config(width = 25, activebackground = "#33B5E5", relief = RAISED, font=font1)
encodeButton = Button(main, text="Message Encoding Algorithm", foreground = 'green', command=messageEncode)

encodeButton.place(x=300,y=110)
encodeButton.config(width=25,	activebackground=	"#33B5E5",relief	= RAISED,font=font1)

mappingButton = Button(main, text="Message Mapping & Encrypt Points",foreground= 'green', command=mappingEncryption)
mappingButton.place(x=10,y=160)
mappingButton.config(width=25,	activebackground	="#33B5E5",relief	= RAISED,font=font1)

signButton = Button(main, text="Signing Encrypted Points",foreground = 'green', command=pointsSigning)
signButton.place(x=300,y=160)
signButton.config(width	=25,	activebackground="#33B5E5",relief= RAISED,font=font1)

graphButton = Button(main, text="Message Encoding Graph",fg = 'yellow', bg='#567', command=graph)
graphButton.place(x=575,y=210)
graphButton.config(width	=	25,activebackground="#33B5E5",relief= RAISED,font=font1)

text=Text(main,height=25,width=60)
scroll=Scrollbar(text)
text.configure(yscrollcommand=scroll.set)
text.place(x=10,y=210)
text.config(font=font1)

verifyButton = Button(main, text="Receiver Message Verification",foreground = 'red', command=verification)
verifyButton.place(x=750,y=110)
verifyButton.config(width	=	25,activebackground="#33B5E5",relief= RAISED,font=font1)

decryptButton = Button(main,	text="Decrypt	Points",foreground='red', command=decryptPoints)
decryptButton.place(x=1050,y=110)
decryptButton.config(width=25,	activebackground	=	"#33B5E5",	relief= RAISED,font=font1)

decodeButton = Button(main, text="Decode Mapped Points",foreground = 'red', command=decodeMappedPoints)
decodeButton.place(x=750,y=160)
decodeButton.config(width=25,	activebackground	=	"#33B5E5",	relief= RAISED,font=font1)

plainButton=Button(main,text="Binary to	Plain Text",foreground	= 'red', command=plainText)
plainButton.place(x=1050,y=160)
plainButton.config(width	=  25,	activebackground	=	"#33B5E5",	relief= RAISED,font=font1)

text1=Text(main,height=25,width=60)
scroll=Scrollbar(text1)
text1.configure(yscrollcommand=scroll.set)
text1.place(x=800,y=210)
text1.config(font=font1)

main.config(bg='gainsboro')
main.mainloop()

if __name__ == '__main__':
    main.mainloop()
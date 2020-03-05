from tkinter import *
import os
import random
from Crypto.Util import number
_mrpt_num_trials = 5 # number of bases to test
 
import tkinter
from tkinter import filedialog
from sys import exit
import math
from hashlib import sha256
from random import randint
import os
key = 'abcdefghijklmnopqrstuvwxyz1234567890 '

def back1():
    screen1.destroy()


def back2():
    screen2.destroy()
    
    

def exit():
    screen.destroy()


def delete3():
    screen3.destroy()


def delete4():
    screen4.destroy()


def delete5():
    screen5.destroy()



def view_notes1():
    filename1 = raw_filename1.get()
    data = open(filename1, "r")
    data1 = data.read()
    screen9 = Toplevel(screen)
    screen9.title("Notes")
    screen9.geometry("400x400")
    Label(screen9, text = data1).pack()






def createFolder(directory):
    try:
        if not os.path.exists(directory):
            os.makedirs(directory)
    except OSError:
        print ('Error: Creating directory. ' +  directory)
        
# Example
createFolder('C:/Users/Oyshi/Desktop/Encrypted Files/')




def rsaen():
    screen8 = Toplevel(screen)
    screen8.title("RSA Encryption")
    screen8.geometry("250x250")
    
    
    print("RSA Encrypter/ Decrypter")
    p = generateLargePrime(4)
    q = generateLargePrime(5)
    print("Generating your public/private keypairs now . . .")
    global private
    global public
    public, private = generate_keypair(p, q)
    print("Your public key is ", public, " and your private key is ", private)
    
    
    root = Tk()
    root.filename =  filedialog.askopenfilename(initialdir = "C:/Users/Oyshi/Desktop/files for encryption",title = "Select file",filetypes = (("Text files","*.txt"),("jpeg files","*.jpg"),("all files","*.*")))
    path=root.filename
    f = open(root.filename,"rb+")
    print (f)
    txt = f.read()
    print("the file is:")
    print (txt)
    f.truncate(0)
    Label(screen8, text="File Succesfully Encrypted").pack()
    #os.remove(path)
    
    
    message = txt
    global encrypted_msg
    encrypted_msg = encrypt(private, message)
    print("Your encrypted message is: ")
    print(''.join(map(lambda x: str(x), encrypted_msg)))
    ar1=bytes(encrypted_msg)
    f = open("C:/Users/Oyshi/Desktop/Encrypted Files/enc.txt" , "wb")
    f.write(ar1)
    f.close()

def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a


def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)


def find_d(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('Not exist')
    else:
        return x % m


def rabinMiller(n):
    s = n - 1
    t = 0
    while s % 2 == 0:
        s = s // 2
        t += 1
    k = 0
    for i in range(5):
        a = random.randrange(2, n - 1)
        # a^s is computationally infeasible.  we need a more intelligent approach
        # v = (a**s)%n
        # python's core math module can do modular exponentiation
        v = pow(a, s, n)  # where values are (num,exp,mod)
        if v != 1:
            i = 0
            while v != (n - 1):
                if i == t - 1:
                    return False
                else:
                    i = i + 1
                    v = (v ** 2) % n
    return True


def isPrime(n):
    # lowPrimes is all primes (sans 2, which is covered by the bitwise and operator)
    # under 1000. taking n modulo each lowPrime allows us to remove a huge chunk
    # of composite numbers from our potential pool without resorting to Rabin-Miller
    lowPrimes = [3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97
        , 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179
        , 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269
        , 271, 277, 281, 283, 293, 307, 311, 313, 317, 331, 337, 347, 349, 353, 359, 367
        , 373, 379, 383, 389, 397, 401, 409, 419, 421, 431, 433, 439, 443, 449, 457, 461
        , 463, 467, 479, 487, 491, 499, 503, 509, 521, 523, 541, 547, 557, 563, 569, 571
        , 577, 587, 593, 599, 601, 607, 613, 617, 619, 631, 641, 643, 647, 653, 659, 661
        , 673, 677, 683, 691, 701, 709, 719, 727, 733, 739, 743, 751, 757, 761, 769, 773
        , 787, 797, 809, 811, 821, 823, 827, 829, 839, 853, 857, 859, 863, 877, 881, 883
        , 887, 907, 911, 919, 929, 937, 941, 947, 953, 967, 971, 977, 983, 991, 997]
    if (n >= 3):
        if (n & 1 != 0):
            for p in lowPrimes:
                if (n == p):
                    return True
                if (n % p == 0):
                    return False
            return rabinMiller(n)
    return False


def generateLargePrime(k):
    # k is the desired bit length
    r = 100 * (math.log(k, 2) + 1)  # number of attempts max
    r_ = r
    while r > 0:
        # randrange is mersenne twister and is completely deterministic
        # unusable for serious crypto purposes
        n = random.randrange(2 ** (k - 1), 2 ** (k))
        r -= 1
        if isPrime(n) == True:
            return n
    return "Failure after " + 'r_' + " tries."



def generate_keypair(p, q):
    if not (generateLargePrime(8) and generateLargePrime(8)):
        raise ValueError('Both numbers must be prime.')
    elif p == q:
        raise ValueError('p and q cannot be equal')
    # n = pq
    n = p * q

    # Phi is the totient of n
    phi = (p - 1) * (q - 1)

    # Choose an integer e such that e and phi(n) are coprime
    e = random.randrange(1, phi)

    # Use Euclid's Algorithm to verify that e and phi(n) are comprime
    g = gcd(e, phi)
    while g != 1:
        e = random.randrange(1, phi)
        g = gcd(e, phi)

    # Use Extended Euclid's Algorithm to generate the private key
    d = find_d(e, phi)
    print("D : ", d)
    # Return public and private keypair
    # Public key is (e, n) and private key is (d, n)
    return ((e, n), (d, n))


def encrypt(pk, plaintext):
    # Unpack the key into it's components
    key, n = pk
    # Convert each letter in the plaintext to numbers based on the character using a^b mod m
    cipher = [((char) ** key) % n for char in plaintext]
    # Return the array of bytes
    return cipher


def decrypt(pk, ciphertext):
    # Unpack the key into its components
    key, n = pk
    # Generate the plaintext based on the ciphertext and key using a^b mod m
    plain = [chr((char ** key) % n) for char in ciphertext]
    # Return the array of bytes as a string
    return ''.join(plain)
    


def rsade(): 
    screen10 = Toplevel(screen)
    screen10.title("RSA Decryption")
    screen10.geometry("250x250")
    root = Tk()
    root.filename =  filedialog.askopenfilename(initialdir = "C:/Users/Oyshi/Desktop/Encrypted Files/",title = "Select file",filetypes = (("Text files","*.txt"),("jpeg files","*.jpg"),("all files","*.*")))
    path=root.filename
    f = open(root.filename,"rb+")
    print("Decrypting message with public key ", public, " . . .")
    print("Your message is:")
    dec1=decrypt(public, encrypted_msg)
    print(dec1)
    print(type(dec1))
    a=dec1.encode()
    print(type(a))
    f = open("C:/Users/Oyshi/Desktop/Encrypted Files/dec.txt" , "wb")
    f.write(a)
    f.close()
    Label(screen10, text="File Succesfully Decrypted").pack()
    
    
    
 
    
def rsaimen():
    
    
    screen14 = Toplevel(screen)
    screen14.title("RSA Encryption")
    screen14.geometry("250x250")
    
    
    print("RSA Encrypter/ Decrypter")
    p = generateLargePrime(4)
    q = generateLargePrime(5)
    print("Generating your public/private keypairs now . . .")
    global private
    global public
    public, private = generate_keypair(p, q)
    print("Your public key is ", public, " and your private key is ", private)
    
    
    root = Tk()
    root.filename =  filedialog.askopenfilename(initialdir = "C:/Users/Oyshi/Desktop/files for encryption",title = "Select file",filetypes = (("jpeg files","*.jpg"),("all files","*.*")))
    path=root.filename
    f = open(root.filename,"rb+")
    print (f)
    txt = f.read()
    print("the file is:")
    print (txt)
    f.truncate(0)
    Label(screen14, text="File Succesfully Encrypted").pack()
    #os.remove(path)
    
         

     

     
     
    
    
    
    message = txt
    global encrypted_msg
    encrypted_msg = encrypt(private, message)
    print("Your encrypted message is: ")
    print(''.join(map(lambda x: str(x), encrypted_msg)))
    ar1=bytes(encrypted_msg)
    f = open("C:/Users/Oyshi/Desktop/Encrypted Files/enc.txt" , "wb")
    f.write(ar1)
    f.close()



    
def rsaimde():
    
    screen15 = Toplevel(screen)
    screen15.title("RSA Decryption")
    screen15.geometry("250x250")
    root = Tk()
    root.filename =  filedialog.askopenfilename(initialdir = "C:/Users/Oyshi/Desktop/Encrypted Files/",title = "Select file",filetypes = (("Text files","*.txt"),("jpeg files","*.jpg"),("all files","*.*")))
    path=root.filename
    f = open(root.filename,"rb+")
    print("Decrypting message with public key ", public, " . . .")
    print("Your message is:")
    dec1=decrypt(public, encrypted_msg)
    print(dec1)
    print(type(dec1))
    a=dec1.encode()
    print(type(a))
    f = open("C:/Users/Oyshi/Desktop/Encrypted Files/dec.jpg" , "wb")
    f.write(a)
    f.close()
    Label(screen15, text="File Succesfully Decrypted").pack()
    
    
    
    
    
    
    
    
def cce():
    
    screen11= Toplevel(screen)
    screen11.title("Ceaser Chipher Encryption")
    screen11.geometry("250x250")
    root = tkinter.Tk()
    root.filename = tkinter.filedialog.askopenfilename(initialdir = "C:/Users/Oyshi/Desktop/files for encryption",title = "Select file")
    path=root.filename
    global f
    f = open(root.filename)
    message = f.read()
    f.close()  
    global dkey 
    dkey = 5
    global encrypted 
    encrypted = c_en(dkey, message)
    f = open("C:/Users/Oyshi/Desktop/Encrypted Files/encc.txt", "w")
    f.write(str(encrypted))
    f.close()
    Label(screen11, text="File Succesfully Encrypted").pack()
    
    
    
def c_en(n, plaintext):
    
    """Encrypt the string and return the ciphertext"""
    result = ''

    for l in plaintext.lower():
        try:
            i = (key.index(l) + n) % 37
            result += key[i]
        except ValueError:
            result += l
            return result.lower()
    return result    
    
    

def ccd():
    screen12= Toplevel(screen)
    screen12.title("Ceaser Cipher Decryption")
    screen12.geometry("250x250")
    root = tkinter.Tk()
    root.filename = tkinter.filedialog.askopenfilename(initialdir = "C:/Users/Oyshi/Desktop/Encrypted Files/",title = "Select file")
    path = root.filename
    f = open(root.filename)
    f = open("C:/Users/Oyshi/Desktop/Encrypted Files/decc.txt","w")
    f.write(str(c_dec(dkey, encrypted)))
    f.close()
    Label(screen12, text="File Succesfully Decrypted").pack()
    
    

def c_dec(n, ciphertext):
    """Decrypt the string and return the plaintext"""
    result = ''

    for l in ciphertext:
        try:
            i = (key.index(l) - n) % 37
            result += key[i]
        except ValueError:
            result += l
            return result.lower()                        
    return result
    

def session():
    screen6 = Toplevel(screen)
    screen6.title("Dashboard")
    screen6.geometry("400x400")
    Label(screen6, text = "Choose Algorithm for Encryption and Decryption").pack()
    Button(screen6, text = "Ceaser Cipher Encryption",width = 30, height = 2, bg="olive", command = cce).pack()
    Label(text="").pack()
    Button(screen6, text = "Ceaser Cipher Decryption",width = 30, height = 2, bg="olive", command = ccd).pack()
    Label(text="").pack()
    Button(screen6, text = "RSA encrypt",width = 30, height = 2, bg="olive", command = rsaen).pack()
    Label(text="").pack()
    Button(screen6, text = "Rsa Decrypt",width = 30, height = 2, bg="olive", command = rsade).pack()
    Label(text="").pack()
    Button(screen6, text = "Image Encryption",width = 30, height = 2, bg="olive", command = rsaimen).pack()
    Label(text="").pack()
    Button(screen6, text = "Image Decryption",width = 30, height = 2, bg="olive", command = rsaimde).pack()


def login_success():
    session()


def incorrect_password():
    ip = tk.Label(screen2, text = "Incorrect password!", fg = "red", font = ("Calibri", 11))
    ip.pack()
    screen2.after(1500, ip.destroy)


def user_not_found():
    unf = tk.Label(screen2, text = "User not found!", fg = "red", font = ("Calibri", 11))
    unf.pack()
    screen2.after(1500, unf.destroy)

    
def register_user():

    username_info = username.get()
    password_info = password.get()

    file=open(username_info, "w")
    file.write(username_info+"\n")
    file.write(password_info)
    file.close()

    username_entry.delete(0, END)
    password_entry.delete(0, END)

    rs = tk.Label(screen1, text = "Registration Successful", fg = "green", font = ("Calibri", 11))
    rs.pack()
    screen1.after(1500, rs.destroy)


def clear_label(rs):
    print ("label cleared")
    rs.place_forget()

def register():
    global screen1
    screen1 = Toplevel(screen)
    screen1.title("Register")
    screen1.geometry("400x400")

    global username
    global password
    global username_entry
    global password_entry
    username = StringVar()
    password = StringVar()

    Label(screen1, text = "Please enter details below").pack()
    Label(screen1, text = "").pack()
    Label(screen1, text = "Username *").pack()
    username_entry = Entry(screen1, textvariable = username)
    username_entry.pack()
    Label(screen1, text = "Password *").pack()
    password_entry = Entry(screen1, textvariable = password)
    password_entry.pack()
    Label(screen1, text = "").pack()
    Button(screen1, text = "Register", width = 15, height = 2, bg="purple", command = register_user).pack()
    Button(screen1, text = "Back", width = 15, height = 2, bg="gray", command = back1).pack()


def login_verify():
    global username_verify
    global username1
    username1 = username_verify.get()
    password1 = password_verify.get()
    username_entry1.delete(0, END)
    password_entry1.delete(0, END)

    list_of_files = os.listdir()
    if username1 in list_of_files:
        file1 = open(username1, "r")
        verify = file1.read().splitlines()
        if password1 in verify:
            login_success()

        else:
            incorrect_password()
            

    else:
        user_not_found()
    

def login():
    global screen2
    screen2 = Toplevel(screen)
    screen2.title("Login")
    screen2.geometry("400x400")
    Label(screen2, text = "Please enter details below to log in").pack()
    Label(screen2, text = "").pack()

    global username_verify
    global password_verify

    username_verify = StringVar()
    password_verify = StringVar()

    global username_entry1
    global password_entry1

    Label(screen2, text = "Username *").pack()
    username_entry1 = Entry(screen2, textvariable = username_verify)
    username_entry1.pack()
    Label(screen2, text = "Password *").pack()
    password_entry1 = Entry(screen2, textvariable = password_verify)
    password_entry1.pack()
    Label(screen2, text = "").pack()
    Button(screen2, text = "Login", width = 15, height = 2, bg="purple", command = login_verify).pack()
    
    Button(screen2, text = "Back", width = 15, height = 2,bg="gray", command = back2).pack()
    


def main_screen():
    global screen
    screen = Tk()
    screen.title ("Secured Files")
    screen.geometry ("400x400")
    screen.resizable(False,False)
    Label(text = "File encryption and decryption", bg="grey", width="300", height ="2", font = ("Calibri", 13)).pack()
    Label(text = "").pack()
    Button(text = "Login", height = "2", width = "30",bg="olive", command = login).pack()
    Label(text="").pack()
    Button(text= "Register", height = "2", width = "30",bg="olive", command = register).pack()
    Label(text="").pack()
    Button(text= "Exit", height = "2", width = "30",bg="olive", command = exit).pack()


    screen.mainloop()

main_screen()
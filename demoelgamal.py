# -*- coding: utf-8 -*-
"""
Created on Fri Mar 22 21:09:34 2023

@author: Yuta
"""

from Crypto.Util.number import inverse, getPrime
from Crypto.Random.random import randint
import hashlib

# Tạo khóa
def generate_keys():
    #chọn p là 1 số nguyên tố lơn hơn 1024 bit
    p = getPrime(2048)
    #một giá trị khởi tạo g
    g = 2
    #khóa bí mật dùng để kí
    x = randint(1,p-1)
    #tính y 
    y = pow(g,x,p)
    
    public_key = (p,g,y)
    private_key = x
    #print("public_key", public_key)
    #print("private_key", private_key)
    return (public_key, private_key)

# Tạo chữ ký
def sign(h, private_key, public_key):
    p, g, y = public_key
    x = private_key
    #K là một số ngẫu nhiên trong khoảng
    k = randint(1,p-2)
    r = pow(g,k,p)
    
    #inverse là hàm tính nghịch đảo module
    s = ((h-x*r)*inverse(k,p-1))%(p-1)
    signature = (r, s)   
    return signature
    
    
    
# Xác minh chữ ký
def verify(h2, signature, public_key):
    p, g, y = public_key
    r, s = signature
    
    if pow(g,h2,p) == (pow(y,r,p) * pow(r,s,p)%p):
       return True
    else:
       return False
   
   
        

public_key, private_key = generate_keys()
message1 = "Le Thi Bao Yen"
print("Thông điệp gốc:",message1)
#băm thông điệp với hàm băm sha256
h = int(hashlib.sha256(message1.encode()).hexdigest(), 16)
#print("h",h)
signature = sign(h, private_key, public_key)

message2 = input("Nhập thông điệp xác minh: ")
h2 = int(hashlib.sha256(message2.encode()).hexdigest(), 16)
#print("h2",h2)

if verify(h2, signature, public_key):
    print("Chữ ký hợp lệ")
else:
    print("Chữ ký không hợp lệ")

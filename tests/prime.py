from sympy import *

n = 8192
m = 341375 * 2

while(true):
    m +=1
    if(isprime(m) and ((m - 1) / (n*2)).is_integer()):
        print(m)
        break


from sympy import *

n = 7000000189057

while(true):
    n +=1
    if(isprime(n) and ((n - 1) / 16384).is_integer()):
        print(n)
        break


from sympy import *

n = 8192.0 * 2
m = 1832740000000000079.0

while(true):
    m +=1
    if(isprime(m) and ((m - 1) / n).is_integer()):
        print(m)
        break


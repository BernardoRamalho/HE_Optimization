from sympy import *

n = 7000000189057
m = 2.29093 * 10**17
 
while(true):
    m +=1
    if(isprime(m) and ((m - 1) / 16384).is_integer()):
        print(m)
        break


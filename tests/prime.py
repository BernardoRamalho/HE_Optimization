from sympy import *
import decimal

n = 8192 * 2
m = 229092884480049137.000
decimal.setcontext(decimal.Context(prec=15))

while(true):
    m +=1
    x = decimal.Decimal((m - 1) / n)
    if(isprime(m) and ((m - 1) / n).is_integer()):
        print(m)
        break


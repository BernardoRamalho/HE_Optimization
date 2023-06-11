def is_prime(num):
    for n in range(2,int(num**0.5)+1):
        if num%n==0:
            return False
    return True

def find_two_primes_with_sum(n):
    p1 = 2  # Initialize p1 with the smallest prime number
    p2 = n - p1

    while not (is_prime(p1) and is_prime(p2)):
        p1 += 1
        p2 = n - p1
        if(p1 > n or p2 < 0):
            print("Can't be decomposed :(")
            return None, None

    return p1, p2

p = 4295049217
p1, p2 = find_two_primes_with_sum(p)

print("p1 =", p1)
print("p2 =", p2)
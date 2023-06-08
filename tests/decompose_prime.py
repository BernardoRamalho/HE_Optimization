def is_prime(n):
    if n <= 1:
        return False
    elif n <= 3:
        return True
    elif n % 2 == 0 or n % 3 == 0:
        return False

    i = 5
    while i * i <= n:
        if n % i == 0 or n % (i + 2) == 0:
            return False
        i += 6

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
import math

p = 3
q = 7

n = p * q
phi = (p - 1) * (q - 1)

e = 2

while e < phi:
    if math.gcd(e, phi) == 1:
        break
    else:
        e += 1

k = 2
d = (1 + k * phi) // e

msg = 12

print("Message data =", msg)

# Encryption
c = pow(msg, e, n)
print("Encrypted data =", c)

# Decryption
m = pow(c, d, n)
print("Original Message Sent =", m)
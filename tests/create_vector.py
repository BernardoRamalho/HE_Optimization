vector_size = int(input("Which is the vector size? "))
number_vectors = int(input("How many vectors?"))

f = open("number.txt", "w")
number = 0
for i in range(number_vectors):
    for j in range(vector_size):
        f.write(str(number) + " ")
        number += 1
    f.write("\n")
f.close()
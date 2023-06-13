vector_size = int(input("Which is the vector size? "))
number_vectors = int(input("How many vectors?"))

f = open("number.txt", "w")
number = 1
sum_all_numbers = 0
f.write(str(number_vectors) + " ")
f.write(str(vector_size) + "\n")

for i in range(number_vectors):
    for j in range(vector_size):
        #if j < 10:
        #    f.write("1 ")
        #else:
        #    f.write("0 ")
        f.write(str(number) + " ")
        sum_all_numbers += number
        number = (number + 1) % 3
    number = 1
    f.write("\n")
f.close()
print("Sum of all numbers = " + str(sum_all_numbers))

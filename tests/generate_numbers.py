import numpy as np

vector_size = int(input("Which is the vector size? "))
number_vectors = int(input("How many vectors?"))
total_elements = vector_size * number_vectors
all_numbers = []
number = 1
sum_all_numbers = 0

for i in range(number_vectors):
    for j in range(vector_size):
        all_numbers.append(number)
        sum_all_numbers += number
        number = (number + 1) % 3
    number = 1

all_numbers = np.array(all_numbers) * total_elements
all_numbers = all_numbers - sum_all_numbers
all_numbers = all_numbers * all_numbers

all_numbers = [int(x) for x in all_numbers]
print(sum(all_numbers))

#inner_product = int(np.inner(all_numbers, all_numbers))
#n_squared = total_elements ** 2

#squared_inner = inner_product * n_squared

#print("n^3 = " + str(pow(total_elements, 3)))
#print("Sum of all numbers = " + str(sum_all_numbers))
#print("Square Sum of all numbers = " + str(pow(sum_all_numbers, 2)))
#print("n x Square Sum of all numbers = " + str( total_elements * pow(sum_all_numbers, 2)))
#print("n x Inner Product = " + str(total_elements * inner_product)) 
#print("n^2 x Inner Product = " + str(squared_inner)) 
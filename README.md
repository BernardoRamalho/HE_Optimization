# HE_Optimization

## Goals

The goals of this project is to develop optimizations for basic statistical algorithms using FHE.

## Preliminary

**n** --> total number of elements

**m** --> total number of elements in each plaintext

# Mean

The mean is calculated by the sum of all values divided by the number of values added. We implemented 3 strategies.

## Simple Mean Implementation

This implementation can be seen in both "Mean/simple-mean.cpp" and "Mean/simple-coef-mean.cpp".

Both these files work the same they just use a different packing method. One uses slot packing and the other uses coefficient packing. 

In these implementation we just pack each value into a different plaintext (if we have n values, we will have n plaintexts) and then we sum all of them together. We then decrypt and divide the value at index 0 by **n**.

These is the least efficient way since encoding n plaintext for a very big n is unfeaseable in a decent time.

## Rotation Mean Implementation

This implementation can be seen in "Mean/rotation-mean.cpp". In "Mean/optimized-rotation-mean.cpp" and "Mean/optimized-coef-rotation-mean".cpp", we have an optimization on this method so I'll only talk about "Mean/rotation-mean.cpp".

In this implementation we pack **m** values into each plaintext an then add all the ciphertexts together. The tricky part about doing this is that there is no native method to sum all the values of a single ciphertext together. 

The naive approach to do this is to use a sequence of rotations + sums in order to get the value in the first index. Let **cA** be the ciphertext, of size **m**, that is the result of the summation of all ciphertexts together, and **cR** the ciphertext that will hold the result of a rotation. The algorithm will look like this:

```
Do m times:
    **cR** --> rotate(**cA**, 1);
    **cA** --> add(**cR**, **cA**);
```
After repeating it m times, the summation of all the elements will be on the first element. We just have to then decrypt the result and divide by **n**.

## Optimized Rotation Mean Implementation

This implementation is based on the previous one but we reduce the amount of rotations from **m** to **log2(m)**.

Instead of rotation by 1, we can rotate by 2^i where i goes from 0 to log2(m), not inclusive. For this to work, **m** must be a power of 2. So the algorithm looks like this:

```
For i = 0 to i < log2(m):
    **cR** --> rotate(**cA**, 2^i);
    **cA** --> add(**cR**, **cA**);
```
With this method we also get the summation of all the elements on the first element. Here we can actually shave of the last rotation, which is the most costly, and reduce the amount of rotations to log2(m) - 1. In the last rotation, what happens is that we sum the first element with the element that's in the middle of the plaintext. So instead of rotating, we decrypt before the last rotation and just sum those two values. 

At the end we always have to divide the value by **n** to get the correct mean value.

The difference between "Mean/optimized-rotation-mean.cpp" and "Mean/optimized-coef-rotation-mean" is that rotations are done differently since there is no rotation method implemented for Coefficient Packing.
In coefficient packing, the multiplication is done as a polynomial multiplication. This means that if we multiply one ciphertext by a plaintext that contains [0, 1, 0], the ciphertext will be rotated by one. Basically, the index of where the 1 value is, is how much we rotate the ciphertext.

So in order to implement this method with Coefficient packing, we have to create log2(m) plaintexts as follows:

```
vector<Plaintext> rotation_plaintexts = {}
for i = 0 to i < log2(m):
    vector<int> zeros --> zeros(m) // creates a vector of size m filled with zeros
    zeros[2^i] --> 1
    Plaintext p = CoefficientPacking(zeros)
    rotation_plaintexts.append(p)
```

Then instead of using the rotate method we just use the multiplication method. We can also shave off one rotation because of the same reason explained above.

# Inner Product

The inner product is calculated by multiplying two vectors together and adding the resulting values together. For all the implementations, we always start by encrypting two vectors into two ciphertexts.

## Basic implementation

For the basic implementation we decided to skip the naive one, since, for very large amount of data, is just unfeasible.

So for this implementation we multiply both ciphertexts together and then use the rotation + addition method **m** times. At the end, the inner product value will be in the first index.

## Optimized Slot Packing Implementation

This implementation is done in "InnerProduct/optimized-inner-product.cpp".

This is also based on the optimization done for the Mean implementation with rotation. So we reduced the amoutn of rotation from **m** to **log2(m) - 1**.

## Optimized Coefficient Packing Implementation

Since multiplication works as a polynomial multiplication we actually don't need to use rotation. If we reverse the second vector and multiply it with the first, due to how polynomial multiplication works, we get the value of the inner product at the last index.

With this we save all the time we would use with rotation and only need to do one multiplication.

# Variance

## First Approach

In our first approach to implement the Variance we simplified the original formula into: **sum(n*xi - sum(x))/n^3**

For this approach we tried implementing a version with slot packing and with coefficient packing. In all the implementation we found the same main problem, the plaintext needs to be very large in order to accomodate for the sum(x) and the n*xi values.

### Slot Packing Implementation

In this implementation we start by calculating the sum(x) using the same method as in the mean except we do one more rotation in order for all the elements of the plaintext to be the value of the summation.

In order to multiply xi by n, a plaintext is need where all the elements are equal to n (which is the total number of elements).

After these two operations we just have to subtract the first result from the second and square the final output.

In order to finish we need to use again the summation algorithm used in the mean to get the final total value of the summation.

After decrypting that ciphertext, we divide the value in the first element by n^3 and we get the value of the variance.

### Coef Packing Implementation

We tried implemented using Coef Packing but we found that is too difficult. This is because, due to how operation in these kind of packing work, it is extremly difficult to get the value of sum(xi) in all elements of a ciphertext without decrypting and encrypting again in the middle of the operations. These goes agaisn't the aim of this project and, as such, we cut, for now, this implementation. 

## Second Approach

The second approach comes from a paper that show that the variance can be calculated as such: **(n*X*X - sum(x)^2)/n^2**

For this approach we implemented a version with slot packing and coefficient packing. In all the implementation we found the same main problem, the plaintext needs to be very large in order to accomodate for sum(x)^2 and n*X*X.


### Slot Packing Implementation

In this implementation we start by doing two operation in parallel. 

The first one is calculating the square of the sum. To do this we use the same algorithm as always to calculate the sum of all elements but we multiply the resulting ciphertext by itself in the end to get the squared value.

The second operation done is calculate the inner product. This is also easily done by multiplying the ciphertext with itself in order to get everything squared and then use the same algorithm as before to calculate the sum of all the elements.

After this operation are done, we multiply the inner product result by a plaintext where all elements are n in order to get n*X*X.

To finish we just need to subtract the square of the sum from the inner product and we can decrypt the resulting ciphertext and extract the first element. If we divide this element by n^2 we get the variance value.

### Coef Packing Implementation

For this implementation we have to encrypt some extra ciphertexts. We still start by doing the two same operation in parallel.

In order to calculate the square of the sum we actually have to divide the ciphertexts in half. This make it so that if we just multiply each ciphertext with every ciphertext and then sum everything together we get the square of the sum.

In order to calculate the inner product we need to encrypt another ciphertext where all the values and reversed (the first element is in the last position and the last element is in the first position). This makes it so we just have to multiply the normal ciphertext with the inverted one and sum all the elements together to get the inner product. 

After multiplying the inner product result with n (the same way we did for the slot packing) we just have to subtract the square of the sum from the inner product. We then decrypt the resulting ciphertext and dive the last element with n^2 to get the variance value.

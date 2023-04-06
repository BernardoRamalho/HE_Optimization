# HE_Optimization

## Goals

The goals of this project is to develop optimizations for basic statistical algorithms using FHE.

## Preliminary

**n** --> total number of elements
**m** --> total number of elements in each plaintext
## Mean

The mean is calculated by the sum of all values divided by the number of values added. We implemented 3 strategies.

### Simple Mean Implementation

This implementation can be seen in both "Mean/simple-mean.cpp" and "Mean/simple-coef-mean.cpp".

Both these files work the same they just use a different packing method. One uses slot packing and the other uses coefficient packing. 

In these implementation we just pack each value into a different plaintext (if we have n values, we will have n plaintexts) and then we sum all of them together. We then decrypt and divide the value at index 0 by **n**.

These is the least efficient way since encoding n plaintext for a very big n is unfeaseable in a decent time.

### Rotation Mean Implementation

This implementation can be seen in "Mean/rotation-mean.cpp". In "Mean/optimized-rotation-mean.cpp" and "Mean/optimized-coef-rotation-mean".cpp", we have an optimization on this method so I'll only talk about "Mean/rotation-mean.cpp".

In this implementation we pack **m** values into each plaintext an then add all the ciphertexts together. The tricky part about doing this is that there is no native method to sum all the values of a single ciphertext together. 

The naive approach to do this is to use a sequence of rotations + sums in order to get the value in the first index. Let **cA** be the ciphertext, of size **m**, that is the result of the summation of all ciphertexts together, and **cR** the ciphertext that will hold the result of a rotation. The algorithm will look like this:
`
Do m times:
    **cR** --> rotate(**cA**, 1);
    **cA** --> add(**cR**, **cA**);
`
After repeating it m times, the summation of all the elements will be on the first element. We just have to then decrypt the result and divide by **n**.

### Optimized Rotation Mean Implementation

This implementation is based on the previous one but we reduce the amount of rotations from **m** to **log2(m)**.

Instead of rotation by 1, we can rotate by 2^i where i goes from 0 to log2(m), not inclusive. For this to work, **m** must be a power of 2. So the algorithm looks like this:
`
For i = 0 to i < log2(m):
    **cR** --> rotate(**cA**, 2^i);
    **cA** --> add(**cR**, **cA**);
`
With this method we also get the summation of all the elements on the first element. Here we can actually shave of the last rotation, which is the most costly, and reduce the amount of rotations to log2(m) - 1. In the last rotation, what happens is that we sum the first element with the element that's in the middle of the plaintext. So instead of rotating, we decrypt before the last rotation and just sum those two values. 

At the end we always have to divide the value by **n** to get the correct mean value.

The difference between "Mean/optimized-rotation-mean.cpp" and "Mean/optimized-coef-rotation-mean" is that rotations are done differently since there is no rotation method implemented for Coefficient Packing.
In coefficient packing, the multiplication is done as a polynomial multiplication. This means that if we multiply one ciphertext by a plaintext that contains [0, 1, 0], the ciphertext will be rotated by one. Basically, the index of where the 1 value is, is how much we rotate the ciphertext.

So in order to implement this method with Coefficient packing, we have to create log2(m) plaintexts as follows:
`
vector<Plaintext> rotation_plaintexts = {}
for i = 0 to i < log2(m):
    vector<int> zeros --> zeros(m) // creates a vector of size m filled with zeros
    zeros[2^i] --> 1
    Plaintext p = CoefficientPacking(zeros)
    rotation_plaintexts.append(p)
`

Then instead of using the rotate method we just use the multiplication method. We can also shave off one rotation because of the same reason explained above.

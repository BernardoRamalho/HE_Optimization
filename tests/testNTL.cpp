/**
 * @file optimized-coef-rotation-mean.cpp
 * @author Bernardo Ramalho
 * @brief Optimized FHE implementation of the mean of n values using Coefficient Packing
 * @version 0.1
 * @date 2023-04-05
 * 
 * @copyright Copyright (c) 2023
 * 
 */

#include <NTL/ZZ.h>
#include "openfhe.h"
#include <iostream>
#include <fstream>
using namespace lbcrypto;
using namespace NTL;
/*
 * argv[1] --> number's file name
*/
int main(int argc, char *argv[]) {

    // Auxiliary Variables for the Pre Processing 
   // int64_t plaintext_modulus = 4295049217;
   // int64_t alpha = 626534755, inverse_alpha = 2398041854;
    ZZ plaintext_modulus = ZZ(7000000462849);
    ZZ alpha = ZZ(3398481477433);	
    ZZ a = alpha * alpha;
    int64_t test;
    conv(test, a % plaintext_modulus);
    
    std::cout << a << std::endl;
    std::cout << test << std::endl; 
}

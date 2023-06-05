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

#include "openfhe.h"
#include <iostream>
#include <fstream>
#include <cstdlib>
using namespace lbcrypto;
std::vector<int64_t> pre_process_numbers(std::vector<int64_t> values, int64_t alpha, int64_t plaintext_modulus){
    std::vector<int64_t> pre_processed_values;
    int64_t alpha_value = 1, pre_processed_value;
    unsigned long long mult_value;

    for(unsigned int i = 0; i < values.size(); i++){
	mult_value = values[i] * alpha_value;

        pre_processed_value = mult_value % plaintext_modulus;

        alpha_value = alpha_value * alpha % plaintext_modulus;

        if(pre_processed_value > (plaintext_modulus - 1 ) /2){
		    pre_processed_value = pre_processed_value - plaintext_modulus;
	    }

        pre_processed_values.push_back(pre_processed_value);
    }

    return pre_processed_values;
}

std::vector<int64_t> post_process_numbers(std::vector<int64_t> pre_processed_values, int64_t inverse_alpha, int64_t plaintext_modulus){
    std::vector<int64_t> post_processed_values;
    unsigned long long inverse_alpha_value = 1;
    uint64_t post_processed_value;
    unsigned long long mult_value;

    for(unsigned int i = 0; i < pre_processed_values.size(); i++){

        if(pre_processed_values[i] < 0){
            pre_processed_values[i] += plaintext_modulus;
        }

        mult_value = pre_processed_values[i] * inverse_alpha_value;

        post_processed_value = mult_value % plaintext_modulus;

        inverse_alpha_value = inverse_alpha_value * inverse_alpha % plaintext_modulus;

        post_processed_values.push_back(post_processed_value);
    }

    return post_processed_values;
}


/*
 * argv[1] --> number's file name
*/
int main(int argc, char *argv[]) {
    int64_t plaintext_modulus = 4295049217;
    int64_t alpha = 626534755, inverse_alpha = 2398041854;

   // int64_t plaintext_modulus = 65537;

    // Set CryptoContext
    CCParams<CryptoContextBFVRNS> parameters;
    parameters.SetPlaintextModulus(plaintext_modulus);
    parameters.SetMultiplicativeDepth(2);

    CryptoContext<DCRTPoly> cryptoContext = GenCryptoContext(parameters);
    // Enable features that you wish to use
    cryptoContext->Enable(PKE);
    cryptoContext->Enable(KEYSWITCH);
    cryptoContext->Enable(LEVELEDSHE);
    cryptoContext->Enable(ADVANCEDSHE);

    // Key Generation

    // Initialize Public Key Containers
    KeyPair<DCRTPoly> keyPair;

    // Generate a public/private key pair
    keyPair = cryptoContext->KeyGen();

    // Generate the relinearization key
    cryptoContext->EvalMultKeyGen(keyPair.secretKey);
    
    // Pre process the numbers before encrypting
    // Auxiliary Variables for the Pre Processing 
   // int64_t alpha = 81, inverse_alpha = 8091;
	
    std::vector<int64_t> multiply_by(8192, 0);
    multiply_by[0] = 8192 * 8192;
    std::vector<int64_t> all_numbers(8192, 0);
    std::vector<int64_t> all_numbers_reversed(8192, 0);
    std::vector<int64_t> all_ones(8192, 1);
    
   for(int i = 0; i < atoi(argv[1]); i++){
	   all_numbers[i] = 1;
	   all_numbers_reversed[i] = 1;
   }

   reverse(all_numbers_reversed.begin(), all_numbers_reversed.end());

    std::vector<int64_t> pre_processed_numbers = pre_process_numbers(all_numbers, alpha, plaintext_modulus);
    std::vector<int64_t> pre_processed_reversed_numbers = pre_process_numbers(all_numbers_reversed, alpha, plaintext_modulus);
    std::vector<int64_t> pre_processed_multiply_by = pre_process_numbers(multiply_by, alpha, plaintext_modulus);
    std::vector<int64_t> pre_processed_all_ones = pre_process_numbers(all_ones, alpha, plaintext_modulus);

    Plaintext plaintext = cryptoContext->MakeCoefPackedPlaintext(pre_processed_numbers);
    Plaintext reveserd_plaintext = cryptoContext->MakeCoefPackedPlaintext(pre_processed_reversed_numbers);
    Plaintext plaintextMultiply = cryptoContext->MakeCoefPackedPlaintext(pre_processed_multiply_by);
    Plaintext plaintextAllOnes = cryptoContext->MakeCoefPackedPlaintext(pre_processed_all_ones);

    // Calculate square sum
    auto elementsCipher = cryptoContext->Encrypt(keyPair.publicKey, plaintext);
    auto ciphertextAdd = cryptoContext->EvalMult(elementsCipher, plaintextAllOnes);

    ciphertextAdd = cryptoContext->EvalMult(ciphertextAdd, ciphertextAdd);

    // Calculate Inner Product
     auto elementsReversedCipher = cryptoContext->Encrypt(keyPair.publicKey, plaintext);
     auto cipherInnerProduct = cryptoContext->EvalMult(elementsCipher, elementsReversedCipher) ;

    cipherInnerProduct = cryptoContext->EvalMult(cipherInnerProduct, plaintextMultiply);
    
    cipherInnerProduct = cryptoContext->EvalSub(cipherInnerProduct, ciphertextAdd);
    // Decryption
    Plaintext plaintextDec;
 
    cryptoContext->Decrypt(keyPair.secretKey, cipherInnerProduct, &plaintextDec);
    std::vector<int64_t> post_processed_values = post_process_numbers(plaintextDec->GetCoefPackedValue(), inverse_alpha, plaintext_modulus);
    float variance = post_processed_values[atoi(argv[1])-1] / pow(8192, 3);
    std::cout << variance  << std::endl;
}

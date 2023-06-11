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

std::vector<Plaintext> generate_rotation_plaintexts(int64_t number_rotations, CryptoContext<DCRTPoly> cryptoContext){
    std::vector<Plaintext> rotation_plaintexts;
    Plaintext plaintextRot;

    for(int i = 0; i < number_rotations; i++){
	    // Create vector of size 8192 filled with 0
        std::vector<int64_t> rotationVector(8191, 0);

        // Rotating by 2^i --> element @ index 2^i = 1
	    rotationVector[(int)pow(2, i)] = 1;

        rotation_plaintexts.push_back(cryptoContext->MakeCoefPackedPlaintext(rotationVector));
    }

    return rotation_plaintexts;
}

/*
 * argv[1] --> number's file name
*/
int main(int argc, char *argv[]) {
    // Read the vector from a file
    std::ifstream numbers_file (argv[1]);

     if (!numbers_file.is_open()) {
        std::cerr << "Could not open the file - '"
             << argv[1] << "'" << std::endl;
        return EXIT_FAILURE;
    }
    
    // Header of file contains information about nr of vector and the size of each of them
    int64_t number_vectors, size_vectors, number;
    std::vector<int64_t> numbers;

    numbers_file >> number_vectors;
    numbers_file >> size_vectors;
      

    // Body of the file contains all the numbers
    while (numbers_file >> number) {
        numbers.push_back(number);
    }

    // Auxiliary Variables for the Pre Processing 
   // int64_t plaintext_modulus = 4295049217;
   // int64_t alpha = 626534755, inverse_alpha = 2398041854;
    int64_t plaintext_modulus = 7000000462849;
    int64_t alpha = 3398481477433, inverse_alpha = 2279133059052;	
    std::vector<int64_t> pre_processed_numbers;
    pre_processed_numbers = pre_process_numbers(numbers, alpha, plaintext_modulus);
    
    //std::vector<int64_t> all_ones(8192, 1);
    //std::vector<int64_t> pre_processed_all_ones = pre_process_numbers(all_ones, alpha, plaintext_modulus);

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
    
        // Create Plaintexts
    std::vector<Ciphertext<DCRTPoly>> ciphertexts;
    Ciphertext<DCRTPoly> processedCipher; 
    int begin, end;
    
    for(int i = 0; i < number_vectors; i++){
        // Calculate beginning and end of plaintext values
        begin = i * size_vectors;
        end = size_vectors * (i + 1);

        // Encode Plaintext  with coefficient packing and encrypt it into a ciphertext vector
        Plaintext plaintext = cryptoContext->MakeCoefPackedPlaintext(std::vector<int64_t>(pre_processed_numbers.begin() + begin, pre_processed_numbers.begin() + end));
        ciphertexts.push_back(cryptoContext->Encrypt(keyPair.publicKey, plaintext));
    }
	    
    //Plaintext all_ones_plaintext = cryptoContext->MakeCoefPackedPlaintext(pre_processed_all_ones);

    // Homomorphic Operations 
   // auto ciphertextAdd = cryptoContext->EvalMult(ciphertexts[0], all_ones_plaintext); 

    // Decryption
    Plaintext plaintextDec;
 
    cryptoContext->Decrypt(keyPair.secretKey, ciphertexts[0], &plaintextDec);
   std::vector<int64_t> post_processed_values = post_process_numbers(plaintextDec->GetCoefPackedValue(), inverse_alpha, plaintext_modulus);
    std::cout << post_processed_values << std::endl <<std::endl << std::endl;
    
}

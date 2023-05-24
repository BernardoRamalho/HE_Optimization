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
    std::vector<int64_t> all_numbers;

    numbers_file >> number_vectors;
    numbers_file >> size_vectors;
    int64_t plaintext_modulus = 65537;
    int64_t total_elements = size_vectors * number_vectors;
    int64_t alpha = 81, subtractions_done = 0, pre_processed_value;
	   // , alpha1 = 8091;
	   
    int alphaValue = 1;
    // Body of the file contains all the numbers
    while (numbers_file >> number) {
	    
	pre_processed_value = number * alphaValue % plaintext_modulus;

        alphaValue = alphaValue * alpha % plaintext_modulus;

        if(pre_processed_value > (plaintext_modulus - 1 ) /2){
		    pre_processed_value = pre_processed_value - plaintext_modulus;
	    }

        all_numbers.push_back(pre_processed_value);
    }
    // Due to the optimization we can do log(n) - 1 rotations
    double number_rotations = ceil(log2(size_vectors));
     TimeVar t;
    std::vector<double> processingTimes = {0.0, 0.0, 0.0, 0.0, 0.0};

    TIC(t);

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
    std::cout << parameters.GetSecretKeyDist() << std::endl;
    // Key Generation

    // Initialize Public Key Containers
    KeyPair<DCRTPoly> keyPair;

    // Generate a public/private key pair
    keyPair = cryptoContext->KeyGen();

    // Generate the relinearization key
    cryptoContext->EvalMultKeyGen(keyPair.secretKey);
    
    // Generate the rotation plaintexts
    std::vector<Plaintext> rotation_plaintexts;
    Plaintext plaintextRot;

    for(int i = 0; i < number_rotations; i++){
	    // Create vector of size 8192 filled with 0
        std::vector<int64_t> rotationVector(8191, 0);

        // Rotating by 2^i --> element @ index 2^i = 1
	    rotationVector[(int)pow(2, i)] = 1;

        rotation_plaintexts.push_back(cryptoContext->MakeCoefPackedPlaintext(rotationVector));
    }

    
    // Print time spent on setup
    TOC(t);
    processingTimes[0] = TOC(t);
    
    std::cout << "Duration of setup: " << processingTimes[0] << "ms" << std::endl;

    TIC(t);

    // Create Plaintexts
    std::vector<Ciphertext<DCRTPoly>> ciphertexts;
   Ciphertext<DCRTPoly> processedCipher; 
    int begin, end;
    
    for(int i = 0; i < number_vectors; i++){
        // Calculate beginning and end of plaintext values
        begin = i * size_vectors;
        end = size_vectors * (i + 1);

        // Encode Plaintext  with coefficient packing and encrypt it into a ciphertext vector
        Plaintext plaintext = cryptoContext->MakeCoefPackedPlaintext(std::vector<int64_t>(all_numbers.begin() + begin, all_numbers.begin() + end));
        ciphertexts.push_back(cryptoContext->Encrypt(keyPair.publicKey, plaintext));
    }

    // Print time spent on encryption
    TOC(t);
    processingTimes[1] = TOC(t);
 
    std::cout << "Duration of encryption: " << processingTimes[1] << "ms" << std::endl;
    
    TIC(t);
	    
    // Homomorphic Operations 
    //auto ciphertextAdd = cryptoContext->EvalAddMany(ciphertexts);
   // auto ciphertextRot = ciphertextAdd;
    auto ciphertextAdd = cryptoContext->EvalMult(ciphertexts[0], ciphertexts[0]); 
    // For each iteration, rotate the vector through multiplication and then add it with the non rotated vector
   // for(int i = 0; i < number_rotations; i++){
   //	    ciphertextRot = cryptoContext->EvalMult(ciphertextAdd, rotation_plaintexts[i]);
     //   ciphertextAdd = cryptoContext->EvalAdd(ciphertextAdd, ciphertextRot);
   // }

    // Print time spent on homomorphic operations
    TOC(t);
    processingTimes[2] = TOC(t);
 
    std::cout << "Duration of homomorphic operations: " << processingTimes[2] << "ms" << std::endl;
    
    TIC(t);

    // Decryption
    Plaintext plaintextDecAdd;
 
    cryptoContext->Decrypt(keyPair.secretKey, ciphertextAdd, &plaintextDecAdd);

    // Print time spent on decryption
    TOC(t);
    processingTimes[3] = TOC(t);
    std::cout << plaintextDecAdd->GetCoefPackedValue() << std::endl; 
    std::cout << "Duration of decryption: " << processingTimes[3] << "ms" << std::endl;
    std::cout << "Substractions done: " <<  subtractions_done << std::endl;    
   TIC(t);

    // Plaintext Operations
    int numberValues = plaintextDecAdd->GetCoefPackedValue().size();
    
    double mean_sum = plaintextDecAdd->GetCoefPackedValue()[0]*-1 + plaintextDecAdd->GetCoefPackedValue()[numberValues - 1];
   
    double mean = mean_sum / total_elements; 

    // Print time spent on plaintext operations
    TOC(t);
    processingTimes[4] = TOC(t);
 
    std::cout << "Duration of plaintext operations: " << processingTimes[4] << "ms" << std::endl;
    
    // Calculate and print final time and value
    double total_time = std::reduce(processingTimes.begin(), processingTimes.end());

    std::cout << "Total runtime: " << total_time << "ms" << std::endl;
    std::cout << "Mean: " << mean << std::endl;

}

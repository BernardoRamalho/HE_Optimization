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

void printIntoCSV(std::vector<double> processingTimes, double total_time, double mean){
    // Open the file
    std::string filePath;

    std::ofstream meanCSV("timeCSVs/1000mean.csv", std::ios_base::app);
    
    meanCSV << "pre-proc-coef-rot, ";

    for(unsigned int i = 0; i < processingTimes.size(); i++){
        meanCSV << processingTimes[i] << ", ";
    }
    meanCSV << total_time << ", ";
    
    meanCSV << mean << std::endl;
 
    meanCSV.close();
}

std::vector<int64_t> generate_alpha_values(int64_t alpha, int64_t plaintext_modulus, int size){
    std::vector<int64_t> alpha_values;
    int64_t alpha_value = 1;

    for(unsigned int i = 0; i < size; i++){
        alpha_values.append(alpha_value);

        alpha_value = alpha_value * alpha % plaintext_modulus;
    }

    return alpha_values;
}

std::vector<int64_t> pre_process_numbers(std::vector<int64_t> values, std::vector<int64_t> alphas, int64_t plaintext_modulus){
    std::vector<int64_t> pre_processed_values;
    int64_t pre_processed_value;
    unsigned long long mult_value;

    for(unsigned int i = 0; i < values.size(); i++){
	    mult_value = values[i] * alphas[i];

        pre_processed_value = mult_value % plaintext_modulus;

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

    int64_t total_elements = size_vectors * number_vectors;

    // Body of the file contains all the numbers
    while (numbers_file >> number) {
        all_numbers.push_back(number);
    }

    // Due to the optimization we can do log(n) - 1 rotations
    double number_rotations = ceil(log2(size_vectors)) - 1;

    TimeVar t;
    std::vector<double> processingTimes = {0.0, 0.0, 0.0, 0.0, 0.0};

    TIC(t);
    int64_t plaintext_modulus = 4295049217;

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
    int64_t alpha = 626534755, inverse_alpha = 2398041854;
	
    std::vector<int64_t> alpha_values = generate_alpha_values(alpha, plaintext_modulus, size_vectors);
    std::vector<int64_t> pre_processed_numbers = pre_process_numbers(all_numbers, alpha_values, plaintext_modulus);
    

    // Generate the rotation plaintexts
    std::vector<Plaintext> rotation_plaintexts;
    Plaintext plaintextRot;

    for(int i = 0; i < number_rotations; i++){
	    // Create vector of size 8192 filled with 0
        std::vector<int64_t> rotationVector(8191, 0);

        // Rotating by 2^i --> element @ index 2^i = 1
	    rotationVector[(int)pow(2, i)] = alpha_values[(int)pow(2, i)];

        rotation_plaintexts.push_back(cryptoContext->MakeCoefPackedPlaintext(rotationVector));
    }

    
    // Print time spent on setup
    TOC(t);
    processingTimes[0] = TOC(t);
    
    //std::cout << "Duration of setup: " << processingTimes[0] << "ms" << std::endl;

    TIC(t);

    // Create Plaintexts
    std::vector<Ciphertext<DCRTPoly>> ciphertexts;
    
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
 
    //std::cout << "Duration of encryption: " << processingTimes[1] << "ms" << std::endl;
    
    TIC(t);
	    
    // Homomorphic Operations 
    auto ciphertextAdd = cryptoContext->EvalAddMany(ciphertexts);
    auto ciphertextRot = ciphertextAdd;
    
    // For each iteration, rotate the vector through multiplication and then add it with the non rotated vector
    for(int i = 0; i < number_rotations; i++){
   	    ciphertextRot = cryptoContext->EvalMult(ciphertextAdd, rotation_plaintexts[i]);
        ciphertextAdd = cryptoContext->EvalAdd(ciphertextAdd, ciphertextRot);
    }

    // Print time spent on homomorphic operations
    TOC(t);
    processingTimes[2] = TOC(t);
 
    //std::cout << "Duration of homomorphic operations: " << processingTimes[2] << "ms" << std::endl;
    
    TIC(t);

    // Decryption
    Plaintext plaintextDecAdd;
 
    cryptoContext->Decrypt(keyPair.secretKey, ciphertextAdd, &plaintextDecAdd);

    // Print time spent on decryption
    TOC(t);
    processingTimes[3] = TOC(t);
 
    //std::cout << "Duration of decryption: " << processingTimes[3] << "ms" << std::endl;
    
    TIC(t);

    // Plaintext Operations
    std::vector<int64_t> post_processed_values = post_process_numbers(plaintextDec->GetCoefPackedValue(), inverse_alpha, plaintext_modulus);

    int numberValues = post_processed_values.size();
    
    double mean_sum = post_processed_values[0]*-1 + post_processed_values[numberValues - 1];
   
    double mean = mean_sum / total_elements; 

    // Print time spent on plaintext operations
    TOC(t);
    processingTimes[4] = TOC(t);
 
    //std::cout << "Duration of plaintext operations: " << processingTimes[4] << "ms" << std::endl;
    
    // Calculate and print final time and value
    double total_time = std::reduce(processingTimes.begin(), processingTimes.end());

    //std::cout << "Total runtime: " << total_time << "ms" << std::endl;
    //std::cout << "Mean: " << mean << std::endl;

    printIntoCSV(processingTimes, total_time, mean);
}
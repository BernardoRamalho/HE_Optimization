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

void printIntoCSV(std::vector<double> processingTimes, double total_time, double mean, std::string name){
    // Open the file
    std::string filePath;

    std::ofstream meanCSV("timeCSVs/ringDimOptimization.csv", std::ios_base::app);
    
    meanCSV << name << ", ";


    for(unsigned int i = 0; i < processingTimes.size(); i++){
        meanCSV << processingTimes[i] << ", ";
    }
    meanCSV << total_time << ", ";
    
    meanCSV << mean << std::endl;
 
    meanCSV.close();
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
    int64_t total_elements, number;
    std::vector<int64_t> all_numbers;

    numbers_file >> total_elements;

    // Body of the file contains all the numbers
    while (numbers_file >> number) {
        all_numbers.push_back(number);
    }

    TimeVar t;
    std::vector<double> processingTimes = {0.0, 0.0, 0.0, 0.0, 0.0};

    TIC(t);
    int64_t plaintext_modulus = atol(argv[2]);
    int64_t ringDim = atoi(argv[3]);
    float standardDev = atof(argv[4]);
    
    int64_t number_vectors = total_elements / ringDim;

    // Set CryptoContext
    CCParams<CryptoContextBFVRNS> parameters;
    parameters.SetPlaintextModulus(plaintext_modulus);
    parameters.SetMultiplicativeDepth(2);
    parameters.SetSecurityLevel(HEStd_NotSet); // disable security
    parameters.SetRingDim(ringDim);
    parameters.SetStandardDeviation(standardDev);

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

    
    std::vector<int64_t> all_ones(ringDim, 1);

    Plaintext all_ones_plaintext = cryptoContext->MakeCoefPackedPlaintext(all_ones);

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
        begin = i * ringDim;
        end = ringDim * (i + 1);

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

    ciphertextAdd = cryptoContext->EvalMult(ciphertextAdd, all_ones_plaintext); 

    // Print time spent on homomorphic operations
    TOC(t);
    processingTimes[2] = TOC(t);
 
    //std::cout << "Duration of homomorphic operations: " << processingTimes[2] << "ms" << std::endl;
    
    TIC(t);

    // Decryption
    Plaintext plaintextDec;
 
    cryptoContext->Decrypt(keyPair.secretKey, ciphertextAdd, &plaintextDec);

    // Print time spent on decryption
    TOC(t);
    processingTimes[3] = TOC(t);
 
    //std::cout << "Duration of decryption: " << processingTimes[3] << "ms" << std::endl;
    TIC(t);

    // Plaintext Operations
    int numberValues = plaintextDec->GetCoefPackedValue().size();
    double mean_sum = plaintextDec->GetCoefPackedValue()[numberValues - 1];
   
    //double mean = mean_sum / total_elements; 

    // Print time spent on plaintext operations
    TOC(t);
    processingTimes[4] = TOC(t);
 
    //std::cout << "Duration of plaintext operations: " << processingTimes[4] << "ms" << std::endl;
    
    // Calculate and print final time and value
    double total_time = std::reduce(processingTimes.begin(), processingTimes.end());

    //std::cout << "Total runtime: " << total_time << "ms" << std::endl;
    //std::cout << "Sum: " << mean_sum << std::endl;

   printIntoCSV(processingTimes, total_time, mean_sum, argv[5]);
}

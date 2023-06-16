/**
 * @file optimized-inner-product.cpp
 * @author Bernardo Ramalho
 * @brief Optimized implementation of the inner product between two vectors
 * @version 0.1
 * @date 2023-04-05
 * 
 * @copyright Copyright (c) 2023
 *  
 */

#include "openfhe.h"
#include <iostream>
#include <fstream>
#include <cmath>

using namespace lbcrypto;

void printIntoCSV(std::vector<double> processingTimes, double total_time, double innerProduct){
    // Open the file
    std::string filePath;

    std::ofstream innerProductCSV("timeCSVs/1000innerProduct.csv", std::ios_base::app);
    
    innerProductCSV<< "optimized-slot, ";

    for(unsigned int i = 0; i < processingTimes.size(); i++){
        innerProductCSV<< processingTimes[i] << ", ";
    }
    innerProductCSV<< total_time << ", ";
    
    innerProductCSV<< innerProduct << std::endl;
 
    innerProductCSV.close();
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
    
    // Generate the rotation evaluation keys
    // Due to the optimization we can do log(n) - 1 rotations
    double number_rotations = ceil(log2(ringDim));
    std::vector<int32_t> rotation_indexes;
    for(int i = 0; i < number_rotations; i++){
       rotation_indexes.push_back(pow(2,i)); // Rotate always in 2^i
    }

    cryptoContext->EvalRotateKeyGen(keyPair.secretKey, rotation_indexes);    
    
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

        // Encode Plaintext with slot packing and encrypt it into a ciphertext vector
        Plaintext plaintext = cryptoContext->MakePackedPlaintext(std::vector<int64_t>(all_numbers.begin() + begin, all_numbers.begin() + end));
        ciphertexts.push_back(cryptoContext->Encrypt(keyPair.publicKey, plaintext));
    }
    
    // Print time spent on encryption
    TOC(t);
    processingTimes[1] = TOC(t);
 
    //std::cout << "Duration of encryption: " << processingTimes[1] << "ms" << std::endl;
    
    TIC(t);
	    
    // Homomorphic Operations 
    for(int i = 0; i < ciphertexts.size(); i++){
        ciphertexts[i] = cryptoContext->EvalMult(ciphertexts[i], ciphertexts[i])
    }

    Ciphertext<DCRTPoly> ciphertextResult = cryptoContext->EvalAddMany(ciphertexts);
    
    // Rotate and sum until all values are summed together
    Ciphertext<DCRTPoly> ciphertextRot;
    for(int i = 0; i < number_rotations; i++){
        ciphertextRot = cryptoContext->EvalRotate(ciphertextResult, pow(2, i));
     
        ciphertextResult = cryptoContext->EvalAdd(ciphertextResult, ciphertextRot);
    }

    // Print time spent on homomorphic operations
    TOC(t);
    processingTimes[2] = TOC(t);
 
    //std::cout << "Duration of homomorphic operations: " << processingTimes[2] << "ms" << std::endl;
    
    TIC(t);

    // Decryption
    Plaintext plaintextDecAdd;
  
    cryptoContext->Decrypt(keyPair.secretKey, ciphertextResult, &plaintextDecAdd);
    plaintextDecAdd->SetLength(vector_size);
    
    // Print time spent on decryption
    TOC(t);
    processingTimes[3] = TOC(t);
 
    //std::cout << "Duration of decryption: " << processingTimes[3] << "ms" << std::endl;

    // Inner Product value will be in the first element of the plaintext
    int64_t inner_product = plaintextDecAdd->GetPackedValue()[0] + plaintextDecAdd->GetPackedValue()[vector_size/2];

    // Calculate and print final time and value
    double total_time = std::reduce(processingTimes.begin(), processingTimes.end());

    std::cout << "Total runtime: " << total_time << "ms" << std::endl;
    std::cout << "Inner Product: " << inner_product << std::endl;

    //printIntoCSV(processingTimes, total_time, inner_product);

    return 0;
}

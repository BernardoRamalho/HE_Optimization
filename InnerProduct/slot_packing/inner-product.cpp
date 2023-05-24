/**
 * @file inner-product.cpp
 * @author Bernardo Ramalho
 * @brief Naive implementation of the inner product between two vectors
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

void printIntoCSV(std::vector<double> processingTimes, double total_time, double innerProduct){
    // Open the file
    std::string filePath;

    std::ofstream innerProductCSV("timeCSVs/innerProduct.csv", std::ios_base::app);
    std::cout.rdbuf(innerProductCSV.rdbuf()); //redirect std::cout to out.txt!
    
    std::cout << "\nsimple, ";

    for(unsigned int i = 0; i < processingTimes.size(); i++){
        std::cout << processingTimes[i] << ", ";
    }
    std::cout << total_time << ", ";
    
    std::cout << innerProduct << std::endl;
 
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
    
    // Body of file is made of two lines, each representing a vector
    int64_t number;                                 // Variable to store the read number
    std::string vector_line;                        // Variable to store a whole line
    std::vector<std::vector<int64_t>> vectors;      // Vector contains both vectors in the file

    while(std::getline(numbers_file, vector_line)){
        // Read the line
        std::istringstream line(vector_line);

        // Read a number at a time from the line and store it in a vector
        std::vector<int64_t> v;
        while (line >> number) {
            v.push_back(number);
        }
        
        // Save the vector in a 2D vector
        vectors.push_back(v);
    }
    
    int64_t vector_size = vectors[0].size();

    TimeVar t;
    std::vector<double> processingTimes = {0.0, 0.0, 0.0, 0.0};

    TIC(t);

    // Set CryptoContext
    CCParams<CryptoContextBFVRNS> parameters;
    parameters.SetPlaintextModulus(65537);
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
    
    // Generate the rotation evaluation keys
    cryptoContext->EvalRotateKeyGen(keyPair.secretKey, {1, 2, -1, -2});    
    
    // Print time spent on setup
    TOC(t);
    processingTimes[0] = TOC(t);
    
    std::cout << "Duration of setup: " << processingTimes[0] << "ms" << std::endl;

    TIC(t);

    // Create Plaintexts
    std::vector<Ciphertext<DCRTPoly>> ciphertexts;
    
    for(int i = 0; i < 2; i++){
        // Encode Plaintext with slot packing
        Plaintext plaintext = cryptoContext->MakePackedPlaintext(vectors[i]);
        
        // Encrypt it into a ciphertext vector
        ciphertexts.push_back(cryptoContext->Encrypt(keyPair.publicKey, plaintext));
    }

    // Print time spent on encryption
    TOC(t);
    processingTimes[1] = TOC(t);
 
    std::cout << "Duration of encryption: " << processingTimes[1] << "ms" << std::endl;
    
    TIC(t);
	    
    // Homomorphic Operations 
    // Start by Multiplying both vectors together
    auto ciphertextResult = cryptoContext->EvalMult(ciphertexts[0], ciphertexts[1]);

    // Rotate and sum, until all values are summed together
    auto ciphertextRot = ciphertextResult;
    for(int i = 0; i <= vector_size; i++){
        ciphertextRot = cryptoContext->EvalRotate(ciphertextRot, 1);

        ciphertextResult = cryptoContext->EvalAdd(ciphertextResult, ciphertextRot);
    }

    // Print time spent on homomorphic operations
    TOC(t);
    processingTimes[2] = TOC(t);
 
    std::cout << "Duration of homomorphic operations: " << processingTimes[2] << "ms" << std::endl;
    
    TIC(t);

    // Decryption
    Plaintext plaintextDecAdd;
 
    cryptoContext->Decrypt(keyPair.secretKey, ciphertextResult, &plaintextDecAdd);
    plaintextDecAdd->SetLength(vector_size);

    // Print time spent on decryption
    TOC(t);
    processingTimes[3] = TOC(t);
 
    std::cout << "Duration of decryption: " << processingTimes[3] << "ms" << std::endl;

    // Inner Product value will be in the first element of the plaintext
    int64_t inner_product = plaintextDecAdd->GetPackedValue()[0];

    // Calculate and print final time and value
    double total_time = std::reduce(processingTimes.begin(), processingTimes.end());

    std::cout << "Total runtime: " << total_time << "ms" << std::endl;
    std::cout << "Inner Product: " << inner_product << std::endl;

    printIntoCSV(processingTimes, total_time, inner_product);

    return 0;
}

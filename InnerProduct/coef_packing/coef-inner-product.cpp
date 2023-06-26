/**
 * @file coef-inner-product.cpp
 * @author Bernardo Ramalho
 * @brief Optimized implementation of the inner product between two vectors using coefficient packing
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

void printIntoCSV(std::vector<double> processingTimes, double total_time, double innerProduct, std::string name){
    // Open the file
    std::string filePath;

    std::ofstream innerProductCSV("timeCSVs/innerProdCoefToSlotTimes.csv", std::ios_base::app);
    
    innerProductCSV<< name << ", ";

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
    std::vector<double> processingTimes = {0.0, 0.0, 0.0, 0.0};

    TIC(t);
    int64_t plaintext_modulus = atol(argv[2]);
    int64_t ringDim = atoi(argv[3]);
    float standardDev = atof(argv[4]);
    
    int64_t number_vectors = 1;

    if(ringDim < total_elements){
	    number_vectors = total_elements / ringDim;
    }

    if((int)all_numbers.size() < (int)ringDim){
	    std::vector<int64_t> zeros(ringDim - all_numbers.size(), 0);
	    all_numbers.insert(all_numbers.end(), zeros.begin(), zeros.end());
    }

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

    // Print time spent on setup
    TOC(t);
    processingTimes[0] = TOC(t);
    
    ////std::cout << "Duration of setup: " << processingTimes[0] << "ms" << std::endl;

    TIC(t);

    // Create Plaintexts
    std::vector<Ciphertext<DCRTPoly>> ciphertexts;
    std::vector<Ciphertext<DCRTPoly>> inverted_ciphertexts;

    int begin, end;
    
    for(int i = 0; i < number_vectors; i++){
        // Calculate beginning and end of plaintext values
        begin = i * ringDim;
        end = ringDim * (i + 1);

        // Create vectors
        std::vector<int64_t> numbers(all_numbers.begin() + begin, all_numbers.begin() + end);
        std::vector<int64_t> inverted_numbers = numbers;
        reverse(inverted_numbers.begin(), inverted_numbers.end()); 

        // Encode Plaintext with coef packing and encrypt it into a ciphertext vector
        Plaintext plaintext = cryptoContext->MakeCoefPackedPlaintext(numbers);
        ciphertexts.push_back(cryptoContext->Encrypt(keyPair.publicKey, plaintext));
       
       	Plaintext inverted_plaintext = cryptoContext->MakeCoefPackedPlaintext(inverted_numbers);
        inverted_ciphertexts.push_back(cryptoContext->Encrypt(keyPair.publicKey, inverted_plaintext));

    }

    // Print time spent on encryption
    TOC(t);
    processingTimes[1] = TOC(t);
 
    ////std::cout << "Duration of encryption: " << processingTimes[1] << "ms" << std::endl;
    
    TIC(t);
	    
    // Calculate the Inner Product
    // Multiplying all vectors together will calculate the Inner Product value on the last index of the plaintext
    for(unsigned int i = 0; i < ciphertexts.size(); i++){
        ciphertexts[i] = cryptoContext->EvalMult(ciphertexts[i], inverted_ciphertexts[i]);
    }

    // Print time spent on Mult
    TOC(t);
    processingTimes[2] = TOC(t);
    TIC(t);

    Ciphertext<DCRTPoly> ciphertextInnerProduct = cryptoContext->EvalAddMany(ciphertexts);

    // Print time spent on Mult
    TOC(t);
    processingTimes[3] = TOC(t);

    // Decryption
    Plaintext plaintextDecAdd;
  
    cryptoContext->Decrypt(keyPair.secretKey, ciphertextInnerProduct, &plaintextDecAdd);

   // Inner Product value will be in the last element of the plaintext
    int64_t inner_product = plaintextDecAdd->GetCoefPackedValue()[ringDim - 1];

    // Calculate and print final time and value
    double total_time = std::reduce(processingTimes.begin(), processingTimes.end());

    //std::cout << "Total runtime: " << total_time << "ms" << std::endl;
    //std::cout << "Inner Product: " << inner_product << std::endl;

    printIntoCSV(processingTimes, total_time, inner_product, argv[5]);

    return 0;
}

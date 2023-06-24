/**
 * @file optimized-rotation-mean.cpp
 * @author Bernardo Ramalho
 * @brief Optimized FHE implementation of the mean of n values using Slot Packing
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

    std::ofstream meanCSV("timeCSVs/sumSlotTimes.csv", std::ios_base::app);
    
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
    
    // Generate the rotation evaluation keys
    // Due to the optimization we can do log(n) - 1 rotations
    double number_rotations = ceil(log2(ringDim)) - 1;
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
    TIC(t);
	    
    // Homomorphic Operations 
    auto ciphertextAdd = cryptoContext->EvalAddMany(ciphertexts);

    // Print time spent on Add many
    TOC(t);
    processingTimes[2] = TOC(t);
    TIC(t);

    auto ciphertextRot = ciphertextAdd;

    for(int i = 0; i < number_rotations; i++){
        ciphertextRot = cryptoContext->EvalRotate(ciphertextAdd, pow(2, i));

        ciphertextAdd = cryptoContext->EvalAdd(ciphertextAdd, ciphertextRot);
    }

    // Print time spent on Rot + Add
    TOC(t);
    processingTimes[3] = TOC(t);

    // Decryption
    Plaintext plaintextDecAdd;
 
    cryptoContext->Decrypt(keyPair.secretKey, ciphertextAdd, &plaintextDecAdd);

    // Plaintext Operations
    double mean_sum = plaintextDecAdd->GetPackedValue()[0] + plaintextDecAdd->GetPackedValue()[ringDim/2];

 
    //std::cout << "Duration of plaintext operations: " << processingTimes[4] << "ms" << std::endl;
    
    // Calculate and print final time and value
    double total_time = std::reduce(processingTimes.begin(), processingTimes.end());

    //std::cout << "Total runtime: " << total_time << "ms" << std::endl;
    //std::cout << "Sum: " << mean_sum << std::endl;
    
    printIntoCSV(processingTimes, total_time, mean_sum, argv[5]);
}

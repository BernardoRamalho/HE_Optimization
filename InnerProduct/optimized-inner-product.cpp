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
    int64_t number, nr_elements;
    std::vector<std::vector<int64_t>> vectors;
    std::string vector_line;

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
    
    // Due to the optimization we can do log(n) - 1 rotations, instead of n rotations
    double number_rotations = ceil(log2(vectors[0].size())) - 1;
    
    // For that to work, each vector has to be 2^x in size
    nr_elements = (int)pow(2, number_rotations + 1);
    int64_t vector_size = vectors[0].size();

    // If the provided vectors are not 2^x size, fille it with zeros until it is
    if(nr_elements != vector_size){
      // Generate a vector of zeros with size such that when we append it to the vectors, they will be 2^x in size
      std::vector<int64_t> zeros(nr_elements - vector_size);
      
      // Append the vector of zeros to the original vectors
      vectors[0].insert(vectors[0].end(), zeros.begin(), zeros.end());
      vectors[1].insert(vectors[1].end(), zeros.begin(), zeros.end()); 
      
      // Set the vector size to the correct value
      vector_size = nr_elements;
    }

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
    std::cout << "n = " << cryptoContext->GetCryptoParameters()->GetElementParams()->GetCyclotomicOrder()/2 << std::endl;
    std::cout << "log2 q = " << log2(cryptoContext->GetCryptoParameters()->GetElementParams()->GetModulus().ConvertToDouble()) << std::endl;
    // Key Generation

    // Initialize Public Key Containers
    KeyPair<DCRTPoly> keyPair;

    // Generate a public/private key pair
    keyPair = cryptoContext->KeyGen();

    // Generate the relinearization key
    cryptoContext->EvalMultKeyGen(keyPair.secretKey);
    
    // Generate the rotation evaluation keys
    std::vector<int32_t> rotation_indexes;
    for(int i = 0; i < number_rotations; i++){
       rotation_indexes.push_back(pow(2,i)); 
    }

    cryptoContext->EvalRotateKeyGen(keyPair.secretKey,rotation_indexes);    
    
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
	plaintext->SetLength(vector_size);

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
    Ciphertext<DCRTPoly> ciphertextResult = cryptoContext->EvalMult(ciphertexts[0], ciphertexts[1]);
    
    // Rotate and sum until all values are summed together
    Ciphertext<DCRTPoly> ciphertextRot;
    for(int i = 0; i < number_rotations; i++){
        ciphertextRot = cryptoContext->EvalRotate(ciphertextResult, pow(2, i));
     
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
    int64_t scalar_product = plaintextDecAdd->GetPackedValue()[0] + plaintextDecAdd->GetPackedValue()[vector_size/2];

    // Calculate and print final time and value
    double total_time = std::reduce(processingTimes.begin(), processingTimes.end());

    std::cout << "Total runtime: " << total_time << "ms" << std::endl;
    std::cout << "Scalar Product: " << scalar_product << std::endl;

    return 0;
}

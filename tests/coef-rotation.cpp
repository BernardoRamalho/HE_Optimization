/**
 * @file coef-rotation.cpp
 * @author Bernardo Ramalho
 * @brief test if, while using coefficient packing, multiplication of ciphertext with (0, 1, 0, 0) lead to a rotation by 1
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
int main() {
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

    // Create Plaintexts
    std::vector<Ciphertext<DCRTPoly>> ciphertexts;
    std::vector<int64_t> v = {1, 2, 3, 4};
    std::vector<int64_t> r = {0, 1, 0, 0};

    Plaintext plaintext = cryptoContext->MakeCoefPackedPlaintext(v);
    ciphertexts.push_back(cryptoContext->Encrypt(keyPair.publicKey, plaintext));
    Plaintext plaintextRot = cryptoContext->MakeCoefPackedPlaintext(r);
    ciphertexts.push_back(cryptoContext->Encrypt(keyPair.publicKey, plaintextRot));
	    
    // Homomorphic Operations 

    auto ciphertextAdd = cryptoContext->EvalMult(ciphertexts[0], ciphertexts[1]);

    // Decryption
    Plaintext plaintextDecAdd;
 
    cryptoContext->Decrypt(keyPair.secretKey, ciphertextAdd, &plaintextDecAdd);
    plaintextDecAdd->SetLength(5);

    // Plaintext Operations
    double total_time = std::reduce(processingTimes.begin(), processingTimes.end());

    std::cout << "Initial Plaintext: " << plaintext->GetCoefPackedValue() << std::endl;
    std::cout << "Rotation Plaintext: " << plaintextRot->GetCoefPackedValue() << std::endl;
    std::cout << "Final Plaintext: " << plaintextDecAdd->GetCoefPackedValue() << std::endl;

    return 0;
}

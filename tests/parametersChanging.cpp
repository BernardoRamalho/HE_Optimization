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
#include <cstdlib>
using namespace lbcrypto;

/*
 * argv[1] --> number's file name
*/
int main(int argc, char *argv[]) {
    // Auxiliary Variables for the Pre Processing 
    uint64_t plaintext_modulus = 5865951068471297;
    std::cout << "Modulus: " << plaintext_modulus << std::endl;	

    // Set CryptoContext
    CCParams<CryptoContextBFVRNS> parameters;
    parameters.SetPlaintextModulus(plaintext_modulus);
    parameters.SetMultiplicativeDepth(atoi(argv[2]));
parameters.SetSecurityLevel(HEStd_NotSet); // disable security
parameters.SetRingDim( atoi(argv[3]) );
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

    // Generate rotation vectors
    Plaintext plaintextRot;

        // Create vector of size 8192 filled with 0
    std::vector<int64_t> rotationVector(atoi(argv[3]), 0);

        // Rotating by 2^i --> element @ index 2^i = 1
    rotationVector[1] = 1;

        // Encrypt using Coefficient Packing
        plaintextRot = cryptoContext->MakeCoefPackedPlaintext(rotationVector);

    // Generate the relinearization key
    cryptoContext->EvalMultKeyGen(keyPair.secretKey);
    auto n = cryptoContext->GetCryptoParameters()->GetElementParams()->GetCyclotomicOrder() / 2;
	std::cout << "Size: " << n << std::endl;

	std::vector<int64_t> vec(n, 1);
        vec[0] = 2;
	Plaintext p = cryptoContext->MakeCoefPackedPlaintext(vec);

	auto c = cryptoContext->Encrypt(keyPair.publicKey, p);

        c = cryptoContext->EvalMult(c, plaintextRot);

	cryptoContext->Decrypt(keyPair.secretKey, c, &p);

	std::cout << p->GetCoefPackedValue() << std::endl;

}

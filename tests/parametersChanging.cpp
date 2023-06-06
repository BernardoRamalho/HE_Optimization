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
    auto plaintext_modulus = std::stol(argv[1]);
    std::cout << "Modulus: " << plaintext_modulus << std::endl;	

    // Set CryptoContext
    CCParams<CryptoContextBFVRNS> parameters;
    parameters.SetPlaintextModulus(plaintext_modulus);
    parameters.SetMultiplicativeDepth(atoi(argv[2]));

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
    auto n = cryptoContext->GetCryptoParameters()->GetElementParams()->GetCyclotomicOrder() / 2;
	std::cout << "Size: " << n << std::endl;

	std::vector<int64_t> vec(n, 1);

	Plaintext p = cryptoContext->MakePackedPlaintext(vec);

	auto c = cryptoContext->Encrypt(keyPair.publicKey, p);

        c = cryptoContext->EvalAdd(c, c);

	cryptoContext->Decrypt(keyPair.secretKey, c, &p);

	std::cout << p->GetPackedValue().size() << std::endl;

}

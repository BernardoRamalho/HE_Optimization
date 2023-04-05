/**
 * @file plaintextSize.cpp
 * @author Bernardo Ramalho
 * @brief test to check what is the maximum number of values in a plaintext
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

    //Set CryptoContext
    CCParams<CryptoContextBFVRNS> parameters;
    parameters.SetPlaintextModulus(65537);
    parameters.SetMultiplicativeDepth(2);

    CryptoContext<DCRTPoly> cryptoContext = GenCryptoContext(parameters);
    // Enable features that you wish to use
    cryptoContext->Enable(PKE);
    cryptoContext->Enable(KEYSWITCH);
    cryptoContext->Enable(LEVELEDSHE);
    cryptoContext->Enable(ADVANCEDSHE);

    // Print some parameters
    std::cout << "n = " << cryptoContext->GetCryptoParameters()->GetElementParams()->GetCyclotomicOrder()/2 << std::endl;
    std::cout << "log2 q = " << log2(cryptoContext->GetCryptoParameters()->GetElementParams()->GetModulus().ConvertToDouble()) << std::endl;
 
    //Key Generation

    // Initialize Public Key Containers
    KeyPair<DCRTPoly> keyPair;

    // Generate a public/private key pair
    keyPair = cryptoContext->KeyGen();

    // Generate the relinearization key
    cryptoContext->EvalMultKeyGen(keyPair.secretKey);
    
     // Create Plaintexts
    std::vector<Ciphertext<DCRTPoly>> ciphertexts;
    std::vector<int64_t> v, r, p, s;
    
    for(int i = 0; i < 8192; i++){
       v.push_back(i);
       r.push_back(i);
       p.push_back(i);
       s.push_back(i);
    }

    r.push_back(8193);
    r.push_back(8194);
    for(int i = 0; i < 8192; i++){
       p.push_back(i);
       s.push_back(i);
    }
  
    s.push_back(8192*2);

    std::cout << "Encrypting vector v of size: " << v.size() << std::endl;
    Plaintext plaintextV = cryptoContext->MakeCoefPackedPlaintext(v);
    ciphertexts.push_back(cryptoContext->Encrypt(keyPair.publicKey, plaintextV));

    std::cout << "Encrypting vector r of size: " << r.size() << std::endl;
    Plaintext plaintextR = cryptoContext->MakeCoefPackedPlaintext(r);
    ciphertexts.push_back(cryptoContext->Encrypt(keyPair.publicKey, plaintextR));
  
    std::cout << "Encrypting vector p of size: " << p.size() << std::endl;
    Plaintext plaintextP = cryptoContext->MakeCoefPackedPlaintext(p);
    ciphertexts.push_back(cryptoContext->Encrypt(keyPair.publicKey, plaintextP));

    std::cout << "Encrypting vector s of size: " << s.size() << std::endl;
    Plaintext plaintextS = cryptoContext->MakeCoefPackedPlaintext(s);
    ciphertexts.push_back(cryptoContext->Encrypt(keyPair.publicKey, plaintextS));
  
    std::cout << plaintextS->GetPackedValue() << std::endl;
    return 0;
}

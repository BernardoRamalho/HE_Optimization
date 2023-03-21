#include "openfhe.h"
#include <iostream>
#include <fstream>

using namespace lbcrypto;
/*
 * argv[1] --> number's file name
*/
int main() {

    // Sample Program: Step 1: Set CryptoContext
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
 
    // Sample Program: Step 2: Key Generation

    // Initialize Public Key Containers
    KeyPair<DCRTPoly> keyPair;

    // Generate a public/private key pair
    keyPair = cryptoContext->KeyGen();

    // Generate the rotation evaluation keys
    cryptoContext->EvalRotateKeyGen(keyPair.secretKey, {2, 4, 8192, 8191});    
 
    // Generate the relinearization key
    cryptoContext->EvalMultKeyGen(keyPair.secretKey);
    
     // Create Plaintexts
    std::vector<Ciphertext<DCRTPoly>> ciphertexts;
    std::vector<int64_t> v;

    for(int i = 0; i < 8192; i++){
       v.push_back(i);
    }

   // v.push_back(8193);

    std::cout << "Encrypting vector v of size: " << v.size() << std::endl;
    Plaintext plaintextV = cryptoContext->MakePackedPlaintext(v);
    ciphertexts.push_back(cryptoContext->Encrypt(keyPair.publicKey, plaintextV));
    
    std::cout << plaintextV->GetPackedValue() << std::endl;
    // Rotate by 2
    auto rotCipher = cryptoContext->EvalRotate(ciphertexts[0], 2);

    std::ofstream out2("rot2.txt");
    std::cout.rdbuf(out2.rdbuf()); //redirect std::cout to out.txt!

 
        Plaintext plaintextDecAdd;
 
    cryptoContext->Decrypt(keyPair.secretKey, rotCipher, &plaintextDecAdd);
 
   std::cout << plaintextDecAdd->GetPackedValue() << std::endl;
	// Rotate by 4
    rotCipher = cryptoContext->EvalRotate(ciphertexts[0], 4);

    std::ofstream out4("rot4.txt");
    std::cout.rdbuf(out4.rdbuf()); //redirect std::cout to out.txt!

    cryptoContext->Decrypt(keyPair.secretKey, rotCipher, &plaintextDecAdd);
 
   std::cout << plaintextDecAdd->GetPackedValue() << std::endl;
    // Rotate by 8192

    rotCipher = cryptoContext->EvalRotate(ciphertexts[0], 8192);

    std::ofstream out8192("rot8192.txt");
    std::cout.rdbuf(out8192.rdbuf()); //redirect std::cout to out.txt!

    cryptoContext->Decrypt(keyPair.secretKey, rotCipher, &plaintextDecAdd);
 
   std::cout << plaintextDecAdd->GetPackedValue() << std::endl;

    return 0;
}

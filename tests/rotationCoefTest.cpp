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

    // Generate the relinearization key
    cryptoContext->EvalMultKeyGen(keyPair.secretKey);
    
     // Create Plaintexts
    std::vector<Ciphertext<DCRTPoly>> ciphertexts;
    std::vector<int64_t> v;

    for(int i = 0; i < 8192; i++){
       v.push_back(i);
    }

    std::cout << "Encrypting vector v of size: " << v.size() << std::endl;
    Plaintext plaintextV = cryptoContext->MakeCoefPackedPlaintext(v);
    ciphertexts.push_back(cryptoContext->Encrypt(keyPair.publicKey, plaintextV));
    
    std::cout << plaintextV->GetCoefPackedValue() << std::endl;
    // Rotate by 2
    std::vector<int64_t> r = {0, 0, 0, 1};

    Plaintext plaintextRot = cryptoContext->MakeCoefPackedPlaintext(r);
    ciphertexts.push_back(cryptoContext->Encrypt(keyPair.publicKey, plaintextRot));
    auto rotCipher = cryptoContext->EvalMult(ciphertexts[0], ciphertexts[1]);

    std::ofstream out2("coefRot2.txt");
    std::cout.rdbuf(out2.rdbuf()); //redirect std::cout to out.txt!

 
     Plaintext plaintextDecAdd;
 
    cryptoContext->Decrypt(keyPair.secretKey, rotCipher, &plaintextDecAdd);
 
    std::cout << plaintextDecAdd->GetCoefPackedValue() << std::endl;
    return 0;
}

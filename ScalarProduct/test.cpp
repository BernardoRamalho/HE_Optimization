#include "openfhe.h"
#include <iostream>
#include <fstream>
#include <cmath>

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

    // Sample Program: Step 2: Key Generation

    // Initialize Public Key Containers
    KeyPair<DCRTPoly> keyPair;

    // Generate a public/private key pair
    keyPair = cryptoContext->KeyGen();

    // Generate the relinearization key
    cryptoContext->EvalMultKeyGen(keyPair.secretKey);
    
    // Generate the rotation evaluation keys
    cryptoContext->EvalRotateKeyGen(keyPair.secretKey, {1, 2, 3, 4, 5});    
    
    // Create Plaintexts
    std::vector<int64_t> v  = {80, 124, 110, 86, 50};
    
    Plaintext plaintext = cryptoContext->MakePackedPlaintext(v);
    plaintext->SetLength(5);
    
    std::cout << "Plaintext: " << plaintext << " with size " << plaintext->GetLength() << " and values " << plaintext->GetPackedValue() << std::endl;
    
    Ciphertext<DCRTPoly> ciphertext = cryptoContext->Encrypt(keyPair.publicKey, plaintext);
    Ciphertext<DCRTPoly> ciphertextRot;
    
    
    // Homomorphic Operations 
    Plaintext plaintextDec;

    for(int i = 1; i < 5; i++){
        	std::cout << "Rotation: " << i << std::endl;
     	cryptoContext->Decrypt(keyPair.secretKey, ciphertext, &plaintextDec);
    		plaintextDec->SetLength(5);
    		std::cout << "Before Rot Plaintext: " << plaintextDec << " with size " << plaintextDec->GetLength() << "and values " << plaintextDec->GetPackedValue() << std::endl;
     

        ciphertextRot = cryptoContext->EvalRotate(ciphertext, i);
	std::cout << "ROTATED :))))" << std::endl; 
   		 cryptoContext->Decrypt(keyPair.secretKey, ciphertextRot, &plaintextDec);
   		 plaintextDec->SetLength(5);
   		 std::cout << "Rot Plaintext: " << plaintextDec << " with size " << plaintextDec->GetLength() << "and values " << plaintextDec->GetPackedValue() << std::endl;
    }
    return 0;
}

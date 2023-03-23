#include "openfhe.h"
#include <iostream>
#include <fstream>

using namespace lbcrypto;
/*
 * argv[1] --> number's file name
*/
int main(int argc, char *argv[]) {

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
    double closest_exponent = ceil(log2(8192));
    std::cout << "Closest Exponent: " << closest_exponent << std::endl; 
    std::vector<int32_t> rotation_indexes;
    for(int i = 0; i < closest_exponent; i++){
       rotation_indexes.push_back(pow(2,i)); 
    }

    cryptoContext->EvalRotateKeyGen(keyPair.secretKey, rotation_indexes);    
 
    // Create Plaintexts
    std::vector<Ciphertext<DCRTPoly>> ciphertexts;
    std::vector<int64_t> v;

    for(int i = 0; i < 7564; i++){
       v.push_back(1);
    }

    Plaintext plaintextV = cryptoContext->MakePackedPlaintext(v);
    ciphertexts.push_back(cryptoContext->Encrypt(keyPair.publicKey, plaintextV));
  
    Plaintext plaintextDecAdd;
    // Homomorphic Operations 
    Ciphertext<DCRTPoly> ciphertextAdd = ciphertexts[0], ciphertextRot = ciphertexts[0];
    for(int i = 0; i < closest_exponent - 1; i++){
        ciphertextRot = cryptoContext->EvalRotate(ciphertextAdd, pow(2, i));
        ciphertextAdd = cryptoContext->EvalAdd(ciphertextAdd, ciphertextRot);
    }
   
    // Decryption
 
    cryptoContext->Decrypt(keyPair.secretKey, ciphertextAdd, &plaintextDecAdd);
    plaintextDecAdd->SetLength(8192);

    // Plaintext Operations
    double mean_sum = plaintextDecAdd->GetPackedValue()[0] + plaintextDecAdd->GetPackedValue()[4096];
    std::cout << "Sum: " << mean_sum << std::endl;
    double mean = mean_sum / 8192; 
    std::cout << "Mean: " << mean << std::endl;
}

#include "openfhe.h"
#include <iostream>
#include <fstream>
#include <cstdlib>
using namespace lbcrypto;

void print_moduli_chain(const DCRTPoly& poly){
    int num_primes = poly.GetNumOfElements();
    double total_bit_len = 0.0;
    for (int i = 0; i < num_primes; i++) {
        auto qi = poly.GetParams()->GetParams()[i]->GetModulus();
        std::cout << "q_" << i << ": " 
                    << qi
                    << ",  log q_" << i <<": " << log(qi.ConvertToDouble()) / log(2)
                    << std::endl;
        total_bit_len += log(qi.ConvertToDouble()) / log(2);
    }   
    std::cout << "Total bit length: " << total_bit_len << std::endl;
}

/*
 * argv[1] --> number's file name
*/
int main(int argc, char *argv[]) {
    // Auxiliary Variables for the Pre Processing 
    uint64_t plaintext_modulus = 97;
    // Set CryptoContext
    CCParams<CryptoContextBFVRNS> parameters;
    parameters.SetPlaintextModulus(plaintext_modulus);
    parameters.SetMultiplicativeDepth(2);
    parameters.SetRingDim(131072);
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
   std::cout << "What" << std::endl; 
    const std::vector<DCRTPoly>& bgv_pk = keyPair.publicKey->GetPublicElements();
    std::cout << "Moduli chain of pk: " << std::endl;
    print_moduli_chain(bgv_pk[0]);
} 

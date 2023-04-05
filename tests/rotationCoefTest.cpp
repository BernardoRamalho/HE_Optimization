#include "openfhe.h"
#include <iostream>
#include <fstream>

using namespace lbcrypto;

int main() {
// Read the vector from a file
    std::ifstream numbers_file ("number.txt");

     if (!numbers_file.is_open()) {
        std::cerr << "Could not open the file - '"
             << "number.txt" << "'" << std::endl;
        return EXIT_FAILURE;
    }

    // Header of file contains information about nr of vector and the size of each of them
    int64_t number_vectors, size_vectors, number;
    std::vector<int64_t> all_numbers;

    numbers_file >> number_vectors;
    numbers_file >> size_vectors;

    int64_t total_elements = size_vectors * number_vectors;

    // Body of the file contains all the numbers
    while (numbers_file >> number) {
        all_numbers.push_back(number);
    }

 
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

    // Generate rotation vectors
    std::vector<Ciphertext<DCRTPoly>> rotation_ciphertexts;
    Plaintext plaintextRot;

    for(int i = 0; i < 13; i++){
        // Create vector of size 8192 filled with 0
        std::vector<int64_t> rotationVector(8191, 0);

        // Rotating by 2^i --> element @ index 2^i = 1
        rotationVector[(int)pow(2, i)] = 1;

        // Encrypt using Coefficient Packing
        plaintextRot = cryptoContext->MakeCoefPackedPlaintext(rotationVector);
        rotation_ciphertexts.push_back(cryptoContext->Encrypt(keyPair.publicKey, plaintextRot));
    }

    // Create Plaintexts
    std::vector<Ciphertext<DCRTPoly>> ciphertexts;
    
    int begin, end;
    
    for(int i = 0; i < number_vectors; i++){
        // Calculate beginning and end of plaintext values
        begin = i * size_vectors;
        end = size_vectors * (i + 1);

        // Encode Plaintext  with coefficient packing and encrypt it into a ciphertext vector
        Plaintext plaintext = cryptoContext->MakeCoefPackedPlaintext(std::vector<int64_t>(all_numbers.begin() + begin, all_numbers.begin() + end));
        ciphertexts.push_back(cryptoContext->Encrypt(keyPair.publicKey, plaintext));
    }

    // Homomorphic Operations 
    auto ciphertextAdd = cryptoContext->EvalAddMany(ciphertexts);
    
    // Save the result of the addiction into a .txt file
    // Open the file
    std::string filePath;

    std::ofstream out1("coefRotResults/coefRotAdd.txt");
    std::cout.rdbuf(out1.rdbuf()); //redirect std::cout to out.txt!
    
    // Decrypt and save it into a file
    Plaintext plaintextDecAdd;
    cryptoContext->Decrypt(keyPair.secretKey, ciphertextAdd, &plaintextDecAdd);
 
    std::cout << plaintextDecAdd->GetCoefPackedValue() << std::endl;
    out1.close();

    // Rotate 12 times and each time save the result into a .txt file
    for(int i = 0; i < 13; i++){
       // Rotate using multiplication
       auto rotCipher = cryptoContext->EvalMult(ciphertextAdd, rotation_ciphertexts[i]);
       
       // Open the .txt file
       filePath = "coefRotResults/coefRot" + std::to_string((int)pow(2, i)) + ".txt";   
       std::ofstream out2(filePath);
       std::cout.rdbuf(out2.rdbuf()); //redirect std::cout to out.txt!
       
       // Decrypt and save the result into a file
       cryptoContext->Decrypt(keyPair.secretKey, rotCipher, &plaintextDecAdd);
 
       std::cout << plaintextDecAdd->GetCoefPackedValue() << std::endl;
       out2.close();
    }


    return 0;
}

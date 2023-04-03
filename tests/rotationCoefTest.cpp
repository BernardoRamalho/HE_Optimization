#include "openfhe.h"
#include <iostream>
#include <fstream>

using namespace lbcrypto;
/*
 * argv[1] --> number's file name
*/
int main() {

    std::ifstream numbers_file ("number.txt");

     if (!numbers_file.is_open()) {
        std::cerr << "Could not open the file - '"
             << "number.txt" << "'" << std::endl;
        return EXIT_FAILURE;
    }

    int64_t number_vectors, size_vectors, number;
    std::vector<int64_t> all_numbers;

    numbers_file >> number_vectors;
    numbers_file >> size_vectors;


    while (numbers_file >> number) {
        all_numbers.push_back(number);
    }

 
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

    // Generate rotation vectors
    std::vector<Ciphertext<DCRTPoly>> rotation_ciphertexts;
    Plaintext plaintextRot;
    for(int i = 0; i < 13; i++){
	std::vector<int64_t> rotationVector(8191, 0);
	rotationVector[(int)pow(2, i)] = 1;
        plaintextRot = cryptoContext->MakeCoefPackedPlaintext(rotationVector);
        rotation_ciphertexts.push_back(cryptoContext->Encrypt(keyPair.publicKey, plaintextRot));
    }

    // Create Plaintexts
    std::vector<Ciphertext<DCRTPoly>> ciphertexts;
    
    int begin, end;
    
    for(int i = 0; i < number_vectors; i++){
        begin = i * size_vectors;
        end = size_vectors * (i + 1);

        Plaintext plaintext = cryptoContext->MakeCoefPackedPlaintext(std::vector<int64_t>(all_numbers.begin() + begin, all_numbers.begin() + end));
        ciphertexts.push_back(cryptoContext->Encrypt(keyPair.publicKey, plaintext));
    }

    // Homomorphic Operations 
    auto ciphertextAdd = cryptoContext->EvalAddMany(ciphertexts);
       // Rotate by 2
    Plaintext plaintextDecAdd;
    std::string filePath;

    std::ofstream out1("coefRotResults/coefRotAdd.txt");
    std::cout.rdbuf(out1.rdbuf()); //redirect std::cout to out.txt!

    cryptoContext->Decrypt(keyPair.secretKey, ciphertextAdd, &plaintextDecAdd);
 
    std::cout << plaintextDecAdd->GetCoefPackedValue() << std::endl;
    out1.close();


    for(int i = 0; i < 13; i++){
       auto rotCipher = cryptoContext->EvalMult(ciphertextAdd, rotation_ciphertexts[i]);
       filePath = "coefRotResults/coefRot" + std::to_string((int)pow(2, i)) + ".txt";   
       std::ofstream out2(filePath);
       std::cout.rdbuf(out2.rdbuf()); //redirect std::cout to out.txt!

       cryptoContext->Decrypt(keyPair.secretKey, rotCipher, &plaintextDecAdd);
 
       std::cout << plaintextDecAdd->GetCoefPackedValue() << std::endl;
       out2.close();
    }


    return 0;
}

#include "openfhe.h"
#include <iostream>
#include <fstream>

using namespace lbcrypto;

/*
 * argv[1] --> number's file name
*/
int main(int argc, char *argv[]) {
    // Read the vector from a file
    std::ifstream numbers_file (argv[1]);

     if (!numbers_file.is_open()) {
        std::cerr << "Could not open the file - '"
             << argv[1] << "'" << std::endl;
        return EXIT_FAILURE;
    }

    // Header of file contains information about nr of vector and the size of each of them
    int64_t number_vectors, size_vectors, number;
    std::vector<int64_t> all_number_N, inverted_all_number_N;

    numbers_file >> number_vectors;
    numbers_file >> size_vectors;

    int64_t total_elements = size_vectors * number_vectors;

    // Body of the file contains all the numbers
    while (numbers_file >> number) {
        all_number_N.push_back(number);
        inverted_all_number_N.push_back(number);
    }

    reverse(inverted_all_number_N.begin(), inverted_all_number_N.end());

    TimeVar t;
    std::vector<double> processingTimes = {0.0, 0.0, 0.0, 0.0, 0.0};

    TIC(t);

    int64_t plaintext_modulus = 4295049217;

    std::vector<int64_t> all_ones(8192, 1);

    std::vector<int64_t> multiply_by(8192, 0);
    multiply_by[0] = total_elements * total_elements;


    // Set CryptoContext
    CCParams<CryptoContextBFVRNS> parameters;
    parameters.SetPlaintextModulus(plaintext_modulus);
    parameters.SetMultiplicativeDepth(2);

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
    
    // Print time spent on setup
    TOC(t);
    processingTimes[0] = TOC(t);
    
    std::cout << "Duration of setup: " << processingTimes[0] << "ms" << std::endl;

    TIC(t);

    // Create Plaintexts
    std::vector<Ciphertext<DCRTPoly>> ciphertexts;
    std::vector<Ciphertext<DCRTPoly>> inverted_ciphertexts;

    int begin, end;
    
    for(int i = 0; i < number_vectors; i++){
        // Calculate beginning and end of plaintext values
        begin = i * size_vectors;
        end = size_vectors * (i + 1);

        // Create vectors
        std::vector<int64_t> numbers(all_number_N.begin() + begin, all_number_N.begin() + end);
        std::vector<int64_t> inverted_numbers(inverted_all_number_N.begin() + begin, inverted_all_number_N.begin() + end);;

        // Encode Plaintext with coef packing and encrypt it into a ciphertext vector
        Plaintext plaintext = cryptoContext->MakeCoefPackedPlaintext(numbers);
        ciphertexts.push_back(cryptoContext->Encrypt(keyPair.publicKey, plaintext));
       
       	Plaintext inverted_plaintext = cryptoContext->MakeCoefPackedPlaintext(inverted_numbers);
        inverted_ciphertexts.push_back(cryptoContext->Encrypt(keyPair.publicKey, inverted_plaintext));

    }
    Plaintext all_ones_plaintext = cryptoContext->MakeCoefPackedPlaintext(all_ones);
    Plaintext multiply_by_plaintext = cryptoContext->MakeCoefPackedPlaintext(multiply_by);

    // Print time spent on encryption
    TOC(t);
    processingTimes[1] = TOC(t);
 
    std::cout << "Duration of encryption: " << processingTimes[1] << "ms" << std::endl;
    
    TIC(t);
	    
    // Homomorphic Operations 
    Plaintext plaintextDec;

    // Calculate the Square Mean
    auto ciphertextSquareSum = cryptoContext->EvalAddMany(ciphertexts);

    ciphertextSquareSum = cryptoContext->EvalMult(ciphertextSquareSum, all_ones_plaintext); // Get Sum in all Indexes
    cryptoContext->Decrypt(keyPair.secretKey, ciphertextSquareSum, &plaintextDec);
    std::cout << "Sum:\n" << plaintextDec->GetCoefPackedValue() << std::endl;

    ciphertextSquareSum = cryptoContext->EvalSquare(ciphertextSquareSum); // Get square sum * total_elements in all indexes
    cryptoContext->Decrypt(keyPair.secretKey, ciphertextSquareSum, &plaintextDec);
    std::cout << "Square:\n" << plaintextDec->GetCoefPackedValue() << std::endl;

    // Calculate the Inner Product
    // Multiplying both vectors together will calculate the Inner Product value on the last index of the plaintext
    Ciphertext<DCRTPoly> ciphertextInnerProduct = cryptoContext->EvalMult(ciphertexts[0], inverted_ciphertexts[0]);
    cryptoContext->Decrypt(keyPair.secretKey, ciphertextInnerProduct, &plaintextDec);
    std::cout << "Inner:\n" << plaintextDec->GetCoefPackedValue() << std::endl;

    ciphertextInnerProduct = cryptoContext->EvalMult(ciphertextInnerProduct, multiply_by_plaintext);
    cryptoContext->Decrypt(keyPair.secretKey, ciphertextInnerProduct, &plaintextDec);
    std::cout << "n^2 * Inner:\n" << plaintextDec->GetCoefPackedValue() << std::endl;
// Subtract the mean from the inner product
    auto ciphertextResult = cryptoContext->EvalSub(ciphertextInnerProduct, ciphertextSquareSum);

    // Print time spent on homomorphic operations
    TOC(t);
    processingTimes[2] = TOC(t);
 
    std::cout << "Duration of homomorphic operations: " << processingTimes[2] << "ms" << std::endl;
    
    TIC(t);

    // Decryption
    Plaintext plaintextResult;
 
    cryptoContext->Decrypt(keyPair.secretKey, ciphertextResult, &plaintextResult);
    std::cout << "Result:\n" << plaintextResult->GetCoefPackedValue() << std::endl;
    // Print time spent on decryption
    TOC(t);
    processingTimes[3] = TOC(t);
 
    std::cout << "Duration of decryption: " << processingTimes[3] << "ms" << std::endl;
    
    TIC(t);

    // Plaintext Operations
    double variance = plaintextResult->GetCoefPackedValue()[size_vectors - 1] / pow(total_elements, 3); 

    // Print time spent on plaintext operations
    TOC(t);
    processingTimes[4] = TOC(t);
 
    std::cout << "Duration of plaintext operations: " << processingTimes[4] << "ms" << std::endl;
    
    // Calculate and print final time and value
    double total_time = std::reduce(processingTimes.begin(), processingTimes.end());

    std::cout << "Total runtime: " << total_time << "ms" << std::endl;
    std::cout << "Variance: " << variance << std::endl;
}

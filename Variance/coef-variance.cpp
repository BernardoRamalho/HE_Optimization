#include "openfhe.h"
#include <iostream>
#include <fstream>

using namespace lbcrypto;

int64_t calculateSum(CryptoContext<DCRTPoly> cryptoContext, KeyPair<DCRTPoly> keyPair, std::vector<Ciphertext<DCRTPoly>> ciphertexts, std::vector<Plaintext> rotation_plaintexts,int64_t total_elements, int64_t number_rotations, int64_t size_vectors){
    auto ciphertextAdd = cryptoContext->EvalAddMany(ciphertexts);
    auto ciphertextRot = ciphertextAdd;

    // For each iteration, rotate the vector through multiplication and then add it with the non rotated vector
    for(int i = 0; i < number_rotations ; i++){
   	    ciphertextRot = cryptoContext->EvalMult(ciphertextAdd, rotation_plaintexts[i]);
        ciphertextAdd = cryptoContext->EvalAdd(ciphertextAdd, ciphertextRot);
    }

    Plaintext sumPlaintext;
    cryptoContext->Decrypt(keyPair.secretKey, ciphertextAdd, &sumPlaintext);
    
    int64_t sum = sumPlaintext->GetCoefPackedValue()[pow(2, number_rotations) - 1] + sumPlaintext->GetCoefPackedValue()[size_vectors - 1];
    return (int)(sum / total_elements);
}

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
    std::vector<int64_t> all_number_N;

    numbers_file >> number_vectors;
    numbers_file >> size_vectors;

    int64_t total_elements = size_vectors * number_vectors;

    // Body of the file contains all the numbers
    while (numbers_file >> number) {
        all_number_N.push_back(number * total_elements);
    }

    // Due to the optimization we can do log(n) - 1 rotations
    double number_rotations = ceil(log2(size_vectors)) - 1;

    TimeVar t;
    std::vector<double> processingTimes = {0.0, 0.0, 0.0, 0.0, 0.0};

    TIC(t);

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

    // Key Generation

    // Initialize Public Key Containers
    KeyPair<DCRTPoly> keyPair;

    // Generate a public/private key pair
    keyPair = cryptoContext->KeyGen();

    // Generate the relinearization key
    cryptoContext->EvalMultKeyGen(keyPair.secretKey);
    
    // Generate the rotation plaintexts
    std::vector<Plaintext> rotation_plaintexts;
    Plaintext plaintextRot;

    for(int i = 0; i < number_rotations; i++){
	    // Create vector of size 8192 filled with 0
        std::vector<int64_t> rotationVector(8191, 0);

        // Rotating by 2^i --> element @ index 2^i = 1
	    rotationVector[(int)pow(2, i)] = 1;

        rotation_plaintexts.push_back(cryptoContext->MakeCoefPackedPlaintext(rotationVector));
    }    
    
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
        std::vector<int64_t> inverted_numbers = numbers;
        reverse(inverted_numbers.begin(), inverted_numbers.end());

        // Encode Plaintext with slot packing and encrypt it into a ciphertext vector
        Plaintext plaintext = cryptoContext->MakeCoefPackedPlaintext(numbers);
        ciphertexts.push_back(cryptoContext->Encrypt(keyPair.publicKey, plaintext));
       
       	Plaintext inverted_plaintext = cryptoContext->MakeCoefPackedPlaintext(inverted_numbers);
        inverted_ciphertexts.push_back(cryptoContext->Encrypt(keyPair.publicKey, inverted_plaintext));

    }
    
    // Print time spent on encryption
    TOC(t);
    processingTimes[1] = TOC(t);
 
    std::cout << "Duration of encryption: " << processingTimes[1] << "ms" << std::endl;
    
    TIC(t);
	    
    // Homomorphic Operations 

    // Calculate the Mean
    int64_t negSum = calculateSum(cryptoContext, keyPair, ciphertexts, rotation_plaintexts,total_elements, number_rotations, size_vectors) * -1;
     
    // Create plaintext with sum in all its indexes
    std::vector<int64_t> sumVector(size_vectors, negSum);
    Plaintext plaintextSum = cryptoContext->MakeCoefPackedPlaintext(sumVector);
    
   
    // Calculate  (xi - mean)^2
    std::vector<Ciphertext<DCRTPoly>> subCiphertexts;

    Plaintext plaintextDec;
 
    for(int i = 0; i < (int)ciphertexts.size(); i++){
        // Calculate n*xi - sum(x)
        auto ciphertextSub = cryptoContext->EvalAdd(ciphertexts[i], plaintextSum);
        auto invertedCiphertextSub = cryptoContext->EvalAdd(inverted_ciphertexts[i],plaintextSum); 
	
        // Square Everything
        subCiphertexts.push_back(cryptoContext->EvalMult(ciphertextSub, invertedCiphertextSub));
    }

    // Calculate sum((xi - mean)^2)
    auto ciphertextAdd = cryptoContext->EvalAddMany(subCiphertexts);

    // Print time spent on homomorphic operations
    TOC(t);
    processingTimes[2] = TOC(t);
 
    std::cout << "Duration of homomorphic operations: " << processingTimes[2] << "ms" << std::endl;
    
    TIC(t);

    // Decryption
    Plaintext plaintextDecAdd;
 
    cryptoContext->Decrypt(keyPair.secretKey, ciphertextAdd, &plaintextDecAdd);
    plaintextDecAdd->SetLength(size_vectors);

    // Print time spent on decryption
    TOC(t);
    processingTimes[3] = TOC(t);
 
    std::cout << "Duration of decryption: " << processingTimes[3] << "ms" << std::endl;
    
    TIC(t);

    // Plaintext Operations
    double variance_sum = plaintextDecAdd->GetCoefPackedValue()[total_elements - 1];
    double variance = variance_sum / pow(total_elements, 3); 
   
    // Print time spent on plaintext operations
    TOC(t);
    processingTimes[4] = TOC(t);
 
    std::cout << "Duration of plaintext operations: " << processingTimes[4] << "ms" << std::endl;
    
    // Calculate and print final time and value
    double total_time = std::reduce(processingTimes.begin(), processingTimes.end());

    std::cout << "Total runtime: " << total_time << "ms" << std::endl;
    std::cout << "Variance: " << variance << std::endl;
}

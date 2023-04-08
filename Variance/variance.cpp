#include "openfhe.h"
#include <iostream>
#include <fstream>

using namespace lbcrypto;

double calculateMean(CryptoContext<DCRTPoly> cryptoContext, std::vector<Ciphertext<DCRTPoly>> ciphertexts, int64_t total_elements, int64_t number_rotations){
    auto ciphertextAdd = cryptoContext->EvalAddMany(ciphertexts);

    auto ciphertextRot = ciphertextAdd;

    for(int i = 0; i < number_rotations; i++){
        ciphertextRot = cryptoContext->EvalRotate(ciphertextAdd, pow(2, i));

        ciphertextAdd = cryptoContext->EvalAdd(ciphertextAdd, ciphertextRot);
    }

    Plaintext meanPlaintext;
    cryptoContext->Decrypt(keyPair.secretKey, ciphertextAdd, &meanPlaintext);

    return (meanPlaintext->GetPackedValue()[0] + meanPlaintext->GetPackedValue()[size_vectors/2]) / total_elements;
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
    std::vector<int64_t> all_numbers;

    numbers_file >> number_vectors;
    numbers_file >> size_vectors;

    int64_t total_elements = size_vectors * number_vectors;

    // Body of the file contains all the numbers
    while (numbers_file >> number) {
        all_numbers.push_back(number);
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
    
    // Generate the rotation evaluation keys
    std::vector<int32_t> rotation_indexes;
    for(int i = 0; i < number_rotations; i++){
       rotation_indexes.push_back(pow(2,i)); // Rotate always in 2^i
    }

    cryptoContext->EvalRotateKeyGen(keyPair.secretKey, rotation_indexes);    
    
    // Print time spent on setup
    TOC(t);
    processingTimes[0] = TOC(t);
    
    std::cout << "Duration of setup: " << processingTimes[0] << "ms" << std::endl;

    TIC(t);

    // Create Plaintexts
    std::vector<Ciphertext<DCRTPoly>> ciphertexts;
    
    int begin, end;
    
    for(int i = 0; i < number_vectors; i++){
        // Calculate beginning and end of plaintext values
        begin = i * size_vectors;
        end = size_vectors * (i + 1);

        // Encode Plaintext with slot packing and encrypt it into a ciphertext vector
        Plaintext plaintext = cryptoContext->MakePackedPlaintext(std::vector<int64_t>(all_numbers.begin() + begin, all_numbers.begin() + end));
        ciphertexts.push_back(cryptoContext->Encrypt(keyPair.publicKey, plaintext));
    }
    
    // Print time spent on encryption
    TOC(t);
    processingTimes[1] = TOC(t);
 
    std::cout << "Duration of encryption: " << processingTimes[1] << "ms" << std::endl;
    
    TIC(t);
	    
    // Homomorphic Operations 

    // Calculate the Mean
    double negMean = calculateMean(cryptoContext, ciphertexts, total_elements, number_rotations) * -1;
    
    // Calculate  (xi - mean)^2
    std::vector<Ciphertext<DCRTPoly>> subCiphertexts;

    for(int i = 0; i < ciphertexts.size(); i++){
        auto ciphertextSub = cryptoContext->EvalAdd(ciphertexts[i], negMean);

        subCiphertexts.push_back(cryptoContext->EvalMult(ciphertextSub, ciphertextSub));
    }

    // Calculate sum((xi - mean)^2)
    auto ciphertextAdd = cryptoContext->EvalAddMany(ciphertexts);

    auto ciphertextRot = ciphertextAdd;

    for(int i = 0; i < number_rotations; i++){
        ciphertextRot = cryptoContext->EvalRotate(ciphertextAdd, pow(2, i));

        ciphertextAdd = cryptoContext->EvalAdd(ciphertextAdd, ciphertextRot);
    }
    
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
    double variance_sum = plaintextDecAdd->GetPackedValue()[0] + plaintextDecAdd->GetPackedValue()[size_vectors/2];
    double variance = variance_sum / total_elements; 
   
    // Print time spent on plaintext operations
    TOC(t);
    processingTimes[4] = TOC(t);
 
    std::cout << "Duration of plaintext operations: " << processingTimes[4] << "ms" << std::endl;
    
    // Calculate and print final time and value
    double total_time = std::reduce(processingTimes.begin(), processingTimes.end());

    std::cout << "Total runtime: " << total_time << "ms" << std::endl;
    std::cout << "Variance: " << variance << std::endl;
}

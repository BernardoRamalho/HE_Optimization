#include "openfhe.h"
#include <iostream>
#include <fstream>

using namespace lbcrypto;

std::vector<int64_t> pre_process_numbers(std::vector<int64_t> values, int64_t alpha, int64_t plaintext_modulus){
    std::vector<int64_t> pre_processed_values;
    int64_t alpha_value = 1, pre_processed_value;
    unsigned long long mult_value;

    for(unsigned int i = 0; i < values.size(); i++){
	mult_value = values[i] * alpha_value;

        pre_processed_value = mult_value % plaintext_modulus;

        alpha_value = alpha_value * alpha % plaintext_modulus;

        if(pre_processed_value > (plaintext_modulus - 1 ) /2){
		    pre_processed_value = pre_processed_value - plaintext_modulus;
	    }

        pre_processed_values.push_back(pre_processed_value);
    }

    return pre_processed_values;
}

std::vector<int64_t> post_process_numbers(std::vector<int64_t> pre_processed_values, int64_t inverse_alpha, int64_t plaintext_modulus){
    std::vector<int64_t> post_processed_values;
    unsigned long long inverse_alpha_value = 1;
    uint64_t post_processed_value;
    unsigned long long mult_value;

    for(unsigned int i = 0; i < pre_processed_values.size(); i++){

        if(pre_processed_values[i] < 0){
            pre_processed_values[i] += plaintext_modulus;
        }

        mult_value = pre_processed_values[i] * inverse_alpha_value;

        post_processed_value = mult_value % plaintext_modulus;

        inverse_alpha_value = inverse_alpha_value * inverse_alpha % plaintext_modulus;

        post_processed_values.push_back(post_processed_value);
    }

    return post_processed_values;
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
    /// BIG MODULUS = 7000000462849
    // Header of file contains information about nr of vector and the size of each of them
    int64_t number_vectors, size_vectors, number;
    std::vector<int64_t> numbers;

    numbers_file >> number_vectors;
    numbers_file >> size_vectors;

    int64_t total_elements = size_vectors * number_vectors;

    // Body of the file contains all the numbers
    while (numbers_file >> number) {
        numbers.push_back(number);
    }

    // Auxiliary Variables for the Pre Processing 
    int64_t plaintext_modulus = 4295049217;
    int64_t alpha = 626534755, inverse_alpha = 2398041854;
	
    std::vector<int64_t> pre_processed_numbers;
    pre_processed_numbers = pre_process_numbers(numbers, alpha, plaintext_modulus);
    
    std::vector<int64_t> all_ones(8192, 1);
    std::vector<int64_t> pre_processed_all_ones = pre_process_numbers(all_ones, alpha, plaintext_modulus);


    TimeVar t;
    std::vector<double> processingTimes = {0.0, 0.0, 0.0, 0.0, 0.0};

    TIC(t);

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
        std::vector<int64_t> numbers(numbers.begin() + begin, numbers.begin() + end);
        std::vector<int64_t> inverted_numbers = numbers;
        reverse(inverted_numbers.begin(), inverted_numbers.end());

        // Encode Plaintext with slot packing and encrypt it into a ciphertext vector
        Plaintext plaintext = cryptoContext->MakeCoefPackedPlaintext(numbers);
        ciphertexts.push_back(cryptoContext->Encrypt(keyPair.publicKey, plaintext));
       
       	Plaintext inverted_plaintext = cryptoContext->MakeCoefPackedPlaintext(inverted_numbers);
        inverted_ciphertexts.push_back(cryptoContext->Encrypt(keyPair.publicKey, inverted_plaintext));

    }

    Plaintext all_ones_plaintext = cryptoContext->MakeCoefPackedPlaintext(pre_processed_all_ones);
    
    // Print time spent on encryption
    TOC(t);
    processingTimes[1] = TOC(t);
 
    std::cout << "Duration of encryption: " << processingTimes[1] << "ms" << std::endl;
    
    TIC(t);
	    
    // Homomorphic Operations 

    // Calculate the Sum
    auto ciphertextAdd = cryptoContext->EvalAddMany(ciphertexts)
    auto ciphertextSum = cryptoContext->EvalMult(ciphertextAdd, all_ones_plaintext); 
     
    // Create plaintext with n value in the first index
    Plaintext plaintextTotalElements = cryptoContext->MakeCoefPackedPlaintext([total_elements]);
    std::cout << plaintextTotalElements->GetCoefPackedValue() << std::cout;

    auto ciphertextTest = cryptoContext->EvalMult(ciphertexts[0], plaintextTotalElements);
    cryptoContext->Decrypt(keyPair.secretKey, ciphertextTest, &plaintextTotalElements)
    std::cout << plaintextTotalElements->GetCoefPackedValue() << std::cout;
   
    // Calculate  (xi - mean)^2
    std::vector<Ciphertext<DCRTPoly>> subCiphertexts;

    Plaintext plaintextDec;
 
    for(int i = 0; i < (int)ciphertexts.size(); i++){
        // Calculate n*xi - sum(x)
        auto ciphertextSub = cryptoContext->EvalSub(cryptoContext->EvalMult(ciphertexts[i], plaintextTotalElements), ciphertextSum);
        auto invertedCiphertextSub = cryptoContext->EvalSub(cryptoContext->EvalMult(inverted_ciphertexts[i], plaintextTotalElements),ciphertextSum); 
	
        // Square Everything
        subCiphertexts.push_back(cryptoContext->EvalMult(ciphertextSub, invertedCiphertextSub));
    }

    // Calculate sum((xi - mean)^2)
    auto ciphertextResult = cryptoContext->EvalAddMany(subCiphertexts);

    // Print time spent on homomorphic operations
    TOC(t);
    processingTimes[2] = TOC(t);
 
    std::cout << "Duration of homomorphic operations: " << processingTimes[2] << "ms" << std::endl;
    
    TIC(t);

    // Decryption
    Plaintext plaintextDec;
 
    cryptoContext->Decrypt(keyPair.secretKey, ciphertextResult, &plaintextDec);
    plaintextDec->SetLength(size_vectors);

    // Print time spent on decryption
    TOC(t);
    processingTimes[3] = TOC(t);
 
    std::cout << "Duration of decryption: " << processingTimes[3] << "ms" << std::endl;
    
    TIC(t);

    // Plaintext Operations
    std::vector<int64_t> post_processed_values = post_process_numbers(plaintextDec->GetCoefPackedValue(), inverse_alpha, plaintext_modulus);
    double variance_sum = post_processed_values[total_elements - 1];
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

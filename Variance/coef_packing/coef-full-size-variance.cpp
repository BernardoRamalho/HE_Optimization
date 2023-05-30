#include "openfhe.h"
#include <iostream>
#include <fstream>

using namespace lbcrypto;

std::vector<int64_t> pre_process_numbers(std::vector<int64_t> values, std::vector<int64_t> alpha_values, int64_t plaintext_modulus){
    std::vector<int64_t> pre_processed_values;
    int64_t pre_processed_value;

    for(unsigned int i = 0; i < values.size(); i++){
        pre_processed_value = values[i] * alpha_values[i] % plaintext_modulus;

        if(pre_processed_value > (plaintext_modulus - 1 ) /2){
		    pre_processed_value = pre_processed_value - plaintext_modulus;
	    }

        pre_processed_values.push_back(pre_processed_value);
    }

    return pre_processed_values;
}

std::vector<int64_t> post_process_numbers(std::vector<int64_t> pre_processed_values, int64_t inverse_alpha, int64_t plaintext_modulus){
    std::vector<int64_t> post_processed_values;
    int64_t inverse_alpha_value = 1, post_processed_value;

    for(unsigned int i = 0; i < pre_processed_values.size(); i++){
        
        if(pre_processed_values[i] < 0){
            pre_processed_values[i] += plaintext_modulus;
        }

        post_processed_value = pre_processed_values[i] * inverse_alpha_value % plaintext_modulus;

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

    // Auxiliary Variables for the Pre Processing 
    int64_t plaintext_modulus = 4295049217;
    int64_t alpha = 626534755, inverse_alpha = 2398041854;
	
    std::vector<int64_t> pre_processed_numbers;
    pre_processed_numbers = pre_process_numbers(all_number_N, alpha, plaintext_modulus);

    std::vector<int64_t> pre_processed_inverted_numbers;
    pre_processed_inverted_numbers = pre_process_numbers(inverted_all_number_N, alpha, plaintext_modulus);
    
    std::vector<int64_t> all_ones(8192, 1);
    std::vector<int64_t> pre_processed_all_ones = pre_process_numbers(all_ones, alpha, plaintext_modulus);
    Plaintext all_ones_plaintext = cryptoContext->MakeCoefPackedPlaintext(pre_processed_all_ones);

    std::vector<int64_t> multiply_by(8192, 0);
    multiply_by[0] = total_elements * total_elements;
    std::vector<int64_t> pre_processed_multiply_by = pre_process_numbers(multiply_by, alpha, plaintext_modulus);
    Plaintext multiply_by_plaintext = cryptoContext->MakeCoefPackedPlaintext(pre_processed_multiply_by);


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
        std::vector<int64_t> numbers(pre_processed_numbers.begin() + begin, pre_processed_numbers.begin() + end);
        std::vector<int64_t> inverted_numbers(pre_processed_inverted_numbers.begin() + begin, pre_processed_inverted_numbers.begin() + end);;

        // Encode Plaintext with coef packing and encrypt it into a ciphertext vector
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

    // Calculate the Square Mean
    auto ciphertextSquareSum = cryptoContext->EvalAddMany(ciphertexts);

    ciphertextSquareSum = cryptoContext->EvalMult(ciphertextSquareSum, all_ones_plaintext); // Get Sum in all Indexes
    
    ciphertextSquareSum = cryptoContext->EvalSquare(ciphertextSquareSum); // Get square sum * total_elements in all indexes

    // Calculate the Inner Product
    // Multiplying both vectors together will calculate the Inner Product value on the last index of the plaintext
    Ciphertext<DCRTPoly> ciphertextInnerProduct = cryptoContext->EvalMult(ciphertexts[0], inverted_ciphertexts[0]);

    ciphertextInnerProduct = cryptoContext->EvalMult(ciphertextInnerProduct, multiply_by_plaintext);

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
    plaintextResult->SetLength(20);

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

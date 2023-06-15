#include <NTL/ZZ.h>
#include "openfhe.h"
#include <iostream>
#include <fstream>

using namespace lbcrypto;
using namespace NTL;



std::vector<int64_t> pre_process_numbers(std::vector<int64_t> values, int64_t alpha, int64_t plaintext_modulus){
    std::vector<int64_t> pre_processed_values;

    ZZ mult_value, zz_value, alpha_value = ZZ(1), zz_alpha = ZZ(alpha), zz_modulus = ZZ(plaintext_modulus);
    
    for(unsigned int i = 0; i < values.size(); i++){
        int64_t pre_processed_value;
	
	zz_value = ZZ(values[i]);
	mult_value = zz_value * alpha_value;

        zz_value = mult_value % plaintext_modulus;

        alpha_value = alpha_value * alpha % zz_modulus;
        
	conv(pre_processed_value, zz_value);

        if(pre_processed_value > (plaintext_modulus - 1 ) /2){
		    pre_processed_value = pre_processed_value - plaintext_modulus;
	    }

        pre_processed_values.push_back(pre_processed_value);
    }

    return pre_processed_values;
}

std::vector<int64_t> post_process_numbers(std::vector<int64_t> pre_processed_values, int64_t inverse_alpha, int64_t plaintext_modulus){
    std::vector<int64_t> post_processed_values;

    ZZ mult_value, zz_value, inverse_alpha_value = ZZ(1), zz_inverse_alpha = ZZ(inverse_alpha), zz_modulus = ZZ(plaintext_modulus);

    for(unsigned int i = 0; i < pre_processed_values.size(); i++){

        if(pre_processed_values[i] < 0){
            pre_processed_values[i] += plaintext_modulus;
        }

        zz_value = ZZ(pre_processed_values[i]);

        mult_value = zz_value * inverse_alpha_value;

        zz_value = mult_value % plaintext_modulus;

        inverse_alpha_value = inverse_alpha_value * zz_inverse_alpha % zz_modulus;

        int64_t post_processed_value; 
	conv(post_processed_value, zz_value);

        post_processed_values.push_back(post_processed_value);
    }

    return post_processed_values;
}
void print_packed_values(Ciphertext<DCRTPoly> c, KeyPair<DCRTPoly> keyPair, CryptoContext<DCRTPoly> cryptoContext, int64_t inverse_alpha, int64_t plaintext_modulus){
	Plaintext p;
	cryptoContext->Decrypt(keyPair.secretKey, c, &p);
	std::vector values = post_process_numbers(p->GetCoefPackedValue(), inverse_alpha, plaintext_modulus);
	std::cout << values << std::endl;
}
void printIntoCSV(std::vector<double> processingTimes, double total_time, double mean){
    // Open the file
    std::string filePath;

    std::ofstream meanCSV("timeCSVs/variance.csv", std::ios_base::app);
    
    meanCSV << "wu-haven-coef, ";

    for(unsigned int i = 0; i < processingTimes.size(); i++){
        meanCSV << processingTimes[i] << ", ";
    }
    meanCSV << total_time << ", ";
    
    meanCSV << mean << std::endl;
 
    meanCSV.close();
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
    int64_t total_elements, number;
    std::vector<int64_t> all_numbers;

    numbers_file >> total_elements;

    // Body of the file contains all the numbers
    while (numbers_file >> number) {
        all_numbers.push_back(number);
    }

    TimeVar t;
    std::vector<double> processingTimes = {0.0, 0.0, 0.0, 0.0, 0.0};

    TIC(t);
    int64_t plaintext_modulus = atol(argv[2]);
    int64_t ringDim = atoi(argv[3]);
    float standardDev = atof(argv[4]);
    
    int64_t number_vectors = total_elements / ringDim;

    // Set CryptoContext
    CCParams<CryptoContextBFVRNS> parameters;
    parameters.SetPlaintextModulus(plaintext_modulus);
    parameters.SetMultiplicativeDepth(2);
    parameters.SetSecurityLevel(HEStd_NotSet); // disable security
    parameters.SetRingDim(ringDim);
    parameters.SetStandardDeviation(standardDev);

    // Key Generation

    // Initialize Public Key Containers
    KeyPair<DCRTPoly> keyPair;

    // Generate a public/private key pair
    keyPair = cryptoContext->KeyGen();

    // Generate the relinearization key
    cryptoContext->EvalMultKeyGen(keyPair.secretKey);
    
    // Pre Process
    int64_t alpha = atol(argv[5]), inverse_alpha = atol(argv[6]);

    std::vector<int64_t> pre_processed_numbers;
    pre_processed_numbers = pre_process_numbers(all_number_N, alpha, plaintext_modulus);

    std::vector<int64_t> pre_processed_inverted_numbers;
    pre_processed_inverted_numbers = pre_process_numbers(inverted_all_number_N, alpha, plaintext_modulus);
    
    std::vector<int64_t> all_ones(8192, 1);
    std::vector<int64_t> pre_processed_all_ones = pre_process_numbers(all_ones, alpha, plaintext_modulus);

    std::vector<int64_t> multiply_by(8192, 0);
    multiply_by[0] = total_elements * total_elements ;
    std::vector<int64_t> pre_processed_multiply_by = pre_process_numbers(multiply_by, alpha, plaintext_modulus);

    // Print time spent on setup
    TOC(t);
    processingTimes[0] = TOC(t);
    
    //std::cout << "Duration of setup: " << processingTimes[0] << "ms" << std::endl;

    TIC(t);

    // Create Plaintexts
    std::vector<Ciphertext<DCRTPoly>> ciphertexts;
    std::vector<Ciphertext<DCRTPoly>> inverted_ciphertexts;

    int begin, end;
    
    for(int i = 0; i < number_vectors; i++){
        // Calculate beginning and end of plaintext values
        begin = i * ringDim;
        end = ringDim * (i + 1);

        // Create vectors
        std::vector<int64_t> numbers(pre_processed_numbers.begin() + begin, pre_processed_numbers.begin() + end);
        std::vector<int64_t> inverted_numbers(pre_processed_inverted_numbers.begin() + begin, pre_processed_inverted_numbers.begin() + end);;

        // Encode Plaintext with coef packing and encrypt it into a ciphertext vector
        Plaintext plaintext = cryptoContext->MakeCoefPackedPlaintext(numbers);
        ciphertexts.push_back(cryptoContext->Encrypt(keyPair.publicKey, plaintext));
       
       	Plaintext inverted_plaintext = cryptoContext->MakeCoefPackedPlaintext(inverted_numbers);
        inverted_ciphertexts.push_back(cryptoContext->Encrypt(keyPair.publicKey, inverted_plaintext));

    }

    Plaintext all_ones_plaintext = cryptoContext->MakeCoefPackedPlaintext(pre_processed_all_ones);
    Plaintext multiply_by_plaintext = cryptoContext->MakeCoefPackedPlaintext(pre_processed_multiply_by);

    // Print time spent on encryption
    TOC(t);
    processingTimes[1] = TOC(t);
 
    //std::cout << "Duration of encryption: " << processingTimes[1] << "ms" << std::endl;
    
    TIC(t);
	    
    // Homomorphic Operations 
    Plaintext inter_plaintext;

    // Calculate the Square Mean
    auto ciphertextSquareSum = cryptoContext->EvalAddMany(ciphertexts);

    ciphertextSquareSum = cryptoContext->EvalMult(ciphertextSquareSum, all_ones_plaintext); // Get Sum in all Indexes
  
    ciphertextSquareSum = cryptoContext->EvalSquare(ciphertextSquareSum); // Get square sum * sum

    // Calculate the Inner Product
    // Multiplying all vectors together will calculate the Inner Product value on the last index of the plaintext
    for(int i = 0; i < ciphertexts.size(); i++){
        ciphertexts[i] = cryptoContext->EvalMult(ciphertexts[i], inverted_ciphertexts[i])
    }

    Ciphertext<DCRTPoly> ciphertextInnerProduct = cryptoContext->EvalAddMany(ciphertexts);

    ciphertextInnerProduct = cryptoContext->EvalMult(ciphertextInnerProduct, multiply_by_plaintext);

// Subtract the mean from the inner product
    auto ciphertextResult = cryptoContext->EvalSub(ciphertextInnerProduct, ciphertextSquareSum);

    // Print time spent on homomorphic operations
    TOC(t);
    processingTimes[2] = TOC(t);
 
    //std::cout << "Duration of homomorphic operations: " << processingTimes[2] << "ms" << std::endl;
    
    TIC(t);

    // Decryption
    Plaintext plaintextResult;
 
    cryptoContext->Decrypt(keyPair.secretKey, ciphertextResult, &plaintextResult);

    // Print time spent on decryption
    TOC(t);
    processingTimes[3] = TOC(t);
 
    //std::cout << "Duration of decryption: " << processingTimes[3] << "ms" << std::endl;
    
    TIC(t);

    // Plaintext Operations
    std::vector<int64_t> results = post_process_numbers(plaintextResult->GetCoefPackedValue(), inverse_alpha, plaintext_modulus);
    double variance = results[ringDim - 1] / pow(total_elements, 3); 

    // Print time spent on plaintext operations
    TOC(t);
    processingTimes[4] = TOC(t);
 
    //std::cout << "Duration of plaintext operations: " << processingTimes[4] << "ms" << std::endl;
    
    // Calculate and print final time and value
    double total_time = std::reduce(processingTimes.begin(), processingTimes.end());

    //std::cout << "Total runtime: " << total_time << "ms" << std::endl;
    //std::cout << "Variance: " << variance << std::endl;

    printIntoCSV(processingTimes, total_time, variance);

}

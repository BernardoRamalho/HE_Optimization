#include "openfhe.h"
#include <iostream>
#include <fstream>

using namespace lbcrypto;

Ciphertext<DCRTPoly> calculateSquareSum(CryptoContext<DCRTPoly> cryptoContext, KeyPair<DCRTPoly> keyPair, std::vector<Ciphertext<DCRTPoly>> ciphertexts, std::vector<Plaintext> rotation_plaintexts,int64_t total_elements, int64_t number_rotations, int64_t size_vectors){
    std::vector<Ciphertext<DCRTPoly>> mult_ciphertexts;

    for(unsigned int i = 0; i < ciphertexts.size(); i++){
        for(unsigned int j = 0; j < ciphertexts.size(); j++){
            mult_ciphertexts.push_back(cryptoContext->EvalMult(ciphertexts[i], ciphertexts[j]));
        }
    }
    auto ciphertextAdd = cryptoContext->EvalAddMany(mult_ciphertexts);
   
    auto ciphertextRot = ciphertextAdd;

    // For each iteration, rotate the vector through multiplication and then add it with the non rotated vector
    for(int i = 0; i < number_rotations ; i++){
   	    ciphertextRot = cryptoContext->EvalMult(ciphertextAdd, rotation_plaintexts[i]);
        ciphertextAdd = cryptoContext->EvalAdd(ciphertextAdd, ciphertextRot);
    }

    return ciphertextAdd;
}

void printIntoCSV(std::vector<double> processingTimes, double total_time, double variance){
    // Open the file
    std::string filePath;

    std::ofstream varianceCSV("timeCSVs/variance.csv", std::ios_base::app);
    
    varianceCSV << "half-size-wu-haven-coef, ";

    for(unsigned int i = 0; i < processingTimes.size(); i++){
        varianceCSV << processingTimes[i] << ", ";
    }
    varianceCSV << total_time << ", ";
    
    varianceCSV << variance << std::endl;
 
    varianceCSV.close();
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

    // Due to the optimization we can do log(n) rotations
    double number_rotations = ceil(log2(size_vectors));

    TimeVar t;
    std::vector<double> processingTimes = {0.0, 0.0, 0.0, 0.0, 0.0};

    TIC(t);

    // Set CryptoContext
    CCParams<CryptoContextBFVRNS> parameters;
    parameters.SetPlaintextModulus(7000000462849);
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
    
    //std::cout << "Duration of setup: " << processingTimes[0] << "ms" << std::endl;

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

        // Encode Plaintext with slot packing and encrypt it into a ciphertext vector
        Plaintext plaintext = cryptoContext->MakeCoefPackedPlaintext(numbers);
        ciphertexts.push_back(cryptoContext->Encrypt(keyPair.publicKey, plaintext));
       
       	Plaintext inverted_plaintext = cryptoContext->MakeCoefPackedPlaintext(inverted_numbers);
        inverted_ciphertexts.push_back(cryptoContext->Encrypt(keyPair.publicKey, inverted_plaintext));

    }

    // Plaintexts to calculate the square mean with one multiplication
    std::vector<Ciphertext<DCRTPoly>> half_ciphertexts;
    int64_t half_size = size_vectors / 2;

    for(int i = 0; i < number_vectors * 2; i++){
        // Calculate beginning and end of plaintext values
        begin = i * half_size;
        end = half_size * (i + 1);

        // Create vectors
        std::vector<int64_t> numbers(all_number_N.begin() + begin, all_number_N.begin() + end);

        // Encode Plaintext with slot packing and encrypt it into a ciphertext vector
        Plaintext plaintext = cryptoContext->MakeCoefPackedPlaintext(numbers);
        half_ciphertexts.push_back(cryptoContext->Encrypt(keyPair.publicKey, plaintext));
    }
    
    // Print time spent on encryption
    TOC(t);
    processingTimes[1] = TOC(t);
 
    //std::cout << "Duration of encryption: " << processingTimes[1] << "ms" << std::endl;
    
    TIC(t);
	    
    // Homomorphic Operations 

    // Calculate the Square Mean
    auto negSquareSum = calculateSquareSum(cryptoContext, keyPair, half_ciphertexts, rotation_plaintexts,total_elements, number_rotations, size_vectors);
    
    // Calculate the Inner Product
    // Multiplying both vectors together will calculate the Inner Product value on the last index of the plaintext
    Ciphertext<DCRTPoly> ciphertextInnerProduct = cryptoContext->EvalMult(ciphertexts[0], inverted_ciphertexts[0]);
     
    ciphertextInnerProduct = cryptoContext->EvalMult(ciphertextInnerProduct,cryptoContext->MakeCoefPackedPlaintext({total_elements}));

    // Subtract the mean from the inner product
    auto ciphertextResult = cryptoContext->EvalSub(ciphertextInnerProduct, negSquareSum);

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
    double variance = plaintextResult->GetCoefPackedValue()[size_vectors - 1] / pow(total_elements, 2); 

    // Print time spent on plaintext operations
    TOC(t);
    processingTimes[4] = TOC(t);
 
    //std::cout << "Duration of plaintext operations: " << processingTimes[4] << "ms" << std::endl;
    
    // Calculate and print final time and value
    double total_time = std::reduce(processingTimes.begin(), processingTimes.end());

   // std::cout << "Total runtime: " << total_time << "ms" << std::endl;
    //std::cout << "Variance: " << variance << std::endl;

    printIntoCSV(processingTimes, total_time, variance);
}

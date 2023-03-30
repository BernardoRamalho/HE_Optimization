#include "openfhe.h"
#include <iostream>
#include <fstream>

using namespace lbcrypto;
/*
 * argv[1] --> number's file name
*/
int main(int argc, char *argv[]) {

    std::ifstream numbers_file (argv[1]);

     if (!numbers_file.is_open()) {
        std::cerr << "Could not open the file - '"
             << argv[1] << "'" << std::endl;
        return EXIT_FAILURE;
    }

    int64_t number_vectors, size_vectors, number;
    std::vector<int64_t> all_numbers;

    numbers_file >> number_vectors;
    numbers_file >> size_vectors;

    int64_t total_elements = size_vectors * number_vectors;

    while (numbers_file >> number) {
        all_numbers.push_back(number);
    }
   
    double number_rotations = ceil(log2(size_vectors)) - 1;
   // size_vectors = (int)pow(2, number_rotations);
   // number_vectors = ceil((float)all_numbers.size() / size_vectors);

    TimeVar t;
    std::vector<double> processingTimes = {0.0, 0.0, 0.0, 0.0, 0.0};

    TIC(t);

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

    // Sample Program: Step 2: Key Generation

    // Initialize Public Key Containers
    KeyPair<DCRTPoly> keyPair;

    // Generate a public/private key pair
    keyPair = cryptoContext->KeyGen();

    // Generate the relinearization key
    cryptoContext->EvalMultKeyGen(keyPair.secretKey);
    
    // Generate the rotation evaluation keys
    std::vector<int32_t> rotation_indexes;
    for(int i = 0; i < number_rotations; i++){
       rotation_indexes.push_back(pow(2,i)); 
    }

    cryptoContext->EvalRotateKeyGen(keyPair.secretKey, rotation_indexes);    
    
    TOC(t);
    processingTimes[0] = TOC(t);
    
    std::cout << "Duration of setup: " << processingTimes[0] << "ms" << std::endl;

    TIC(t);

    // Create Plaintexts
    std::vector<Ciphertext<DCRTPoly>> ciphertexts;
    
    int begin, end;
    
    for(int i = 0; i < number_vectors; i++){
        begin = i * size_vectors;
        end = size_vectors * (i + 1);

        Plaintext plaintext = cryptoContext->MakePackedPlaintext(std::vector<int64_t>(all_numbers.begin() + begin, all_numbers.begin() + end));
        ciphertexts.push_back(cryptoContext->Encrypt(keyPair.publicKey, plaintext));
    }

    TOC(t);
    processingTimes[1] = TOC(t);
 
    std::cout << "Duration of encryption: " << processingTimes[1] << "ms" << std::endl;
    
    TIC(t);
	    
    // Homomorphic Operations 
    auto ciphertextAdd = cryptoContext->EvalAddMany(ciphertexts);

    auto ciphertextRot = ciphertextAdd;

    for(int i = 0; i < number_rotations; i++){
        ciphertextRot = cryptoContext->EvalRotate(ciphertextAdd, pow(2, i));

        ciphertextAdd = cryptoContext->EvalAdd(ciphertextAdd, ciphertextRot);
    }

    TOC(t);
    processingTimes[2] = TOC(t);
 
    std::cout << "Duration of homomorphic operations: " << processingTimes[2] << "ms" << std::endl;
    
    TIC(t);

    // Decryption
    Plaintext plaintextDecAdd;
 
    cryptoContext->Decrypt(keyPair.secretKey, ciphertextAdd, &plaintextDecAdd);
    plaintextDecAdd->SetLength(size_vectors);

    TOC(t);
    processingTimes[3] = TOC(t);
 
    std::cout << "Duration of decryption: " << processingTimes[3] << "ms" << std::endl;
    
    TIC(t);

    // Plaintext Operations
    double mean_sum = plaintextDecAdd->GetPackedValue()[0] + plaintextDecAdd->GetPackedValue()[size_vectors/2];
    double mean = mean_sum / total_elements; 
    
    TOC(t);
    processingTimes[4] = TOC(t);
 
    std::cout << "Duration of plaintext operations: " << processingTimes[4] << "ms" << std::endl;
    
    double total_time = std::reduce(processingTimes.begin(), processingTimes.end());

    std::cout << "Total runtime: " << total_time << "ms" << std::endl;
    std::cout << "Mean: " << mean << std::endl;
}

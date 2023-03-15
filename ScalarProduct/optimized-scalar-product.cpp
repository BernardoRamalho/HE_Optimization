#include "openfhe.h"
#include <iostream>
#include <fstream>
#include <cmath>

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

    int64_t number, nr_elements;

    std::vector<std::vector<int64_t>> vectors;
    
    std::string vector_line;

    while(std::getline(numbers_file, vector_line)){
	std::istringstream line(vector_line);
       
	std::vector<int64_t> v;
	while (line >> number) {
        	v.push_back(number);
   	 }
	vectors.push_back(v);
    }
    
    double closest_exponent = ceil(log2(vectors[0].size()));
    nr_elements = (int)pow(2, closest_exponent);
    int64_t vector_size = vectors[0].size();
    std::cout << "Size: " << vector_size << "; Closest: " << closest_exponent << "; Total Element: " << nr_elements << std::endl;
    if(nr_elements != vector_size){
      std::vector<int64_t> zeros(nr_elements - vector_size);
      vectors[0].insert(vectors[0].end(), zeros.begin(), zeros.end());
      vectors[1].insert(vectors[1].end(), zeros.begin(), zeros.end()); 
      vector_size = nr_elements;
    }

    std::cout << "Vectors: " << vectors[0] << std::endl << vectors[1] << std::endl;

    TimeVar t;
    std::vector<double> processingTimes = {0.0, 0.0, 0.0, 0.0};

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
    cryptoContext->EvalRotateKeyGen(keyPair.secretKey, {1, 2, -1, -2});    
    
    TOC(t);
    processingTimes[0] = TOC(t);
    
    std::cout << "Duration of setup: " << processingTimes[0] << "ms" << std::endl;

    TIC(t);

    // Create Plaintexts
    std::vector<Ciphertext<DCRTPoly>> ciphertexts;
    
    for(int i = 0; i < 2; i++){
                Plaintext plaintext = cryptoContext->MakePackedPlaintext(vectors[i]);
		plaintext->SetLength(vector_size);
		std::cout << "Plaintext: " << plaintext << " with size " << plaintext->GetLength() << "and values " << plaintext->GetPackedValue() << std::endl;
        ciphertexts.push_back(cryptoContext->Encrypt(keyPair.publicKey, plaintext));
    }

    TOC(t);
    processingTimes[1] = TOC(t);
 
    std::cout << "Duration of encryption: " << processingTimes[1] << "ms" << std::endl;
    
    TIC(t);
	    
    // Homomorphic Operations 
    auto ciphertextResult = cryptoContext->EvalMult(ciphertexts[0], ciphertexts[1]);
    auto ciphertextRot = ciphertextResult;
    Plaintext plaintextDec;
 
    cryptoContext->Decrypt(keyPair.secretKey, ciphertextResult, &plaintextDec);
    plaintextDec->SetLength(vector_size);
    std::cout << "Plaintext: " << plaintextDec << std::endl;
       
    for(int i = 0; i < closest_exponent; i++){
        	std::cout << "Rotation: " << pow(2, i) << std::endl;
     
        ciphertextRot = cryptoContext->EvalRotate(ciphertextResult, pow(2, i));
          
   		 cryptoContext->Decrypt(keyPair.secretKey, ciphertextRot, &plaintextDec);
   		 plaintextDec->SetLength(vector_size);
   		 std::cout << "Rot Plaintext: " << plaintextDec << " with size " << plaintextDec->GetLength() << "and values " << plaintextDec->GetPackedValue() << std::endl;
      
        ciphertextResult = cryptoContext->EvalAdd(ciphertextResult, ciphertextRot);

		cryptoContext->Decrypt(keyPair.secretKey, ciphertextResult, &plaintextDec);
    		plaintextDec->SetLength(vector_size);
    		std::cout << "Add Plaintext: " << plaintextDec << " with size " << plaintextDec->GetLength() << "and values " << plaintextDec->GetPackedValue() << std::endl;
     
    }
    TOC(t);
    processingTimes[2] = TOC(t);
 
    std::cout << "Duration of homomorphic operations: " << processingTimes[2] << "ms" << std::endl;
    
    TIC(t);

    // Decryption
    Plaintext plaintextDecAdd;
 
    cryptoContext->Decrypt(keyPair.secretKey, ciphertextResult, &plaintextDecAdd);
    plaintextDecAdd->SetLength(vector_size);
    std::cout << "Plaintext: " << plaintextDecAdd << std::endl;
    TOC(t);
    processingTimes[3] = TOC(t);
 
    std::cout << "Duration of decryption: " << processingTimes[3] << "ms" << std::endl;

    // Plaintext Operations
    int64_t scalar_product = plaintextDecAdd->GetPackedValue()[0];

    double total_time = std::reduce(processingTimes.begin(), processingTimes.end());

    std::cout << "Total runtime: " << total_time << "ms" << std::endl;
    std::cout << "Scalar Product: " << scalar_product << std::endl;

    return 0;
}

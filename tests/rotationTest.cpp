/**
 * @file rotationTest.cpp
 * @author Bernardo Ramalho
 * @brief test how rotation work with slot packing (they rotate in 2 batchs)
 * @version 0.1
 * @date 2023-04-05
 * 
 * @copyright Copyright (c) 2023
 * 
 */

#include "openfhe.h"
#include <iostream>
#include <fstream>

using namespace lbcrypto;
/*
 * argv[1] --> number's file name
*/
int main() {

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

  std::cout << "n = " << cryptoContext->GetCryptoParameters()->GetElementParams()->GetCyclotomicOrder()/2 << std::endl;
  std::cout << "log2 q = " << log2(cryptoContext->GetCryptoParameters()->GetElementParams()->GetModulus().ConvertToDouble()) << std::endl;

  // Key Generation

  // Initialize Public Key Containers
  KeyPair<DCRTPoly> keyPair;

  // Generate a public/private key pair
  keyPair = cryptoContext->KeyGen();

  // Generate the rotation evaluation keys
  cryptoContext->EvalRotateKeyGen(keyPair.secretKey, {2, 30, 2192, 4096, 4097, 6000, 8191, 8192});    

  // Generate the relinearization key
  cryptoContext->EvalMultKeyGen(keyPair.secretKey);
  
  // Create Ciphertext that has size 8192
  std::vector<Ciphertext<DCRTPoly>> ciphertexts;
  
  // Fill a vector with values from 0 -> 8192 (not inclusive)
  std::vector<int64_t> v;
  for(int i = 0; i < 8192; i++){
      v.push_back(i);
  }

  // Pack the vector into a plaintext using slot packing
  std::cout << "Encrypting vector v of size: " << v.size() << std::endl;
  Plaintext plaintextV = cryptoContext->MakePackedPlaintext(v);
  
  // Encrypt it
  ciphertexts.push_back(cryptoContext->Encrypt(keyPair.publicKey, plaintextV));
  
  // ROTATIONS
  Plaintext plaintextDecAdd;
  
  //              //
  // ROTATE by 2  //
  //              //
  auto rotCipher = cryptoContext->EvalRotate(ciphertexts[0], 2);

  // Open the file
  std::ofstream out2("slotRotResults/rot2.txt");
  std::cout.rdbuf(out2.rdbuf()); 
  
  // Decrypt and save it
  cryptoContext->Decrypt(keyPair.secretKey, rotCipher, &plaintextDecAdd);
  std::cout << plaintextDecAdd->GetPackedValue() << std::endl;

   //              //
  // ROTATE by 30  //
  //              //
 rotCipher = cryptoContext->EvalRotate(ciphertexts[0],30);

  // Open the file
  std::ofstream out30("slotRotResults/rot30.txt");
  std::cout.rdbuf(out30.rdbuf()); 
  
  // Decrypt and save it
  cryptoContext->Decrypt(keyPair.secretKey, rotCipher, &plaintextDecAdd);
  std::cout << plaintextDecAdd->GetPackedValue() << std::endl;
 
    //              //
  // ROTATE by 2192  //
  //              //
 rotCipher = cryptoContext->EvalRotate(ciphertexts[0], 2192);

  // Open the file
  std::ofstream out2192("slotRotResults/rot2192.txt");
  std::cout.rdbuf(out2192.rdbuf()); 
  
  // Decrypt and save it
  cryptoContext->Decrypt(keyPair.secretKey, rotCipher, &plaintextDecAdd);
  std::cout << plaintextDecAdd->GetPackedValue() << std::endl;
 
  //                //
  // ROTATE by 4096 //
  //                //
  rotCipher = cryptoContext->EvalRotate(ciphertexts[0], 4096);

  // Open the file
  std::ofstream out4096("slotRotResults/rot4096.txt");
  std::cout.rdbuf(out4096.rdbuf());

  // Decrypt and save it
  cryptoContext->Decrypt(keyPair.secretKey, rotCipher, &plaintextDecAdd);
  std::cout << plaintextDecAdd->GetPackedValue() << std::endl;
  
 //                //
  // ROTATE by 6000 //
  //                //
  rotCipher = cryptoContext->EvalRotate(ciphertexts[0], 6000);

  // Open the file
  std::ofstream out6000("slotRotResults/rot6000.txt");
  std::cout.rdbuf(out6000.rdbuf());

  // Decrypt and save it
  cryptoContext->Decrypt(keyPair.secretKey, rotCipher, &plaintextDecAdd);
  std::cout << plaintextDecAdd->GetPackedValue() << std::endl;
    
  //                //
  // ROTATE by 8191 //
  //                //
  rotCipher = cryptoContext->EvalRotate(ciphertexts[0], 8191);

  // Open the file
  std::ofstream out8191("slotRotResults/rot8191.txt");
  std::cout.rdbuf(out8191.rdbuf());

  // Decrypt and save it
  cryptoContext->Decrypt(keyPair.secretKey, rotCipher, &plaintextDecAdd);
  std::cout << plaintextDecAdd->GetPackedValue() << std::endl;
  
  //                //
  // ROTATE by 8192 //
  //                //
  rotCipher = cryptoContext->EvalRotate(ciphertexts[0], 8192);

  // Open the file
  std::ofstream out8192("slotRotResults/rot8192.txt");
  std::cout.rdbuf(out8192.rdbuf());

  // Decrypt and save it
  cryptoContext->Decrypt(keyPair.secretKey, rotCipher, &plaintextDecAdd);
  std::cout << plaintextDecAdd->GetPackedValue() << std::endl;

  return 0;
}

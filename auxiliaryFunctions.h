#include "openfhe.h"

std::vector<int64_t> pre_process_numbers(std::vector<int64_t> values, int64_t alpha, int64_t plaintext_modulus);

std::vector<int64_t> post_process_numbers(std::vector<int64_t> pre_processed_values, int64_t alpha, int64_t plaintext_modulus);

std::vector<Plaintext> generate_rotation_plaintexts(int64_t number_rotations);
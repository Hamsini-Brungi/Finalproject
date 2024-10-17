#include <iostream>
#include <iomanip>
#include <sstream>
#include <fstream>
#include <string>
#include <cstring>
#include <cstdint>
#include <algorithm> 

class SecureHash256 {
private:
    using HashWord = uint32_t;
    
    // Initial hash values
    const HashWord initialStates[8] = {
        0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
        0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u
    };

    // Round constants
    const HashWord roundConstants[64] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };

    // Core operations
    #define CHOOSE(x,y,z) ((x & y) ^ (~x & z))
    #define MAJORITY(x,y,z) ((x & y) ^ (x & z) ^ (y & z))
    #define ROTATE_RIGHT(x, n) ((x >> n) | (x << ((sizeof(x) << 3) - n)))
    #define SIGMA0(x) ((ROTATE_RIGHT(x, 2)) ^ (ROTATE_RIGHT(x, 13)) ^ (ROTATE_RIGHT(x, 22)))
    #define SIGMA1(x) ((ROTATE_RIGHT(x, 6)) ^ (ROTATE_RIGHT(x, 11)) ^ (ROTATE_RIGHT(x, 25)))
    #define LOWERCASE_SIGMA0(x) (ROTATE_RIGHT(x, 7) ^ ROTATE_RIGHT(x, 18) ^ (x >> 3))
    #define LOWERCASE_SIGMA1(x) (ROTATE_RIGHT(x, 17) ^ ROTATE_RIGHT(x, 19) ^ (x >> 10))

    // Constants
    static const size_t BLOCK_SEQUENCE_LEN = 16;
    static const size_t HASH_ARRAY_LEN = 8;
    static const size_t SCHEDULE_ARRAY_LEN = 64;
    static const size_t BLOCK_SIZE = 512;
    static const size_t BYTE_LENGTH = 8;
    static const size_t WORD_SIZE = 4;

    HashWord** prepareMessage(const unsigned char* input, size_t& blockCount) {
        size_t messageLength = strlen(reinterpret_cast<const char*>(input));
        size_t bitLength = messageLength * BYTE_LENGTH;
        size_t paddingBits = (448 - 1 - bitLength) % BLOCK_SIZE;
        blockCount = (bitLength + 1 + paddingBits + 64) / BLOCK_SIZE;

        HashWord** blocks = new HashWord*[blockCount];
        for(size_t i = 0; i < blockCount; i++) {
            blocks[i] = new HashWord[BLOCK_SEQUENCE_LEN];
        }

        HashWord currentWord;
        size_t index;
        for(size_t i = 0; i < blockCount; i++) {
            for(size_t j = 0; j < BLOCK_SEQUENCE_LEN; j++) {
                currentWord = 0x00u;
                for(size_t k = 0; k < WORD_SIZE; k++) {
                    index = i * 64 + j * 4 + k;
                    if(index < messageLength) {
                        currentWord = currentWord << 8 | static_cast<HashWord>(input[index]);
                    } else if(index == messageLength) {
                        currentWord = currentWord << 8 | static_cast<HashWord>(0x80u);
                    } else {
                        currentWord = currentWord << 8 | static_cast<HashWord>(0x00u);
                    }
                }
                blocks[i][j] = currentWord;
            }
        }

        appendLength(bitLength, blocks[blockCount-1][BLOCK_SEQUENCE_LEN-1], 
                    blocks[blockCount-1][BLOCK_SEQUENCE_LEN-2]);
        return blocks;
    }

    void appendLength(size_t messageLength, HashWord& lowBits, HashWord& highBits) {
        lowBits = messageLength;
        highBits = 0x00;
    }

    void processBlocks(HashWord** messageBlocks, size_t blockCount, HashWord* hashValues) {
        HashWord workingVars[HASH_ARRAY_LEN];
        HashWord schedule[SCHEDULE_ARRAY_LEN];

        std::memcpy(hashValues, initialStates, HASH_ARRAY_LEN * sizeof(HashWord));

        for(size_t i = 0; i < blockCount; i++) {
            std::memcpy(schedule, messageBlocks[i], BLOCK_SEQUENCE_LEN * sizeof(HashWord));

            // Extend the schedule
            for(size_t j = 16; j < SCHEDULE_ARRAY_LEN; j++) {
                schedule[j] = schedule[j-16] + LOWERCASE_SIGMA0(schedule[j-15]) + 
                            schedule[j-7] + LOWERCASE_SIGMA1(schedule[j-2]);
            }

            // Initialize working variables
            std::memcpy(workingVars, hashValues, HASH_ARRAY_LEN * sizeof(HashWord));

            // Main compression loop
            for(size_t j = 0; j < SCHEDULE_ARRAY_LEN; j++) {
                HashWord temp1 = workingVars[7] + SIGMA1(workingVars[4]) + 
                               CHOOSE(workingVars[4], workingVars[5], workingVars[6]) + 
                               roundConstants[j] + schedule[j];
                HashWord temp2 = SIGMA0(workingVars[0]) + 
                               MAJORITY(workingVars[0], workingVars[1], workingVars[2]);

                workingVars[7] = workingVars[6];
                workingVars[6] = workingVars[5];
                workingVars[5] = workingVars[4];
                workingVars[4] = workingVars[3] + temp1;
                workingVars[3] = workingVars[2];
                workingVars[2] = workingVars[1];
                workingVars[1] = workingVars[0];
                workingVars[0] = temp1 + temp2;
            }

            // Update hash values
            for(size_t j = 0; j < HASH_ARRAY_LEN; j++) {
                hashValues[j] += workingVars[j];
            }
        }
    }

    std::string generateDigest(HashWord* hashValues) {
        std::stringstream ss;
        for(size_t i = 0; i < HASH_ARRAY_LEN; i++) {
            ss << std::hex << std::setw(8) << std::setfill('0') << hashValues[i];
        }
        delete[] hashValues;
        return ss.str();
    }

    void cleanup(HashWord** blocks, size_t blockCount) {
        for(size_t i = 0; i < blockCount; i++) {
            delete[] blocks[i];
        }
        delete[] blocks;
    }

public:
    std::string calculateHash(const unsigned char* input) {
        size_t blockCount;
        HashWord** blocks = prepareMessage(input, blockCount);
        HashWord* hashValues = new HashWord[HASH_ARRAY_LEN];
        processBlocks(blocks, blockCount, hashValues);
        std::string hashResult = generateDigest(hashValues);
        cleanup(blocks, blockCount);
        return hashResult;
    }
};

int main() {
    SecureHash256 hasher;
    int option;
    do {
        std::cout << "Choose an option:\n1. Hash a string\n2. Hash a file\n3. Exit\n";
        std::cin >> option;
        
        switch (option) {
        case 1: {
            std::cout << "Enter string to hash: ";
            std::cin.ignore(); // Clear newline character from input buffer
            std::string input;
            std::getline(std::cin, input);
            std::cout << "Hash: " << hasher.calculateHash(reinterpret_cast<const unsigned char*>(input.c_str())) << std::endl;
            break;
        }
        case 2: {
    std::cout << "Enter file path: ";
    std::string filePath;
    std::cin >> filePath;

    std::ifstream file(filePath);
    if (file.is_open()) {
        std::stringstream buffer;
        buffer << file.rdbuf();
        std::string content = buffer.str();
        
        // Normalize line endings to match console input
        std::string normalized;
        for (size_t i = 0; i < content.length(); ++i) {
            // Skip \r characters (from Windows-style \r\n)
            if (content[i] == '\r') continue;
            normalized += content[i];
        }
        
        // Remove trailing newline if present
        if (!normalized.empty() && normalized.back() == '\n') {
            normalized.pop_back();
        }

        std::cout << "Hash: " << hasher.calculateHash(reinterpret_cast<const unsigned char*>(normalized.c_str())) << std::endl;
        file.close();
    } else {
        std::cout << "Error: Cannot open file " << filePath << std::endl;
    }
    break;
}

        case 3:
            std::cout << "Exiting..." << std::endl;
            break;
        default:
            std::cout << "Invalid option. Please try again." << std::endl;
            break;
        }
    } while (option != 3);

    return 0;
}


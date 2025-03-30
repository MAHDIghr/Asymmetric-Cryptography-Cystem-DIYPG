#include "../../include/phase1.h"


/*===========================================================================================
                Phase 1.0 :                
                               Display of Keys 
===========================================================================================*/
/* 
   This phase focuses on implementing functionality to display cryptographic keys in a human-readable format. 
   The primary objective is to write functions that take key data and output it in a clear and understandable 
   manner.
*/

//...


/*===========================================================================================
                Phase 1.1 :                
                               Encrypting Char by Char
===========================================================================================*/
/* 
   Phase 1.1 involves the implementation of encryption and decryption at the character level. 
   This method encrypts and decrypts each character of a message individually. However, it is recognized that 
   this approach is vulnerable to statistical attacks, making it unsuitable for production cryptography. 
   The functions will be written to process a message (represented as an array of characters or bytes) by 
   encrypting or decrypting each element, with the corresponding output message generated. 
*/

void rsa_encrypt(uint8_t *input, uint64_t length, uint8_t *output, rsaKey_t *pubKey) {
   /// \brief Encrypt le tableau d'octets input de longueur length avec la clé publique pubKey et retourne le tableau encryptée output
   for (uint64_t i = 0; i < length; i++) {
       output[i] = (uint8_t) puissance_mod_n(input[i], pubKey->E, pubKey->N);
   }
}

void rsa_decrypt(uint8_t *input, uint64_t length, uint8_t *output, rsaKey_t *privKey) {
   /// \brief Decrypte le tableau d'octets input de longueur length avec la clé privée privKey et retourne le tableau encryptée output
   for (uint64_t i = 0; i < length; i++) {
       output[i] = (uint8_t) puissance_mod_n(input[i], privKey->E, privKey->N);
   }
}

/*===========================================================================================
                Phase 1.2 :                
                               Encrypting Using Files for Input and Output
===========================================================================================*/
/* 
   In Phase 1.2, the encryption and decryption functionality will be extended to work with files. 
   The goal is to implement functions that read a message from a file, encrypt it using a key, 
   and write the encrypted result back to a file. Similarly, functions will be developed to read an 
   encrypted message from a file, decrypt it using a decryption key, and write the decrypted message 
   to a file. This functionality enables file-based encryption, a common approach for secure data storage 
   and transmission. 
*/

//...

/*===========================================================================================
                Phase 1.3 :                
                               Base64 Conversion Tools
===========================================================================================*/
/* 
   Phase 1.3 introduces the implementation of Base64 encoding and decoding tools. Base64 encoding 
   is a method used to convert binary data into a text format that is easily transferable over systems 
   that support text-based communication, such as email or web services. In this phase, functions will be 
   created to:
   - Convert binary data (such as a byte array) into a Base64-encoded string.
   - Convert a Base64-encoded string back into its original binary form.
   - Implement file-based conversions, where binary data in files is converted to Base64 and vice versa.
*/

void base64_encode(const uint8_t *input, uint64_t length, char *output) {
    int i, j;
    for (i = 0, j = 0; i < length; i += 3) {
        uint32_t octet = (input[i] << 16) | (i + 1 < length ? (input[i + 1] << 8) : 0) | (i + 2 < length ? input[i + 2] : 0);
        output[j++] = base64_table[(octet >> 18) & 0x3F];
        output[j++] = base64_table[(octet >> 12) & 0x3F];
        output[j++] = (i + 1 < length) ? base64_table[(octet >> 6) & 0x3F] : '=';
        output[j++] = (i + 2 < length) ? base64_table[octet & 0x3F] : '=';
    }
    output[j] = '\0';
}

void base64_decode(const char *input, uint8_t *output, uint64_t *out_length) {
    int len = strlen(input);
    int i, j;
    uint32_t buffer = 0;
    int buffer_length = 0;
    *out_length = 0;
    for (i = 0, j = 0; i < len; i++) {
        if (input[i] == '=') break;
        int value = strchr(base64_table, input[i]) - base64_table;
        buffer = (buffer << 6) | value;
        buffer_length += 6;
        if (buffer_length >= 8) {
            output[j++] = (buffer >> (buffer_length - 8)) & 0xFF;
            buffer_length -= 8;
        }
    }
    *out_length = j;
}

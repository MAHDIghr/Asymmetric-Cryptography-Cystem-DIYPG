#include "../../include/phase1.h"
#include "../../include/rsa_common_header.h"
#include "../../include/rsa_tools.h"
#include "../../include/other_base64.h"
#include <stdint.h>


/*===========================================================================================
                Phase 1.0 :                
                               Display of Keys 
===========================================================================================*/
/* 
   This phase focuses on implementing functionality to display cryptographic keys in a human-readable format. 
   The primary objective is to write functions that take key data and output it in a clear and understandable 
   manner.
*/



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
   /// \brief Decrypte le tableau d'octets input de longueur length avec la clé privée privKey et retourne le tableau décrypté output
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

char *convert_binary_to_base64(const unsigned char *data, size_t input_length) {
   /// \brief Convert binaire en base64
    size_t output_length;
    char *encoded_data = base64_encode(data, input_length, &output_length);
    return encoded_data;
}

unsigned char *convert_base64_to_binary(const char *base64_string, size_t *output_length) {
   /// \brief Converti  base64 string en binaire
   return base64_decode(base64_string, strlen(base64_string), output_length);
}
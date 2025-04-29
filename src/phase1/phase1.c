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
void print_rsa_key(const rsaKey_t *key, const char *type) {
    if (strcmp(type, "publique") == 0) {
        printf("Clé publique : (e=%" PRIu64 ", n=%" PRIu64 ")\n", key->E, key->N);
    } else {
        printf("Clé privée : (d=%" PRIu64 ", n=%" PRIu64 ")\n", key->E, key->N);
    }
 }


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

uint64_t encrypt_char(uint64_t input, rsaKey_t *pubKey) {
   // Chiffrement du bloc en 64 bits avec la clé publique
   return puissance_mod_n(input, pubKey->E, pubKey->N);
}

uint64_t decrypt_char(uint64_t input, rsaKey_t *privKey) {
   // Déchiffrement du bloc en 64 bits avec la clé privée
   return puissance_mod_n(input, privKey->E, privKey->N);
}

uint8_t* encrypt_tab(uint8_t* input, int length, rsaKey_t* pubKey) {
   uint8_t* encrypted_tab = malloc(length * sizeof(uint8_t));  // Allocation pour octets chiffrés
   if (encrypted_tab == NULL) {
       return NULL;
   }

   for (int i = 0; i < length; i++) {
       uint64_t encrypted = encrypt_char((uint64_t)input[i], pubKey);  // Chiffrement de chaque octet
       encrypted_tab[i] = (uint8_t)(encrypted & 0xFF);  // Conservez seulement le premier octet du résultat
   }
   return encrypted_tab;
}

uint8_t* decrypt_tab(uint8_t* input, int length, rsaKey_t* privKey) {
   uint8_t* decrypted_tab = malloc(length * sizeof(uint8_t));  // Allocation pour octets déchiffrés
   if (decrypted_tab == NULL) {
       return NULL;
   }

   for (int i = 0; i < length; i++) {
       uint64_t decrypted = decrypt_char((uint64_t)input[i], privKey);  // Déchiffrement de chaque octet
       decrypted_tab[i] = (uint8_t)(decrypted & 0xFF);  // Conservez seulement le premier octet du résultat
   }
   return decrypted_tab;
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

void convert_file_binary_to_base64(const char *input_file, const char *output_file) {
   FILE *f_in = fopen(input_file, "rb");
   if (f_in == NULL) {
       perror("Erreur d'ouverture du fichier d'entrée");
       return;
   }

   // Lire tout le fichier binaire
   fseek(f_in, 0, SEEK_END);
   long input_size = ftell(f_in);
   fseek(f_in, 0, SEEK_SET);

   unsigned char *data = (unsigned char *)malloc(input_size);
   if (data == NULL) {
       perror("Erreur d'allocation mémoire");
       fclose(f_in);
       return;
   }

   fread(data, 1, input_size, f_in);
   fclose(f_in);

   // Convertir en Base64
   size_t output_length;
   char *base64_encoded = convert_binary_to_base64(data, input_size);
   free(data);

   // Écrire dans le fichier de sortie
   FILE *f_out = fopen(output_file, "w");
   if (f_out == NULL) {
       perror("Erreur d'ouverture du fichier de sortie");
       free(base64_encoded);
       return;
   }

   fwrite(base64_encoded, 1, strlen(base64_encoded), f_out);
   fclose(f_out);

   free(base64_encoded);
}

void convert_file_base64_to_binary(const char *input_file, const char *output_file) {
    FILE *f_in = fopen(input_file, "r");
    if (f_in == NULL) {
        perror("Erreur d'ouverture du fichier d'entrée");
        return;
    }

    // Lire le contenu du fichier Base64
    fseek(f_in, 0, SEEK_END);
    long input_size = ftell(f_in);
    fseek(f_in, 0, SEEK_SET);

    char *base64_data = (char *)malloc(input_size + 1);
    if (base64_data == NULL) {
        perror("Erreur d'allocation mémoire");
        fclose(f_in);
        return;
    }

    fread(base64_data, 1, input_size, f_in);
    fclose(f_in);
    base64_data[input_size] = '\0';  // Ajouter le caractère de fin de chaîne

    // Décoder en binaire
    size_t output_length;
    unsigned char *decoded_data = convert_base64_to_binary(base64_data, &output_length);
    free(base64_data);

    // Écrire dans le fichier binaire de sortie
    FILE *f_out = fopen(output_file, "wb");
    if (f_out == NULL) {
        perror("Erreur d'ouverture du fichier de sortie");
        free(decoded_data);
        return;
    }

    fwrite(decoded_data, 1, output_length, f_out);
    fclose(f_out);

    free(decoded_data);
}

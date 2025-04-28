#include "../../../include/phase1.h"
#include "../../../include/rsa_common_header.h"
#include "../../../include/other_base64.h"
#include "../../../include/rsa_tools.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

//############################################################################## chiffrement/dechiffrement ############################################################

void test_rsa_encrypt_decrypt(uint8_t* input, int length, const char *test_name) {
    keyPair_t keyPair;
    keyPair.pubKey.E=3;
    keyPair.pubKey.N=257;
    keyPair.privKey.E=171;
    keyPair.privKey.N=257;

    uint8_t* encrypted = malloc(length * sizeof(uint8_t));  // Allocation pour les octets chiffrés
    uint8_t* decrypted = malloc(length * sizeof(uint8_t));  // Allocation pour les octets déchiffrés

    if (encrypted == NULL || decrypted == NULL) {
        printf("Erreur d'allocation mémoire\n");
        return;
    }

    // Génération des clés
    //genKeysRabin(&keyPair.pubKey, &keyPair.privKey, MAX_PRIME);

    // Chiffrement
    encrypted = encrypt_tab(input, length, &keyPair.pubKey);
    printf("Chiffrement: input = 0x");
    for (int i = 0; i < length; i++) {
        printf("%02x", input[i]);
    }
    printf(", output = 0x");
    for (int i = 0; i < length; i++) {
        printf("%02x", encrypted[i]);
    }
    printf("\n");

    // Déchiffrement
    decrypted = decrypt_tab(encrypted, length, &keyPair.privKey);
    printf("Déchiffrement: input = 0x");
    for (int i = 0; i < length; i++) {
        printf("%02x", encrypted[i]);
    }
    printf(", output = 0x");
    for (int i = 0; i < length; i++) {
        printf("%02x", decrypted[i]);
    }
    printf("\n");

    // Assertion pour vérifier que l'entrée déchiffrée est égale à l'input
    assert(memcmp(input, decrypted, length) == 0);  // Verifie que le déchiffrement donne bien l'input

    printf("%s réalisé avec succès.\n", test_name);

    free(encrypted);
    free(decrypted);
}


void test_rsa() {
    uint8_t input[] = { 0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF };  // Message de 8 octets
    int length = sizeof(input) / sizeof(input[0]);
    printf("Test RSA avec un bloc de 64 bits (input = 0x1234567890ABCDEF)\n");
    test_rsa_encrypt_decrypt(input, length, "Test 1");
}

void test_rsa_multiple_bytes() {
    uint8_t input[] = { 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49 };  // Message de 8 octets
    int length = sizeof(input) / sizeof(input[0]);
    printf("Test RSA avec plusieurs octets (input = 0x4243444546474849)\n");
    test_rsa_encrypt_decrypt(input, length, "Test 2");
}


void test_rsa_empty_message() {
    uint8_t input[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};  // Message vide
    printf("Test RSA avec message vide\n");
    test_rsa_encrypt_decrypt(input, sizeof(input), "Test 3");
}

void test_rsa_long_message() {
    uint8_t input[] = {0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x20, 0x57, 0x6F};  // Message "Hello Wo" en 64 bits
    printf("Test RSA avec message long (input = 0x48656C6C6F20576F)\n");
    test_rsa_encrypt_decrypt(input, sizeof(input), "Test 4");
}

void test_rsa_8_bytes_message() {
    uint8_t input[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};  // Message de 8 octets
    printf("Test RSA avec 8 octets (input = 0x0102030405060708)\n");
    test_rsa_encrypt_decrypt(input, sizeof(input), "Test 5");
}


//############################################################# BASE 64 ##############################################################################

// Helper function for printing binary data
void print_hex(const uint8_t *data, size_t length) {
    for (size_t i = 0; i < length; i++)
        printf("%02X ", data[i]);
    printf("\n");
}

// Test conversion of uint32_t
void test_uint32() {
    printf("\n[TEST] uint32_t Base64 Conversion\n");

    uint32_t value = 0xDEADBEEF;  // Example 32-bit value
    size_t encoded_length, decoded_length;

    char *encoded = base64_encode((unsigned char *)&value, sizeof(value), &encoded_length);
    printf("uint32: %08X -> Base64: %s\n", value, encoded);

    uint32_t *decoded = (uint32_t *)base64_decode(encoded, encoded_length, &decoded_length);
    assert(decoded_length == sizeof(uint32_t));
    printf("Decoded: %08X\n", *decoded);

    free(encoded);
    free(decoded);
}

// Test conversion of uint64_t
void test_uint64() {
    printf("\n[TEST] uint64_t Base64 Conversion\n");

    uint64_t value = 0x1122334455667788;  // Example 64-bit value
    size_t encoded_length, decoded_length;

    char *encoded = base64_encode((unsigned char *)&value, sizeof(value), &encoded_length);
    printf("uint64: %016lX -> Base64: %s\n", value, encoded);

    uint64_t *decoded = (uint64_t *)base64_decode(encoded, encoded_length, &decoded_length);
    assert(decoded_length == sizeof(uint64_t));
    printf("Decoded: %016lX\n", *decoded);

    free(encoded);
    free(decoded);
}

// Test conversion of a character string
void test_string() {
    printf("\n[TEST] String Base64 Conversion\n");

    const char *message = "Hello, Base64!";
    size_t encoded_length, decoded_length;

    char *encoded = base64_encode((const unsigned char *)message, strlen(message), &encoded_length);
    printf("Original: %s -> Base64: %s\n", message, encoded);

    char *decoded = (char *)base64_decode(encoded, encoded_length, &decoded_length);
    printf("Decoded: %.*s\n", (int)decoded_length, decoded);

    free(encoded);
    free(decoded);
}

// Test conversion of a binary key (16 bytes)
void test_binary_key() {
    printf("\n[TEST] Binary Key Base64 Conversion\n");

    uint8_t key[16] = {0xBA, 0xAD, 0xF0, 0x0D, 0xCA, 0xFE, 0xBE, 0xEF,
                       0xDE, 0xAD, 0xC0, 0xDE, 0x12, 0x34, 0x56, 0x78};
    size_t encoded_length, decoded_length;

    char *encoded = base64_encode(key, sizeof(key), &encoded_length);
    printf("Binary Key: ");
    print_hex(key, sizeof(key));
    printf("Base64: %s\n", encoded);

    uint8_t *decoded = base64_decode(encoded, encoded_length, &decoded_length);
    printf("Decoded Key: ");
    print_hex(decoded, decoded_length);

    assert(memcmp(key, decoded, sizeof(key)) == 0);

    free(encoded);
    free(decoded);
}

void test_conversion() {
    printf("\n[TEST] file Conversion\n");
    // Test de conversion binaire -> Base64
    unsigned char binary_data[] = {0x12, 0x34, 0x56, 0x78};
    size_t binary_data_len = sizeof(binary_data);

    // Conversion binaire -> Base64
    char *base64_encoded = convert_binary_to_base64(binary_data, binary_data_len);
    printf("Base64 Encoded: %s\n", base64_encoded);

    // On attend le résultat encodé en base64
    char *expected_base64 = "EjRWeA==";
    assert(strcmp(base64_encoded, expected_base64) == 0);  // Vérification que la conversion est correcte

    // Test de conversion Base64 -> binaire
    size_t decoded_length;
    unsigned char *decoded_data = convert_base64_to_binary(base64_encoded, &decoded_length);

    // On attend que la longueur de données décodées soit égale à la longueur d'origine
    assert(decoded_length == binary_data_len);

    // Vérification des valeurs décodées
    for (size_t i = 0; i < decoded_length; i++) {
        assert(decoded_data[i] == binary_data[i]);  // Vérifie que chaque octet décodé correspond à l'original
    }

    printf("Décodage réussi.\n");

    // Libération de la mémoire allouée
    free(base64_encoded);
    free(decoded_data);
}

void test_file_conversion(const char *binary_input_file, const char *base64_output_file, const char *binary_output_file) {
    // Étape 1 : Convertir le fichier binaire en Base64
    printf("Conversion du fichier binaire en Base64...\n");
    convert_file_binary_to_base64(binary_input_file, base64_output_file);
    printf("Fichier Base64 généré : %s\n", base64_output_file);

    // Étape 2 : Convertir le fichier Base64 en binaire
    printf("Conversion du fichier Base64 en binaire...\n");
    convert_file_base64_to_binary(base64_output_file, binary_output_file);
    printf("Fichier binaire généré : %s\n", binary_output_file);

    // Étape 3 : Comparer les fichiers binaires d'origine et décryptés
    FILE *f_in1 = fopen(binary_input_file, "rb");
    FILE *f_in2 = fopen(binary_output_file, "rb");

    if (f_in1 == NULL || f_in2 == NULL) {
        perror("Erreur d'ouverture des fichiers binaires pour la comparaison");
        return;
    }

    // Obtenir la taille des fichiers
    fseek(f_in1, 0, SEEK_END);
    fseek(f_in2, 0, SEEK_END);
    long size1 = ftell(f_in1);
    long size2 = ftell(f_in2);
    fseek(f_in1, 0, SEEK_SET);
    fseek(f_in2, 0, SEEK_SET);

    if (size1 != size2) {
        printf("Les fichiers binaires n'ont pas la même taille.\n");
        fclose(f_in1);
        fclose(f_in2);
        return;
    }

    // Comparer les fichiers octet par octet
    int mismatch_found = 0;
    for (long i = 0; i < size1; i++) {
        unsigned char byte1, byte2;
        fread(&byte1, 1, 1, f_in1);
        fread(&byte2, 1, 1, f_in2);
        if (byte1 != byte2) {
            mismatch_found = 1;
            break;
        }
    }

    fclose(f_in1);
    fclose(f_in2);

    if (mismatch_found) {
        printf("Les fichiers binaires ne correspondent pas.\n");
    } else {
        printf("Les fichiers binaires sont identiques. Test réussi !\n");
    }
}

int main(int argc, char *argv[]) {
    (void)argc;
    (void)argv;

    // PHASE 1.1
    test_rsa();
    test_rsa_multiple_bytes();
    test_rsa_empty_message();
    test_rsa_long_message();
    test_rsa_8_bytes_message();
    printf("Tous les tests phase 1.1 réussis.\n");

    // PHASE 1.2

    // PHASE 1.3
    build_decoding_table();

    test_uint32();
    test_uint64();
    test_string();
    test_binary_key();
    test_conversion();

    // Fichiers de test
    const char *binary_input_file = "input_binary_file.bin";
    const char *base64_output_file = "output_base64_file.txt";
    const char *binary_output_file = "output_binary_file.bin";

    // Créer un fichier binaire d'exemple pour les tests
    FILE *f_in = fopen(binary_input_file, "wb");
    if (f_in == NULL) {
        perror("Erreur de création du fichier binaire d'entrée");
        return -1;
    }

    // Exemple de données binaires : "Hello, world!" en ASCII
    const char *data = "Hello, world!";
    fwrite(data, 1, strlen(data), f_in);
    fclose(f_in);

    // Lancer le test
    test_file_conversion(binary_input_file, base64_output_file, binary_output_file);

    base64_cleanup();
    printf("Le test de la phase 1.3 réussi.\n");

    return 0;
}

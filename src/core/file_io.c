#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../include/file_io.h"


// Function to read a message from a file
uint8_t* read_message(const char *filename) {
    // Open the file in binary read mode ("rb")
    FILE *file = fopen(filename, "rb");

    // Check if the file was opened correctly
    if (file == NULL) {
        perror("Error opening file");
        return NULL;
    }

    // Move to the end of the file to determine its size
    fseek(file, 0, SEEK_END);
    size_t file_size = ftell(file);  // changet from long to size_t

    // If the file is empty or the operation fails, return NULL
    if (file_size <= 0) {
        fclose(file);
        return NULL;
    }

    // Move back to the beginning of the file for reading
    fseek(file, 0, SEEK_SET);

    // Dynamically allocate memory to hold the file content
    uint8_t *message = (uint8_t*) malloc(file_size);
    if (message == NULL) {
        perror("Memory allocation error");
        fclose(file);
        return NULL;
    }

    // Read the file contents into the allocated memory
    size_t bytes_read = fread(message, 1, file_size, file);
    if (bytes_read != file_size) {
        perror("Error reading file");
        free(message);
        fclose(file);
        return NULL;
    }

    // Close the file after reading
    fclose(file);
    return message;
}

// Function to write a message to a file
int write_message(const char *filename, uint8_t *message) {
    // Open the file in binary write mode ("wb")
    FILE *file = fopen(filename, "wb");

    // Check if the file was opened correctly
    if (file == NULL) {
        perror("Error opening file");
        return -1;
    }

    // Write the entire message to the file
    size_t bytes_written = fwrite(message, 1, strlen((char*)message), file);
    if (bytes_written != strlen((char*)message)) {
        perror("Error writing to file");
        fclose(file);
        return -1;
    }

    // Close the file after writing
    fclose(file);
    return 0;
}

#ifndef FILE_IO_H
#define FILE_IO_H

#include <stdint.h>

// Function to read a message from a file
// Returns a dynamically allocated array containing the read message
// Returns NULL in case of an error (file not found, read error, etc.)
uint8_t* read_message(const char *filename);

// Function to write a message to a file
// Takes the message to write as a parameter
// Returns 0 on success, -1 on error (file not found, write error, etc.)
int write_message(const char *filename, uint8_t *message);

#endif // FILE_IO_H

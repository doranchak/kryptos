#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

int ALPHABET_SIZE = 26;

// start with letters A through Z, represented by integers 0 to 25
// return new arrangement where keyword appears first, followed by remaining unused letters.
// return seen index marking the alphabet positions for each letter
int *keyword_alphabet(char *keyword, int *seen) {
    int keyword_length = strlen(keyword);
    int* result = (int*)malloc(ALPHABET_SIZE * sizeof(int));
    for (int i=0; i<ALPHABET_SIZE; i++) result[i] = -1;
    for (int i=0; i<ALPHABET_SIZE; i++) seen[i] = -1; // track the position of each letter in the resulting re-arranged alphabet
    int pos = 0;
    for (int i=0; i<keyword_length; i++) {
        char ch = keyword[i];
        int val = ch - 'A';
        if (seen[val] == -1) {
            result[pos] = val;
            seen[val] = pos++;
        }
    }
    for (int i=0; i<ALPHABET_SIZE; i++) {
        if (seen[i] == -1) {
            result[pos] = i;
            seen[i] = pos++;
        }
    }

    return result;
}

void decrypt(char *ciphertext, int ciphertext_length, char *keyword, char *cycleword) {
    // get the vignere alphabet
    int* index = (int*)malloc(ALPHABET_SIZE * sizeof(int));
    int *alphabet = keyword_alphabet(keyword, index);

    // encrypt
    int len = strlen(cycleword);
    for (int i=0; i<(int)ciphertext_length; i++) {
        // char pt_ch = file_contents[i];
        int ct = ciphertext[i] - 'A';
        int pos = ((index[ct] - index[cycleword[i%len]-'A'])+26) % ALPHABET_SIZE;
        char pt = alphabet[pos] + 'A';
        printf("%c", pt);
    }
    printf("\n");
}

int main(int argc, char *argv[]) {
    if (argc != 4) {
        fprintf(stderr, "Decrypts the given ciphertext with Quagmire III using the given keyword and cycle (indicator) word.\n");
        fprintf(stderr, "Usage: %s <ciphertext_file> <keyword> <cycleword>\n", argv[0]);
        return 1;
    }

    // Open the text file
    FILE *file = fopen(argv[1], "r");
    if (file == NULL) {
        perror("Error opening file");
        return 2;
    }

    // Find the size of the file
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    // Allocate memory for the file contents
    char *file_contents = (char *)malloc(file_size + 1);
    if (file_contents == NULL) {
        fclose(file);
        perror("Memory allocation error");
        return 3;
    }

    // Read the entire file into the buffer
    size_t bytes_read = fread(file_contents, 1, file_size, file);
    if (bytes_read != (size_t)file_size) {
        fclose(file);
        free(file_contents);
        perror("Error reading file");
        return 4;
    }

    // Close the file
    fclose(file);

    // Remove non-alphabet characters
    size_t j = 0;
    for (size_t i = 0; i < (size_t)file_size; i++) {
        if (isalpha(file_contents[i])) {
            file_contents[j++] = toupper(file_contents[i]);
        }
    }
    file_contents[j] = '\0';  // Null-terminate the modified contents
    decrypt(file_contents, (int)j, argv[2], argv[3]);
    return 0;
}

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

int ALPHABET_SIZE = 26;

// start with letters A through Z, represented by integers 0 to 25
// return new arrangement where keyword appears first, followed by remaining unused letters.
// return seen index marking the alphabet positions for each letter
// return length of keyword, counting only unique letters
int *keyword_alphabet(char *keyword, int *seen, int *length) {
    int keyword_length = strlen(keyword);
    length = 0;
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
            length++;
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

void dump_alphabet_1(int *alphabet) {
    printf("     ");
    for (int i=0; i<26; i++) printf("%c", alphabet[i]+'A');
    printf("\n");
}
void dump_alphabet_2(int *alphabet, int* index, char *indicatorword, int indicatorword_length) {
    for (int i=0; i<indicatorword_length; i++) {
        printf("     ");
        for (int j=0; j<26; j++) {
            int offset = index[indicatorword[i]-'A'];
            printf("%c", alphabet[(j+offset)%26]+'A');
        }
        printf("\n");
    }
}

// operation:  0 = encrypt, 1 = decrypt
void quag(int operation, int type, char *input_text, int input_text_length, char *keyword1, char *keyword2, char *indicatorword, int verbose) {
    int len = strlen(indicatorword);
    // get the vignere alphabet
    int* index1 = (int*)malloc(ALPHABET_SIZE * sizeof(int));
    int* index2;

    int length;
    int *alphabet1 = keyword_alphabet(keyword1, index1, &length);
    int *alphabet2;
    if (type == 4) {
        index2 = (int*)malloc(ALPHABET_SIZE * sizeof(int));
        alphabet2 = keyword_alphabet(keyword2, index2, &length);
        if (verbose == 1) {
            printf("\n     ==========================\n");
            printf("     00000000001111111111222222\n");
            printf("     01234567890123456789012345\n");
            dump_alphabet_1(alphabet1);
            printf("     ==========================\n");
            dump_alphabet_2(alphabet2, index2, indicatorword, len);
        }
    } else {
        if (verbose == 1) {
            printf("\n     ==========================\n");
            dump_alphabet_1(alphabet1);
            printf("     ==========================\n");
            dump_alphabet_2(alphabet1, index1, indicatorword, len);
        }
    }
    if (verbose == 1) printf("     ==========================\n\n");

    // encrypt
    int* index = type == 4 ? index2 : index1;
    int* alphabet = type == 4 && operation == 0 ? alphabet2 : alphabet1;

    for (int i=0; i<(int)input_text_length; i++) {
        int ch1 = input_text[i] - 'A';
        int val = index[indicatorword[i%len]-'A'];
        int pos = type == 4 && operation == 1 ? index2[ch1] : index1[ch1];

        if (operation == 0) {
            pos += val;
        } else {
            pos -= val;
            pos += 26;
        }
        pos %= ALPHABET_SIZE;

        char ch2 = alphabet[pos] + 'A';
        printf("%c", ch2);
    }
    printf("\n");
}

int main(int argc, char *argv[]) {
    if (argc < 6) {
        fprintf(stderr, "Encrypts (decrypts) the given plaintext (ciphertext) with Quagmire III using the given keyword(s) and indicator (cycle) word.\n");
        fprintf(stderr, "Usage: %s [-verbose] <encrypt|decrypt> <type> <plaintext_file> <keyword1> <keyword2> <indicatorword>\n", argv[0]);
        fprintf(stderr, "  If -verbose is specified, more details are printed during encryption (decryption).\n");
        return 1;
    }

    int pos = 1;
    char* operation = argv[pos++];
    int verbose = 0;
    if (strcmp(operation, "-verbose") == 0) {
        operation = argv[pos++];
        verbose = 1;
    }

    if (strcmp(operation, "encrypt") != 0 && strcmp(operation, "decrypt") != 0) {
        fprintf(stderr, "BAD OPERATION: %s\n", operation);
        fprintf(stderr, "Supported operations are: encrypt, decrypt.\n");
        return 1;
    }

    int type = atoi(argv[pos++]);
    char* input_file = argv[pos++];

    if (type < 1 || type > 4) {
        fprintf(stderr, "BAD TYPE: %i\n", type);
        fprintf(stderr, "Supported types are: 1, 2, 3 and 4.\n");
        return 1;
    }

    if (type == 4 && argc < 6) {
        fprintf(stderr, "Missing keywords.  For Quagmire IV, you need 2 keywords and an indicator word.\n");
        return 1;
    }

    char* keyword1 = argv[pos++];
    char* keyword2;
    char* indicatorword;

    if (type == 4) keyword2 = argv[pos++];
    indicatorword = argv[pos++];

    // Open the text file
    FILE *file = fopen(input_file, "r");
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
    quag(strcmp(operation, "encrypt") == 0 ? 0 : 1, type, file_contents, (int)j, keyword1, keyword2, indicatorword, verbose);
    return 0;
}

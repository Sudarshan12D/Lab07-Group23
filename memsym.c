#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#define TRUE 1
#define FALSE 0

// Assuming maximum page table entries and maximum number of processes
#define MAX_PROCESSES 4

// Memory parameters
int OFFSET_BITS = -1; 
int PFN_BITS = -1;
int VPN_BITS = -1;
int CURRENT_PID = 0;
int IS_DEFINED = FALSE;

// Output file
FILE* output_file;

// TLB replacement strategy (FIFO or LRU)
char* strategy;


// Function prototypes
void processCommand(char** tokens);



char** tokenize_input(char* input) {
    char** tokens = NULL;
    char* token = strtok(input, " ");
    int num_tokens = 0;

    while (token != NULL) {
        num_tokens++;
        tokens = realloc(tokens, num_tokens * sizeof(char*));
        tokens[num_tokens - 1] = malloc(strlen(token) + 1);
        strcpy(tokens[num_tokens - 1], token);
        token = strtok(NULL, " ");
    }

    num_tokens++;
    tokens = realloc(tokens, num_tokens * sizeof(char*));
    tokens[num_tokens - 1] = NULL;

    return tokens;
}

int main(int argc, char* argv[]) {
    const char usage[] = "Usage: memsym.out <strategy> <input trace> <output trace>\n";
    char* input_trace;
    char* output_trace;
    char buffer[1024];

    // Parse command line arguments
    if (argc != 4) {
        printf("%s", usage);
        return 1;
    }
    strategy = argv[1];
    input_trace = argv[2];
    output_trace = argv[3];

    // Open input and output files
    FILE* input_file = fopen(input_trace, "r");
    output_file = fopen(output_trace, "w");  

    while ( !feof(input_file) ) {
        // Read input file line by line
        char *rez = fgets(buffer, sizeof(buffer), input_file);
        if ( !rez ) {
            fprintf(stderr, "Reached end of trace. Exiting...\n");
            return -1;
        } else {
            size_t len = strlen(buffer);
            if (len > 0 && buffer[len - 1] == '\n') {
                buffer[len - 1] = '\0';
            }
        }
        char** tokens = tokenize_input(buffer);
        processCommand(tokens);

        // TODO: Implement your memory simulator

        // Deallocate tokens
        for (int i = 0; tokens[i] != NULL; i++)
            free(tokens[i]);
        free(tokens);
    }

    // Close input and output files
    fclose(input_file);
    fclose(output_file);

    return 0;
}


void processCommand(char** tokens) {
    if (tokens[0] && strcmp(tokens[0], "define") == 0) {
        if (IS_DEFINED) {
            // If already defined, print an error and return
            fprintf(output_file, "Current PID: %d. Error: multiple calls to define in the same trace\n", CURRENT_PID);
            return;
        }
        OFFSET_BITS = atoi(tokens[1]);
        PFN_BITS = atoi(tokens[2]);
        VPN_BITS = atoi(tokens[3]);
        IS_DEFINED = TRUE;

        fprintf(output_file, "Current PID: %d. Memory instantiation complete. OFF bits: %d. PFN bits: %d. VPN bits: %d\n", 
                CURRENT_PID, OFFSET_BITS, PFN_BITS, VPN_BITS);
    }

    else if (tokens[0] && strcmp(tokens[0], "ctxswitch") == 0) {
        int new_pid = atoi(tokens[1]);
        // Check for valid PID range
        if (new_pid >= 0 && new_pid < MAX_PROCESSES) {
            CURRENT_PID = new_pid;
            fprintf(output_file, "Current PID: %d. Switched execution context to process: %d\n", CURRENT_PID, CURRENT_PID);
        } else {
            // Output an error message for invalid PID
            fprintf(output_file, "Current PID: %d. Invalid context switch to process %d\n", CURRENT_PID, new_pid);
        }
    }
    // Other commands should be implemented similarly
}
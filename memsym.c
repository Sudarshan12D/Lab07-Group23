#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#define TRUE 1
#define FALSE 0

// Assuming maximum page table entries and maximum number of processes
#define MAX_PROCESSES 4
#define MAX_REGISTERS 32
#define TLB_SIZE 8
#define PAGETABLE_SIZE 4

int registers[MAX_REGISTERS] = {0};

// Define a process context structure
typedef struct
{
    int registers[MAX_REGISTERS];
} ProcessContext;

ProcessContext processContexts[MAX_PROCESSES];

// Memory parameters
int OFFSET_BITS = -1;
int PFN_BITS = -1;
int VPN_BITS = -1;
int CURRENT_PID = 0;
int IS_DEFINED = FALSE;

uint32_t *physicalMemory;

// Output file
FILE *output_file;

// TLB replacement strategy (FIFO or LRU)
char *strategy;

typedef struct
{
    int pid;
    int validBit;
    int PFN;
    int VPN;
} PageTableEntry;

typedef struct
{
    int pid;
    int PFN;
    int VPN;
    int validBit;
} TLBEntry;

TLBEntry *tlb; // Fixed TLB of 8 entries
PageTableEntry **pageTables;

// Function prototypes
void processCommand(char **tokens);
int isValidRegister(const char *reg);

char **tokenize_input(char *input)
{
    char **tokens = NULL;
    char *token = strtok(input, " ");
    int num_tokens = 0;

    while (token != NULL)
    {
        num_tokens++;
        tokens = realloc(tokens, num_tokens * sizeof(char *));
        tokens[num_tokens - 1] = malloc(strlen(token) + 1);
        strcpy(tokens[num_tokens - 1], token);
        token = strtok(NULL, " ");
    }

    num_tokens++;
    tokens = realloc(tokens, num_tokens * sizeof(char *));
    tokens[num_tokens - 1] = NULL;

    return tokens;
}

int main(int argc, char *argv[])
{
    const char usage[] = "Usage: memsym.out <strategy> <input trace> <output trace>\n";
    char *input_trace;
    char *output_trace;
    char buffer[1024];

    // Parse command line arguments
    if (argc != 4)
    {
        printf("%s", usage);
        return 1;
    }
    strategy = argv[1];
    input_trace = argv[2];
    output_trace = argv[3];

    // Open input and output files
    FILE *input_file = fopen(input_trace, "r");
    output_file = fopen(output_trace, "w");

    while (!feof(input_file))
    {
        // Read input file line by line
        char *rez = fgets(buffer, sizeof(buffer), input_file);
        if (!rez)
        {
            fprintf(stderr, "Reached end of trace. Exiting...\n");
            return -1;
        }
        else
        {
            size_t len = strlen(buffer);
            if (len > 0 && buffer[len - 1] == '\n')
            {
                buffer[len - 1] = '\0';
            }
        }
        char **tokens = tokenize_input(buffer);
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

int isValidRegister(const char *reg)
{
    if (reg[0] != 'r')
    {
        return FALSE;
    }
    long regNum = strtol(&reg[1], NULL, 10);
    return (regNum >= 0 && regNum <= 31); // Assuming registers r0 to r31 are valid
}

void contextSwitch(int new_pid)
{
    // Save current process context
    memcpy(processContexts[CURRENT_PID].registers, registers, sizeof(registers));

    // Switch to new process
    CURRENT_PID = new_pid;

    // Restore new process context
    memcpy(registers, processContexts[CURRENT_PID].registers, sizeof(registers));

    fprintf(output_file, "Current PID: %d. Switched execution context to process: %d\n", CURRENT_PID, CURRENT_PID);
}

void processCommand(char **tokens)
{
    if (tokens[0] && strcmp(tokens[0], "define") == 0)
    {
        if (IS_DEFINED)
        {
            // If already defined, print an error and return
            fprintf(output_file, "Current PID: %d. Error: multiple calls to define in the same trace\n", CURRENT_PID);
            return;
        }

        OFFSET_BITS = atoi(tokens[1]);
        PFN_BITS = atoi(tokens[2]);
        VPN_BITS = atoi(tokens[3]);
        IS_DEFINED = TRUE;

        // Initialize TLB entries as invalid
        tlb = (TLBEntry *)malloc(TLB_SIZE * sizeof(TLBEntry));
        for (int i = 0; i < TLB_SIZE; i++)
        {
            tlb[i].validBit = 0;
            tlb[i].PFN = 0;
            tlb[i].VPN = 0;
            tlb[i].pid = 0;
        }

        pageTables = (PageTableEntry **)malloc(PAGETABLE_SIZE * sizeof(PageTableEntry *));

        // Initialize page table entries as invalid
        for (int i = 0; i < PAGETABLE_SIZE; i++)
        {
            pageTables[i] = (PageTableEntry *)malloc(pow(2, VPN_BITS) * sizeof(PageTableEntry));
            for (int j = 0; j < pow(2, VPN_BITS); j++)
            {
                pageTables[i][j].validBit = 0;
                pageTables[i][j].pid = i;
                pageTables[i][j].VPN = j;
                pageTables[i][j].PFN = 0;
            }
        }

        physicalMemory = (uint32_t *)malloc(pow(2, OFFSET_BITS + PFN_BITS) * sizeof(u_int32_t));

        // Initialize all locations to 0
        for (int i = 0; i < pow(2, OFFSET_BITS + PFN_BITS); i++)
        {
            physicalMemory[i] = 0;
        }

        fprintf(output_file, "Current PID: %d. Memory instantiation complete. OFF bits: %d. PFN bits: %d. VPN bits: %d\n",
                CURRENT_PID, OFFSET_BITS, PFN_BITS, VPN_BITS);
    }

    else if (tokens[0] && strcmp(tokens[0], "ctxswitch") == 0)
    {

        if (!IS_DEFINED)
        {
            fprintf(output_file, "Current PID: %d. Error: attempt to execute instruction before define\n", CURRENT_PID);
            return;
        }

        int new_pid = atoi(tokens[1]);
        // Check for valid PID range
        if (new_pid >= 0 && new_pid < MAX_PROCESSES)
        {
            contextSwitch(new_pid);
        }
        else
        {
            // Output an error message for invalid PID
            fprintf(output_file, "Current PID: %d. Invalid context switch to process %d\n", CURRENT_PID, new_pid);
        }
    }

    else if (tokens[0] && strcmp(tokens[0], "load") == 0)
    {

        static int error_reported = FALSE;

        if (!IS_DEFINED)
        {
            if (!error_reported)
            { // Only print the error if it hasn't been reported already
                fprintf(output_file, "Current PID: %d. Error: attempt to execute instruction before define\n", CURRENT_PID);
                error_reported = TRUE; // Set to TRUE after reporting the error
            }
            return; // Early return since memory is not defined
        }

        if (tokens[1] && tokens[2])
        {
            char *dst = tokens[1]; // Destination register
            char *src = tokens[2]; // Source operand

            if (!isValidRegister(dst))
            {
                fprintf(output_file, "Current PID: %d. Error: invalid register operand %s\n", CURRENT_PID, dst);
                return;
            }

            if (src[0] == '#')
            { // Immediate value

                int regIndex = atoi(dst + 1); // Get the register index, assuming 'rX' format
                int value = atoi(src + 1);    // Get the immediate value
                if (regIndex >= 0 && regIndex < MAX_REGISTERS)
                {
                    registers[regIndex] = value;
                    fprintf(output_file, "Current PID: %d. Loaded immediate %s into register %s\n", CURRENT_PID, src + 1, dst);
                }

                else
                {
                    // TODO: Implement memory location loading
                    // For now, let's just print a placeholder
                    fprintf(output_file, "Current PID: %d. Loaded value of location %s (<value>) into register %s\n", CURRENT_PID, src, dst);
                }
            }
        }
        else
        {
            // Error: 'load' command requires a destination and a source operand
            fprintf(output_file, "Error: 'load' command requires a destination and a source operand.\n");
        }

        error_reported = FALSE;
    }

    else if (tokens[0] && strcmp(tokens[0], "add") == 0)
    {
        if (!IS_DEFINED)
        {
            fprintf(output_file, "Current PID: %d. Error: attempt to execute instruction before define\n", CURRENT_PID);
            return;
        }

        // Store the initial value of r1 before performing the addition
        int initial_r1_value = registers[1];

        // Assuming the 'add' instruction adds the contents of r1 and r2 and stores the result in r1
        int sum = initial_r1_value + registers[2];
        registers[1] = sum; // Store the result back in r1

        fprintf(output_file, "Current PID: %d. Added contents of registers r1 (%d) and r2 (%d). Result: %d\n",
                CURRENT_PID, initial_r1_value, registers[2], sum);
    }

    else if (tokens[0] && strcmp(tokens[0], "map") == 0)
    {
        if (!IS_DEFINED)
        {
            fprintf(output_file, "Current PID: %d. Error: attempt to execute instruction before define\n", CURRENT_PID);
            return;
        }

        if (tokens[1] && tokens[2])
        {
            int VPN = atoi(tokens[1]);
            int PFN = atoi(tokens[2]);

            if (VPN >= 0 && VPN < pow(2, VPN) && PFN >= 0 && PFN < pow(2, PFN))
            {
                // Update TLB

                // Update page table
                pageTables[CURRENT_PID][VPN].PFN = PFN;
                pageTables[CURRENT_PID][VPN].validBit = 1;

                fprintf(output_file, "Current PID: %d. Mapped virtual page number %d to physical frame number %d\n", CURRENT_PID, VPN, PFN);
            }
            else
            {
                fprintf(output_file, "Error: Invalid VPN or PFN\n");
            }
        }
        else
        {
            fprintf(output_file, "Error: 'map' command requires a VPN and a PFN\n");
        }
    }
    // Other commands should be implemented similarly
}
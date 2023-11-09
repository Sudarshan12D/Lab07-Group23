#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <math.h>
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
int32_t counter = -1;

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
    uint32_t timestamp;
    int PFN;
    int VPN;
    int validBit;
} TLBEntry;

TLBEntry *tlb;
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

    free(physicalMemory);
    free(tlb);
    free(pageTables);

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

void map2TLB(int VPN, int PFN)
{
    int replacementIndex = -1;
    uint32_t oldestTimestamp = UINT32_MAX;
    int foundEmptySlot = FALSE;

    // Search for existing entry or the first empty slot
    for (int i = 0; i < TLB_SIZE; i++)
    {
        if (tlb[i].validBit && tlb[i].VPN == VPN && tlb[i].pid == CURRENT_PID)
        {
            tlb[i].PFN = PFN;
            tlb[i].timestamp = counter; // Update timestamp on hit
            return;
        }
        if (!tlb[i].validBit && !foundEmptySlot)
        {
            replacementIndex = i; // First empty slot
            foundEmptySlot = TRUE;
        }
        else if (tlb[i].validBit && tlb[i].timestamp < oldestTimestamp)
        {
            oldestTimestamp = tlb[i].timestamp;
            replacementIndex = i; // Oldest entry for replacement
        }
    }

    // Replace the chosen entry
    tlb[replacementIndex].pid = CURRENT_PID;
    tlb[replacementIndex].VPN = VPN;
    tlb[replacementIndex].PFN = PFN;
    tlb[replacementIndex].validBit = 1;
    tlb[replacementIndex].timestamp = counter; // Update timestamp for new or replaced entry
}

int translateAddress(int virtualAddr)
{
    int VPN = virtualAddr / pow(2, OFFSET_BITS); // Calculate the VPN from the virtual address
    int offset = virtualAddr % (int)pow(2, OFFSET_BITS);
    int TLBHit = FALSE;

    // First, check the TLB for a quick lookup
    for (int i = 0; i < TLB_SIZE; i++)
    {
        if (tlb[i].validBit && tlb[i].VPN == VPN && tlb[i].pid == CURRENT_PID)
        {
            fprintf(output_file, "Current PID: %d. Translating. Lookup for VPN %d hit in TLB entry %d. PFN is %d\n", CURRENT_PID, VPN, i, tlb[i].PFN);
            TLBHit = TRUE;
            tlb[i].timestamp = counter;                       // Update timestamp on hit
            return tlb[i].PFN * pow(2, OFFSET_BITS) + offset; // Return physical address
        }
    }

    // TLB miss
    if (!TLBHit)
    {
        fprintf(output_file, "Current PID: %d. Translating. Lookup for VPN %d caused a TLB miss\n", CURRENT_PID, VPN);

        // Check the page table
        if (pageTables[CURRENT_PID][VPN].validBit)
        {
            // Update TLB and return physical address
            map2TLB(VPN, pageTables[CURRENT_PID][VPN].PFN);
            return pageTables[CURRENT_PID][VPN].PFN * pow(2, OFFSET_BITS) + offset;
        }
        else
        {
            // VPN not found in the page table
            fprintf(output_file, "Current PID: %d. Translating. Translation for VPN %d not found in page table\n", CURRENT_PID, VPN);
            // This is not necessarily a page fault, so do not log or return page fault here
        }
    }

    // The function will reach here only if it's a real page fault
    // Check if virtual address is valid and within range, if not, it's a page fault
    if (VPN >= pow(2, VPN_BITS) || offset >= pow(2, OFFSET_BITS))
    {
        fprintf(output_file, "Current PID: %d. Page fault at virtual address %d\n", CURRENT_PID, virtualAddr);
        return -1; // Page fault
    }

    // If the address is within range but VPN not found in page table, it's not a page fault
    return -2; // Indicate address translation failure, but not a page fault
}

void processCommand(char **tokens)
{

    counter++;

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
            {
                fprintf(output_file, "Current PID: %d. Error: attempt to execute instruction before define\n", CURRENT_PID);
                error_reported = TRUE;
            }
            return;
        }

        if (tokens[1] && tokens[2])
        {
            char *dst = tokens[1];
            char *src = tokens[2];

            if (!isValidRegister(dst))
            {
                fprintf(output_file, "Current PID: %d. Error: invalid register operand %s\n", CURRENT_PID, dst);
                return;
            }

            int regIndex = atoi(dst + 1);

            if (src[0] == '#')
            { // Immediate value
                int value = atoi(src + 1);
                registers[regIndex] = value;
                fprintf(output_file, "Current PID: %d. Loaded immediate %s into register %s\n", CURRENT_PID, src + 1, dst);
            }
            else
            { // Load from memory address
                int virtualAddr = atoi(src);
                int physicalAddr = translateAddress(virtualAddr);

                // Check for translation failure
                if (physicalAddr == -2)
                {
                    // Translation failure, but not a page fault. Stop further processing.
                    return;
                }

                if (physicalAddr == -1)
                {
                    // Page fault. Log and stop further processing.
                    fprintf(output_file, "Current PID: %d. Page fault at virtual address %d\n", CURRENT_PID, virtualAddr);
                    return;
                }

                // Successful translation, load from physical memory
                registers[regIndex] = physicalMemory[physicalAddr];
                fprintf(output_file, "Current PID: %d. Loaded value of location %d (%d) into register %s\n", CURRENT_PID, virtualAddr, physicalMemory[physicalAddr], dst);
            }
        }
        else
        {
            fprintf(output_file, "Error: 'load' command requires a destination and a source operand.\n");
        }
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

        int VPN = atoi(tokens[1]);
        int PFN = atoi(tokens[2]);

        if ((VPN >= 0 && VPN < pow(2, VPN_BITS)) && (PFN >= 0 && PFN < pow(2, PFN_BITS)))
        {
            // Update TLB
            map2TLB(VPN, PFN);

            // Update page table
            pageTables[CURRENT_PID][VPN].PFN = PFN;
            pageTables[CURRENT_PID][VPN].validBit = 1;
            pageTables[CURRENT_PID][VPN].VPN = VPN;

            fprintf(output_file, "Current PID: %d. Mapped virtual page number %d to physical frame number %d\n", CURRENT_PID, VPN, PFN);
        }
        else
        {
            fprintf(output_file, "Error: Invalid VPN or PFN\n");
        }
    }

    else if (tokens[0] && strcmp(tokens[0], "unmap") == 0)
    {
        if (!IS_DEFINED)
        {
            fprintf(output_file, "Current PID: %d. Error: attempt to execute instruction before define\n", CURRENT_PID);
            return;
        }

        int VPN = atoi(tokens[1]);
        if (VPN >= 0 && VPN < pow(2, VPN_BITS))
        {

            for (int i = 0; i < TLB_SIZE; i++)
            {

                if (tlb[i].validBit && tlb[i].VPN == VPN && tlb[i].pid == CURRENT_PID)
                {

                    tlb[i].validBit = 0; // Invalidate TLB entry
                }
            }

            // Check page table for the mapping
            if (pageTables[CURRENT_PID][VPN].validBit)
            {
                // Found a mapping in page table, invalidate it
                pageTables[CURRENT_PID][VPN].validBit = 0;
                pageTables[CURRENT_PID][VPN].PFN = 0; // Reset the PFN
            }

            fprintf(output_file, "Current PID: %d. Unmapped virtual page number %d\n", CURRENT_PID, VPN);
        }
        else
        {
            fprintf(output_file, "Error: Invalid VPN\n");
        }
        // Other commands should be implemented similarly
    }

    else if (tokens[0] && strcmp(tokens[0], "rinspect") == 0)
    {
        if (tokens[1])
        {
            if (!isValidRegister(tokens[1]))
            {
                fprintf(output_file, "Current PID: %d. Error: invalid register operand %s\n", CURRENT_PID, tokens[1]);
                return;
            }

            int regIndex = atoi(tokens[1] + 1); // Assuming 'rX' format
            if (regIndex >= 0 && regIndex < MAX_REGISTERS)
            {
                fprintf(output_file, "Current PID: %d. Inspected register %s. Content: %d\n", CURRENT_PID, tokens[1], registers[regIndex]);
            }
            else
            {
                fprintf(output_file, "Current PID: %d. Error: invalid register index %d\n", CURRENT_PID, regIndex);
            }
        }
        else
        {
            fprintf(output_file, "Error: 'rinspect' command requires a register operand.\n");
        }
    }

    else if (tokens[0] && strcmp(tokens[0], "pinspect") == 0)
    {
        if (!IS_DEFINED)
        {
            fprintf(output_file, "Current PID: %d. Error: attempt to execute instruction before define\n", CURRENT_PID);
            return;
        }

        if (tokens[1])
        {
            int VPN = atoi(tokens[1]);
            if (VPN >= 0 && VPN < pow(2, VPN_BITS))
            {
                PageTableEntry entry = pageTables[CURRENT_PID][VPN];
                fprintf(output_file, "Current PID: %d. Inspected page table entry %d. Physical frame number: %d. Valid: %d\n",
                        CURRENT_PID, VPN, entry.PFN, entry.validBit);
            }
            else
            {
                fprintf(output_file, "Current PID: %d. Error: Invalid VPN %d\n", CURRENT_PID, VPN);
            }
        }
        else
        {
            fprintf(output_file, "Error: 'pinspect' command requires a virtual page number.\n");
        }
    }

    else if (tokens[0] && strcmp(tokens[0], "store") == 0)
    {
        if (!IS_DEFINED)
        {
            fprintf(output_file, "Current PID: %d. Error: attempt to execute instruction before define\n", CURRENT_PID);
            return;
        }

        if (!tokens[1] || !tokens[2])
        {
            fprintf(output_file, "Error: 'store' command requires both a virtual address and a value.\n");
            return;
        }

        int virtualAddr = atoi(tokens[1]);
        int valueToStore;

        if (tokens[2][0] == '#')
        {
            valueToStore = atoi(tokens[2] + 1); // Immediate value
            // Store immediate value
            int physicalAddr = translateAddress(virtualAddr);
            if (physicalAddr != -1)
            {
                physicalMemory[physicalAddr] = valueToStore;
                fprintf(output_file, "Current PID: %d. Stored immediate %d into location %d\n",
                        CURRENT_PID, valueToStore, virtualAddr);
            }
            else
            {
                fprintf(output_file, "Current PID: %d. Page fault at virtual address %d\n", CURRENT_PID, virtualAddr);
            }
        }
        else if (isValidRegister(tokens[2]))
        {
            int regIndex = atoi(tokens[2] + 1);
            valueToStore = registers[regIndex]; // Value from register
            // Store value from register
            int physicalAddr = translateAddress(virtualAddr);
            if (physicalAddr != -1)
            {
                physicalMemory[physicalAddr] = valueToStore;
                fprintf(output_file, "Current PID: %d. Stored value of register %s (%d) into location %d\n",
                        CURRENT_PID, tokens[2], valueToStore, virtualAddr);
            }
            else
            {
                fprintf(output_file, "Current PID: %d. Page fault at virtual address %d\n", CURRENT_PID, virtualAddr);
            }
        }
        else
        {
            fprintf(output_file, "Current PID: %d. Error: invalid operand for store %s\n", CURRENT_PID, tokens[2]);
            return;
        }
    }

    else if (tokens[0] && strcmp(tokens[0], "linspect") == 0)
    {
        if (!IS_DEFINED)
        {
            fprintf(output_file, "Current PID: %d. Error: attempt to execute instruction before define\n", CURRENT_PID);
            return;
        }

        if (tokens[1])
        {
            int physicalAddr = atoi(tokens[1]);

            if (physicalAddr >= 0 && physicalAddr < pow(2, OFFSET_BITS + PFN_BITS))
            {
                int value = physicalMemory[physicalAddr];
                fprintf(output_file, "Current PID: %d. Inspected physical location %d. Value: %d\n", CURRENT_PID, physicalAddr, value);
            }
            else
            {
                fprintf(output_file, "Error: Invalid physical memory address %d\n", physicalAddr);
            }
        }
        else
        {
            fprintf(output_file, "Error: 'linspect' command requires a physical memory address.\n");
        }
    }

    else if (tokens[0] && strcmp(tokens[0], "tinspect") == 0)
    {
        if (!IS_DEFINED)
        {
            fprintf(output_file, "Current PID: %d. Error: attempt to execute instruction before define\n", CURRENT_PID);
            return;
        }

        if (tokens[1])
        {
            int tlbIndex = atoi(tokens[1]);
            if (tlbIndex >= 0 && tlbIndex < TLB_SIZE)
            {
                TLBEntry entry = tlb[tlbIndex];
                fprintf(output_file, "Current PID: %d. Inspected TLB entry %d. VPN: %d. PFN: %d. Valid: %d. PID: %d. Timestamp: %u\n",
                        CURRENT_PID, tlbIndex, entry.VPN, entry.PFN, entry.validBit, entry.pid, entry.timestamp);
            }
            else
            {
                fprintf(output_file, "Error: Invalid TLB entry index %d\n", tlbIndex);
            }
        }
        else
        {
            fprintf(output_file, "Error: 'tinspect' command requires a TLB entry index.\n");
        }
    }
}
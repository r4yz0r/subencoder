#define _GNU_SOURCE

#include <string.h>
#include <stdio.h>
#include <sys/stat.h>
#include <ctype.h>
#include <time.h>
#include <stdlib.h>

#define CHR "%_01234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-"

#define ZERO_OUT_EAX "\\x25\\x4A\\x4D\\x4E\\x55\\x25\\x35\\x32\\x31\\x2A"
#define PUSH_EAX "\\x50"

/** ************************************************************************* *
 *                                                                            *
 * Shellcode SUB Encoder                                                      *
 *                                                                            *
 * This code is based on:                                                     *
 * https://github.com/Partyschaum/haxe/blob/master/printable_helper.c         *
 *                                                                            *
 * Compile:                                                                   *
 * gcc -g3 -fno-stack-protector -z execstack -o subencoder subencoder.c       *
 * by r4yz0r                                                                  *
 *                                                                            *
 * ************************************************************************** */

/*
 * Function prototypes
 */
char* find(int start, int end, unsigned char * allowedCharsConverted);
const unsigned int swap_endian(unsigned int address);
void reverse(char *);
int string_length(char *);

int main(int argc, char* argv[])
{
    unsigned int targ, last;

    char ch;
    char *shellcode;
    unsigned char *allowedchars;
    long lSizeAllowedChars;
    long lSizeShellCode;

    char *start_arg = "0"; //EAX is zero-ed out, so we start from zero

    FILE *fpShellcode;
    FILE *fpAllowedChars;

    char * finalresult = malloc(sizeof(char));
    finalresult[0] = 0; //null byte termination

    if(argc < 2)
    {
        printf("Usage: %s <filename shellcode> <filename allowed chars>\n", argv[0]);
        exit(1);
    }

    /* *************************** *
     * Read in Shellcode from file *
     * *************************** */
    fpShellcode = fopen(argv[1],"r");

    if(fpShellcode == NULL)
    {
        perror("Error while opening the file.\n");
        exit(EXIT_FAILURE);
    }

    fseek( fpShellcode , 0L , SEEK_END);
    lSizeShellCode = ftell( fpShellcode );
    rewind( fpShellcode );

    shellcode = calloc( 1, lSizeShellCode+1 );
    if( !shellcode ) fclose(fpShellcode),fputs("memory alloc fails",stderr),exit(1);

    /* copy file into buffer */
    if( 1!=fread( shellcode , lSizeShellCode, 1 , fpShellcode) )
        fclose(fpShellcode),free(shellcode),fputs("entire read fails",stderr),exit(1);

    shellcode[lSizeShellCode-1] = 0; //0 terminate

    /* ******************************* *
     * Read in Allowed Chars from file *
     * ********Ü********************** */
    fpAllowedChars = fopen(argv[2],"r");

    if(fpAllowedChars == NULL)
    {
        perror("Error while opening the file.\n");
        exit(EXIT_FAILURE);
    }

    fseek( fpAllowedChars , 0L , SEEK_END);
    lSizeAllowedChars = ftell( fpAllowedChars );
    rewind( fpAllowedChars );

    allowedchars = calloc( 1, lSizeAllowedChars+1 );
    if( !allowedchars ) fclose(fpAllowedChars),fputs("memory alloc fails",stderr),exit(1);

    /* copy file into buffer */
    if( 1!=fread( allowedchars , lSizeAllowedChars, 1 , fpAllowedChars) )
        fclose(fpAllowedChars),free(allowedchars),fputs("entire read fails",stderr),exit(1);

    printf("Original Shellcode:\n%s\n\n", shellcode);

    //reverse(shellcode);

    printf("Reversed Shellcode:\n%s\n\n", shellcode);

    printf("Allowed_chars file:\n%s\n", allowedchars);

    unsigned char *hexstr = allowedchars;
    unsigned char *substr = (char*) malloc(3*sizeof(char));
    unsigned char *ptr = hexstr;
    unsigned char * allowedchars_convert = malloc( (strlen(allowedchars)/2) * sizeof(char));
    unsigned char *retptr = allowedchars_convert;

    for (int i = 0; i<strlen(allowedchars); i=i+2)
    {
        strncpy(substr, ptr, 2);
        //printf("substr = %s\n", substr);
        int s = strtol(substr, NULL, 16);
        //printf("s= %d\n", s);
        ptr= ptr+2;
        sprintf(retptr, "%c", s);
        retptr = retptr +1;
    }
    //printf("converted= %d\n", allowedchars_convert);

    unsigned int i = 0;

    FILE *f = fopen("output.txt", "w");

    while (i < lSizeShellCode-8)
    {
        char * address = malloc(sizeof(char) * 10 + 1);
        strncpy(address, "0x",2);
        strncat(address, shellcode,8);
        address[10] = 0;

        printf("Address: %s\n", address);

        unsigned int start =  strtoul(start_arg, NULL, 0);
        unsigned int end = strtoul(address, NULL, 0);

        char * result = find(start, end, allowedchars_convert);
        printf("Result: \n%s\n\n", result);

        if (f == NULL)
        {
            printf("Error opening file!\n");
            exit(1);
        }
        fprintf(f, "%s", result);

        shellcode = shellcode + 8;
        i=i+8;
    }
    fclose(f);

    fclose(fpShellcode);
    fclose(fpAllowedChars);
}

char* find(int last, int targ, unsigned char * allowed_chars)
{
    static char* encoded_shellcode;

    unsigned int t[4], l[4];
    unsigned int try, single, carry=0;
    int len, a, i, j, k, m, z, flag=0;
    char word[3][4];
    int sizeAllowed = strlen(allowed_chars);
    unsigned char mem[sizeAllowed];

    srand(time(NULL));
    bzero(mem, sizeAllowed);
    //strcpy(mem, CHR); //default, TODO: make avaible trough command line arg
    strcpy(mem, allowed_chars);
    len = strlen(mem);
    strfry(mem); // randomize

    t[3] = (targ & 0xff000000)>>24; // spliting by bytes
    t[2] = (targ & 0x00ff0000)>>16;
    t[1] = (targ & 0x0000ff00)>>8;
    t[0] = (targ & 0x000000ff);
    l[3] = (last & 0xff000000)>>24;
    l[2] = (last & 0x00ff0000)>>16;
    l[2] = (last & 0x00ff0000)>>16;
    l[1] = (last & 0x0000ff00)>>8;
    l[0] = (last & 0x000000ff);

    for(a=1; a < 5; a++)   // value count
    {
        carry = flag = 0;
        for(z=0; z < 4; z++)   // byte count
        {
            for(i=0; i < len; i++)
            {
                for(j=0; j < len; j++)
                {
                    for(k=0; k < len; k++)
                    {
                        for(m=0; m < len; m++)
                        {
                            if(a < 2) j = len+1;
                            if(a < 3) k = len+1;
                            if(a < 4) m = len+1;
                            try = t[z] + carry+mem[i]+mem[j]+mem[k]+mem[m];
                            single = (try & 0x000000ff);
                            if(single == l[z])
                            {
                                carry = (try & 0x0000ff00)>>8;
                                if(i < len) word[0][z] = mem[i];
                                if(j < len) word[1][z] = mem[j];
                                if(k < len) word[2][z] = mem[k];
                                if(m < len) word[3][z] = mem[m];
                                i = j = k = m = len+2;
                                char *start_arg = "0";
                                flag++;
                            }
                        }
                    }
                }
            }
        }

        if(flag == 4)   // if all 4 bytes found
        {
            printf("-------------------\n");

            unsigned int size = sizeof(word) * 24 * a;
            encoded_shellcode = malloc(51 + sizeof(char) * size);

            //zero out EAX
            printf("AND EAX,554E4D4A\n");
            printf("AND EAX,2A313235\n");
            strncat(encoded_shellcode, ZERO_OUT_EAX,50);

            for(i=0; i < a; i++)
            {
                printf("SUB EAX, 0x%08x\n", *((unsigned int *)word[i]));

                unsigned int _word = *((unsigned int *)word[i]);

                /* swap to little endian:*/
                unsigned int swapped = swap_endian(_word);

                int size2 = snprintf(NULL, 0, "%08x", swapped);
                char * sub_value = malloc(size2+1);
                sprintf(sub_value, "%08x", swapped);

                strncat(encoded_shellcode, "\\x2D",5);

                int newSize = strlen(sub_value) * 2.5;
                char * python_style = malloc( newSize * sizeof(char)  );
                python_style[0] = 0;
                char * p = sub_value;

                for(int v=0; v<strlen(sub_value); v=v+2)
                {
                    strncat(python_style, "\\x", 3);
                    strncat(python_style,p,2);
                    p=p+2;
                }

                strncat(encoded_shellcode, python_style,strlen(python_style));

                free(python_style);
                free(sub_value);

            }
            strncat(encoded_shellcode, PUSH_EAX,4);
            return encoded_shellcode;
        }
    }
    return NULL;
}

/**
 * convert address to little endian format
 */
const unsigned int swap_endian(unsigned int address)
{

    static unsigned int swapped;

    swapped = ((address>>24)&0xff) | // move byte 3 to byte 0
              ((address<<8)&0xff0000) | // move byte 1 to byte 2
              ((address>>8)&0xff00) | // move byte 2 to byte 1
              ((address<<24)&0xff000000); // byte 0 to byte 3
    return swapped;
}

void reverse(char *string)
{
    int length, c;
    char *begin, *end, temp;

    length = string_length(string);
    begin  = string;
    end    = string;

    for (c = 0; c < length - 8; c++)
        end++;

    for (c = 0; c < length/2; c=c+8)
    {
        char * temp = calloc(1,sizeof(char) * 8);
        strncpy(temp,end, 8);

        strncpy(end,begin, 8);
        strncpy(begin,temp, 8);
        free(temp);

        begin=begin + 8;
        end=end -8;
    }
}

int string_length(char *pointer)
{
    int c = 0;

    while( *(pointer + c) != '\0' )
        c++;

    return c;
}


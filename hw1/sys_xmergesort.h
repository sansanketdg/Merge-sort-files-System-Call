/* Structure to be used for data transfer between user program
   and kernel implementation of xmergesort system calls
*/
#define OPTION_UNIQUE_ONLY 0x01
#define OPTION_DUPLICATES_ALLOWED 0x02
#define OPTION_CASE_INSENSITIVE_COMPARE 0x04
#define OPTION_ALREADY_SORTED 0x10
#define OPTION_RETURN_WRITTEN_RECORDS 0x20

typedef struct XmergesortParams {
	char **input_filenames;	//	Array of Input File Path
	unsigned int flags;		//	word specifying what all optionsof sorting are to be applied
	char *output_filename;	//  Output File Path
	int input_filecount;	//  Number of Input Files 
	unsigned int *data;     //  Number of sorted records written in data
}XmergesortParams;
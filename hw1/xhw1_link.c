#include <asm/unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/syscall.h>
#include <unistd.h>
#include "sys_xmergesort.h"

#ifndef __NR_xmergesort
#error xmergesort system call not defined
#endif

typedef enum { false, true } bool;

int main(int argc, char *argv[])
{
	int opt;
	int index;
	XmergesortParams args;
	args.flags = 0;
	args.input_filecount = 0;
	args.data = 0;
	bool data_flag_on = false;

	while((opt = getopt(argc, argv, "uaitd")) != -1 ){
		switch(opt){
			case 'u':
			args.flags = args.flags | OPTION_UNIQUE_ONLY;   
			break;
			case 'a':
			args.flags = args.flags | OPTION_DUPLICATES_ALLOWED; 
			break;
			case 'i':
			args.flags = args.flags | OPTION_CASE_INSENSITIVE_COMPARE;
			break;
			case 't':
			args.flags = args.flags | OPTION_ALREADY_SORTED;
			break;
			case 'd':
			data_flag_on = true;
			args.flags = args.flags | OPTION_RETURN_WRITTEN_RECORDS;
			break;
		}
	}
	args.input_filenames = malloc(sizeof(char*)*(argc - optind - 1));
	args.output_filename = argv[optind];
	args.input_filecount = argc - optind - 1;
	for(index = 0; index < args.input_filecount; index++){
		args.input_filenames[index] = argv[index+optind+1];
	}
	
	args.data = (unsigned int *)malloc(sizeof(unsigned int));
	if(args.data == NULL){
		printf("Could not malloc memory for data\n");
	}
	else{
		*(args.data) = 0;
		int rc;
		void *dummy = (void *) &args;

	  	rc = syscall(__NR_xmergesort, dummy);
		if (rc == 0){
			printf("syscall returned %d\n", rc);
			if(data_flag_on)
			printf("Number of sorted records written - %d\n", *(args.data));
		}
		else
			printf("syscall returned %d (errno=%d)\n", rc, errno);
		free(args.data);
		exit(rc);
	}	
	return 0;
}

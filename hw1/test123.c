#include<stdio.h>
#include <stdlib.h>
#include <unistd.h>
typedef enum { false, true } bool;

void main(int argc, char *argv[]){

	int opt;
	bool  n_flag = false;
	bool s_flag = false;

	//int read_ret;
	//FILE *fileptr;
	//char *buffer;
	//	long filelen;
	//	char *buff = NULL;
	//	int rc=-1;
	//	size_t bytesRead = 0;
	//	struct trfs_record *samplerecord;
	//
	//						int mapping_count = 0;
	//							int address, fd;
	//								int **mapping_arr = 0;
	//									int i;
	//
										while((opt = getopt(argc, argv, "ns")) != -1){
													switch(opt){
																case 'n':
																			n_flag = true;
																							break;
																										case 's':																														s_flag = true;
			break;																							}
																																}
																																			if(s_flag)
																																					printf("s flag is set\n");
																																						if(n_flag)
																																								printf("n flag is set\n");
	//
																					printf("TFILE is %s\n", argv[optind]);
}

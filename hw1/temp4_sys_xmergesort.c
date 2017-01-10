#include <linux/linkage.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <asm/uaccess.h>
#include <asm/segment.h>
#include <asm/page.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/moduleloader.h>
#include <linux/string.h>
#include "sys_xmergesort.h"

/* Flag to allow printing debug statements. Please set this to 0 and rebuild
 this module to prevent printing debug messages
*/
#define DEBUGON		0
/* Flag to allow printing  
*/
#define BUFFER_SIZE 20

asmlinkage extern long (*sysptr)(void *arg);

int file_open(const char* path, int flags, int rights, struct file **filePtr) {
    struct file* filp = NULL;
    mm_segment_t oldfs;
    int err = 0;

    oldfs = get_fs();
    set_fs(get_ds());
    filp = filp_open(path, flags, rights);
    set_fs(oldfs);
    if(IS_ERR(filp)) {
		*filePtr = NULL;
        err = PTR_ERR(filp);
        return err;
    }
	*filePtr = filp;
    return 0;
}

void file_close(struct file **file) {
	if(*file != NULL)
    	filp_close(*file, NULL);
   	*file = NULL;
}

int file_read(struct file* file, unsigned long long offset, unsigned char* data, unsigned int size) {
    mm_segment_t oldfs;
    int ret;

    oldfs = get_fs();
    set_fs(get_ds());

    ret = vfs_read(file, data, size, &offset);

    set_fs(oldfs);
    return ret;
}

int file_write(struct file *file, unsigned long long *offset, unsigned char *data, unsigned int size) {
    mm_segment_t oldfs;
    int ret;

    oldfs = get_fs();
    set_fs(get_ds());

    ret = vfs_write(file, data, size, offset);

    set_fs(oldfs);
    return ret;
}

int getStringTillNextLine(char *data_buf, int *read_output_, char *str_, int *data_buf_offset, struct file *fread, unsigned long long *read_offset){
	int i = *data_buf_offset;
	char c = ' ';
	int str_count = 0;
	memset(str_, 0, BUFFER_SIZE);
	
	while(i < *read_output_){
		c = data_buf[i];
		if(c != '\n'){
			str_[str_count] = c;
			str_count++;
			i++;
		}
		else{
			break;
		}
	}
	if(i == *read_output_){
		memset(data_buf, 0, BUFFER_SIZE);
		*data_buf_offset = 0;
		*read_output_ = file_read(fread, *read_offset, data_buf, BUFFER_SIZE);
		if(*read_output_ > 0){
			*read_offset = *read_offset + *read_output_;
			i = 0;
			while(i < *read_output_){
				c = data_buf[i];
				if(c != '\n'){
					str_[str_count] = c;
					str_count++;
					i++;
				}
				else
					break;
			}	
		}
	}
	
	str_[str_count++] = '\n';
	str_[str_count++] = '\0';
	*data_buf_offset = ++i;
	return str_count;
}

int copyToOutputBuf(char *output_buf, int actual_out_buf_offset, char *str_file, int startIndex, int str_len, struct file *fwrite, unsigned long long *output_buf_offset){
	int i, write_output;
	//check if there is any space in output buf to accomodate the string
	if(BUFFER_SIZE - actual_out_buf_offset < str_len){
		//As there seems to be no space now,flush the output buf to output file
		//Clean the buffer and set offet to 0
		write_output = file_write(fwrite, output_buf_offset, output_buf, actual_out_buf_offset);
		*output_buf_offset = *output_buf_offset + write_output;
		memset(output_buf, 0, BUFFER_SIZE);
		actual_out_buf_offset = 0;
	}
	//Do it -1 for now to eliminated the \0 used for string
	for(i = startIndex; i < startIndex + str_len - 1; i++){
		output_buf[actual_out_buf_offset++] = str_file[i];
	}
	return actual_out_buf_offset;
}

int CopyArgsToKernelSpace(XmergesortParams *args, void *arg){
	int returnValue = 0, i = 0, j = 0;
	XmergesortParams *source = (XmergesortParams *)arg;
	struct filename *outFileName = NULL, *inputFileName = NULL;

	returnValue = copy_from_user(&args->flags, &source->flags, sizeof(int));
	if (0 != returnValue)
		goto label_clean_exit;

	returnValue = copy_from_user(&args->input_filecount, &source->input_filecount, sizeof(int));
	if (0 != returnValue)
		goto label_clean_exit;

	//args->data = (int *)kmalloc(sizeof(int)*1, GFP_KERNEL);
	/*
	returnValue = copy_from_user(&args->data, &source->data, sizeof(int));
	if (0 != returnValue)
		goto label_clean_exit;

	*/
/*
	args->output_filename = (char *)kmalloc(strlen(source->output_filename), GFP_KERNEL);
	returnValue = copy_from_user(&args->output_filename, &source->output_filename, sizeof(int));
	if (0 != returnValue)	
		goto label_outfile_fail;
*/
	/* Use getname() to copy the input and output file names
		from user to kernel space */

	outFileName	= getname(source->output_filename);
	if (IS_ERR(outFileName)) {
		printk(KERN_ALERT "OutFile name copy failed \n");
		returnValue = PTR_ERR(outFileName);
		goto label_outfile_fail;
	}
	args->output_filename = (char *)outFileName->name;

	//printk("I am below output \n");
	for(i = 0; i < args->input_filecount; i++){
		inputFileName = getname(source->input_filenames[i]);
		if(IS_ERR(inputFileName)) {
			printk(KERN_ALERT "InFile name copy failed \n");
			returnValue = PTR_ERR(inputFileName);
			goto label_infile_exit;
		}
		args->input_filenames[i] = (char *)inputFileName->name;
	}

	return returnValue;


label_infile_exit:
	for(j = 0; j < i+1; j++)
		kfree(args->input_filenames[j]);	
label_outfile_fail:
	kfree(args->output_filename);
label_clean_exit:
	return returnValue;
}

int ValidateArgument(void *arg){
	XmergesortParams *args = (XmergesortParams *)arg;
	int returnValue, i;
	struct kstat inputFileStat, outputFileStat;

	/* Check if the pointer itself is not null and can be accessed */
	if (args == NULL || !(access_ok(VERIFY_READ, args,	sizeof(args)))) {
		printk(KERN_ALERT "Arguements from user space are invalid\n");
		returnValue = -EINVAL;
		goto label_invalid_arg;
	}

	/* Validate all of the individual members of the struct for not
	   being null and their access */
	if(args->data == NULL || !(access_ok(VERIFY_READ, args->data, sizeof(args->data)))){
		returnValue = -EINVAL;
		printk("Error in data\n");
		goto label_invalid_arg;
	}

	//Now check the allowed combinations of options set in flags. 
	//For any wrong options combination, return error.

	//1. 'u' and 'a' cant be allowed simultaneously
	if(((args->flags & OPTION_UNIQUE_ONLY) == OPTION_UNIQUE_ONLY) && ((args->flags & OPTION_DUPLICATES_ALLOWED) == OPTION_DUPLICATES_ALLOWED)){
		returnValue = -EINVAL;
		printk("flag u and a set together...NOT ALLOWED\n");
		goto label_invalid_arg;
	}

	//2. Either of 'u' or 'a' should be there
	if(!(((args->flags & OPTION_UNIQUE_ONLY) == OPTION_UNIQUE_ONLY) || ((args->flags & OPTION_DUPLICATES_ALLOWED) == OPTION_DUPLICATES_ALLOWED))){
		returnValue = -EINVAL;
		printk("None of the flags 'u' / 'a' are set\n");
		goto label_invalid_arg;
	}

	if (args->input_filecount < 2 || args->input_filecount > 10 || !(access_ok(VERIFY_READ, args->input_filecount,
			sizeof(args->input_filecount)))) {
		returnValue = -EINVAL;
		printk("In filecount\n");
		goto label_invalid_arg;
	}

	if (args->output_filename == NULL || !(access_ok(VERIFY_READ, args->output_filename,
			sizeof(args->output_filename)))) {
		returnValue = -EINVAL;
		printk("In outputfilename\n");
		goto label_invalid_arg;
	}

	for(i = 0; i < args->input_filecount; i++){
		if (args->input_filenames[i] == NULL || !(access_ok(VERIFY_READ, args->input_filenames[i],
			sizeof(args->input_filenames[i])))) {
				returnValue = -EINVAL;
				printk("In input_filenames%d\n", i + 1);
				goto label_invalid_arg;
		}
	}

	/* Stat the out file to find if it exists and if it is a
		regular file */
	returnValue = vfs_stat(args->output_filename, &outputFileStat);

	if(returnValue && returnValue != -2){
		printk(KERN_ALERT "Could not stat output file. Error %d \n", returnValue);
		goto label_invalid_arg;
	}

	if (returnValue != -2 && !(S_ISREG(outputFileStat.mode))) {
		printk(KERN_ALERT "Output file is a directory \n");
		goto label_invalid_arg;
	}
	
	/* Stat the input files to find if they exist and if they are
		regular files */
	/* The input and output file should not be same */
	for(i = 0; i < args->input_filecount; i++){
		returnValue = vfs_stat(args->input_filenames[i], &inputFileStat);

		if(returnValue && returnValue != -2){
			printk(KERN_ALERT "Could not stat input-file%d. Error %d \n", i+1, returnValue);
			goto label_invalid_arg;
		}

		if (returnValue != -2 && !(S_ISREG(inputFileStat.mode))) {
			printk(KERN_ALERT "Input-file%d is a directory \n", i+1);
			goto label_invalid_arg;
		}

		/* The input and output file should not be same */
		if ((inputFileStat.dev == outputFileStat.dev)
			&& (inputFileStat.ino == outputFileStat.ino)) {
				printk(KERN_ALERT "Error: I/p-%d and O/p file are same \n", i+1);
				returnValue = -EINVAL;
				goto label_invalid_arg;
		}
	}

	#ifdef DEBUGON
		printk(KERN_ALERT "Arguements are valid \n");
	#endif

	return 0;

label_invalid_arg:
	return returnValue;
}

asmlinkage long xmergesort(void *arg)
{
	
	int temp1 = 0, temp2 = 0, str_len1 = 0, str_len2 = 0, actual_out_buf_offset = 0;
	int no_of_sorted_elements = 0;
	//CONVERT received argument structure to its required struct i.e. my_argsread_output_1
	XmergesortParams *args = (XmergesortParams *) arg;
	//XmergesortParams *args = NULL;
	
	unsigned char *data_buf_file1 = NULL, *data_buf_file2 = NULL, *str_file1 = NULL, *str_file2 = NULL, *output_buf = NULL, *last_out_buf_str = NULL;
	int data_buf_offset1 = 0, data_buf_offset2 = 0;
	int i = 0, error_code = 0, sample_first_file = 0, sample_second_file = 0, write_output = 0, read_output_1, read_output_2;
	int fwrite_return = 0, fread_return = 0;//, fread2_return = 0;
	unsigned long long read1_offset = 0, read2_offset = 0, output_buf_offset = 0;
		
	struct file *fwrite = NULL, *fread1 = NULL, *fread2 = NULL;	

	error_code = ValidateArgument(arg);
	if(error_code != 0){
		printk(KERN_ALERT "Invalid Arguement.  Error %d \n", error_code);
		goto lable_return;
	}
/*
	args = kmalloc(sizeof(XmergesortParams), GFP_KERNEL);
	if(!args){
		error_code = -ENOMEM;
		printk(KERN_ALERT "Could not copy user args to kernel	\n");
		goto label_return;
	}
	memset(args, 0, sizeof(XmergesortParams));

	error_code = CopyArgsToKernelSpace(args, arg);
	if (0 != retval) {
		printk(KERN_ALERT "Could not copy arguements to Kernel Space");
		goto label_clean_args;
	}
*/
/*	args = (struct my_args*)kmalloc(sizeof(struct my_args)*1, GFP_KERNEL);
	if(!args)
		return -ENOMEM;

	error_code = CopyArgsToKernelSpace(args, arg);
	if (error_code != 0) {
		printk(KERN_ALERT "Could not copy arguements to Kernel Space");
		kfree(args);
		return error_code;
	}
*/	
	//If received arg is NULL or input number of files is less than 2, flag invalid argument error
//	if(arg == NULL || args->input_filecount < 2)
//		return -EINVAL;

	//If received arg has filecount > 10, flag EDOM - Math argument out of domain of func error
//	if(args->input_filecount > 10)
//		return -EDOM; 

	
	data_buf_file1 = (unsigned char *)kmalloc(sizeof(unsigned char)*BUFFER_SIZE, GFP_KERNEL);
	if(!data_buf_file1){
		kfree(args);
		return -ENOMEM;
	}
	data_buf_file2 = (unsigned char *)kmalloc(sizeof(unsigned char)*BUFFER_SIZE, GFP_KERNEL);
	if(!data_buf_file2){
		kfree(data_buf_file1);
		kfree(args);
		return -ENOMEM;
	}
	str_file1 = (unsigned char *)kmalloc(sizeof(unsigned char)*BUFFER_SIZE, GFP_KERNEL);
	if(!str_file1){
		kfree(data_buf_file1);
		kfree(data_buf_file2);
		kfree(args);
		return -ENOMEM;
	}
	str_file2 = (unsigned char *)kmalloc(sizeof(unsigned char)*BUFFER_SIZE, GFP_KERNEL);
	if(!str_file2){
		kfree(data_buf_file1);
		kfree(data_buf_file2);
		kfree(str_file1);
		kfree(args);
		return -ENOMEM;
	}
	output_buf = (unsigned char *)kmalloc(sizeof(unsigned char)*BUFFER_SIZE, GFP_KERNEL);
	if(!output_buf){
		kfree(data_buf_file1);
		kfree(data_buf_file2);
		kfree(str_file1);
		kfree(str_file2);
		kfree(args);
		return -ENOMEM;
	}
	last_out_buf_str = (unsigned char *)kmalloc(sizeof(unsigned char)*BUFFER_SIZE, GFP_KERNEL);
	if(!last_out_buf_str){
		kfree(data_buf_file1);
		kfree(data_buf_file2);
		kfree(str_file1);
		kfree(str_file2);
		kfree(args);
		kfree(output_buf);
		return -ENOMEM;
	}
	memset(data_buf_file1, 0, BUFFER_SIZE);
	memset(data_buf_file2, 0, BUFFER_SIZE);
	memset(str_file1, 0, BUFFER_SIZE);
	memset(str_file2, 0, BUFFER_SIZE);
	memset(output_buf, 0, BUFFER_SIZE);
	memset(last_out_buf_str, 0, BUFFER_SIZE);
	
	//output_file_permissions = output_file_permissions | S_IRUSR | S_IWUSR | S_IXUSR;
	fwrite_return = file_open(args->output_filename, O_RDWR | O_CREAT, S_IWUSR | S_IRUSR, &fwrite);
	if(fwrite_return < 0){
		printk(KERN_INFO "Error opening output file %s:%d", args->output_filename, fwrite_return);
		error_code = fwrite_return;
		goto clean_all;
	}
	

	for(i = 0; i < args->input_filecount; i++){
		fread_return = file_open(args->input_filenames[i], O_RDONLY, 0, &fread1);
		if(fread_return < 0){
			printk(KERN_INFO "Error opening input file %s:%d", args->input_filenames[i], fread_return);
			error_code = fread_return;
			goto clean_all;
		}
		if(fread1->f_inode == fwrite->f_inode){
			fread_return = -EPERM;
			error_code = fread_return;
			goto clean_all;
		}
		file_close(&fread1);
	}

	//file_close(&fwrite);
	
	//Open first 2 files
	sample_first_file = file_open(args->input_filenames[0], O_RDONLY, 0, &fread1);
	sample_second_file = file_open(args->input_filenames[1], O_RDONLY, 0, &fread2);

	//Initially read page size buffer from both files
	read_output_1 = file_read(fread1, read1_offset, data_buf_file1, BUFFER_SIZE);
	read1_offset = read1_offset + read_output_1;
	read_output_2 = file_read(fread2, read2_offset, data_buf_file2, BUFFER_SIZE);
	read2_offset = read2_offset + read_output_2;

	//For debugginf purpose I am running this loop just once as my data in input file is less than page size
	while(read_output_1 > 0 && read_output_2 > 0){
		if(temp2 > 70)
			break;
		temp2++;

		str_len1 = getStringTillNextLine(data_buf_file1, &read_output_1, str_file1, &data_buf_offset1, fread1, &read1_offset);
		
		str_len2 = getStringTillNextLine(data_buf_file2, &read_output_2, str_file2, &data_buf_offset2, fread2, &read2_offset);

		printk("String 1 - %s\n", str_file1);
		printk("String 2 - %s\n", str_file2);
		
		//For debugginf purpose I am running this loop for just 8 times
		while(data_buf_offset1  < read_output_1+str_len1 && data_buf_offset2 < read_output_2+str_len2){//till the data buf exausts){
				if(temp1 > 70)
					break;
				temp1++;
				
				if((args->flags & OPTION_CASE_INSENSITIVE_COMPARE) == OPTION_CASE_INSENSITIVE_COMPARE){
					if(strcasecmp(str_file1, str_file2) <= 0){
					//printk("Length of str 1 - %d\n", str_len1);

						if((args->flags & OPTION_DUPLICATES_ALLOWED) == OPTION_DUPLICATES_ALLOWED){
							if(strcasecmp(str_file1, last_out_buf_str) >= 0){
								printk("Copy to output_buf - %s\n", str_file1);
								actual_out_buf_offset = copyToOutputBuf(output_buf, actual_out_buf_offset, str_file1, 0, str_len1, fwrite, &output_buf_offset);
								no_of_sorted_elements++;
								memset(last_out_buf_str, 0, BUFFER_SIZE);
								strcpy(last_out_buf_str, str_file1);
							} else if((args->flags & OPTION_ALREADY_SORTED) == OPTION_ALREADY_SORTED){
								printk("Flag t set and one of the file is unsorted\n");
								error_code = -EINVAL;
								goto clean_all;
							}
						}
						else{
							if(strcasecmp(str_file1, last_out_buf_str) > 0){
							printk("Copy to output_buf - %s\n", str_file1);
							actual_out_buf_offset = copyToOutputBuf(output_buf, actual_out_buf_offset, str_file1, 0, str_len1, fwrite, &output_buf_offset);
							no_of_sorted_elements++;
							memset(last_out_buf_str, 0, BUFFER_SIZE);
							strcpy(last_out_buf_str, str_file1);
							} else if((args->flags & OPTION_ALREADY_SORTED) == OPTION_ALREADY_SORTED){
								printk("Flag t set and one of the file is unsorted\n");
								error_code = -EINVAL;
								goto clean_all;
							}
						}						
					
						str_len1 = getStringTillNextLine(data_buf_file1, &read_output_1, str_file1, &data_buf_offset1, fread1, &read1_offset);
						printk("String 1 - %s\n", str_file1);
				
					}else{
						
						if((args->flags & OPTION_DUPLICATES_ALLOWED) == OPTION_DUPLICATES_ALLOWED){
							if(strcasecmp(str_file2, last_out_buf_str) >= 0){
								printk("Copy to output_buf - %s\n", str_file2);
								actual_out_buf_offset = copyToOutputBuf(output_buf, actual_out_buf_offset, str_file2, 0, str_len2, fwrite, &output_buf_offset);
								no_of_sorted_elements++;
								memset(last_out_buf_str, 0, BUFFER_SIZE);
								strcpy(last_out_buf_str, str_file2);
							} else if((args->flags & OPTION_ALREADY_SORTED) == OPTION_ALREADY_SORTED){
								printk("Flag t set and one of the file is unsorted\n");
								error_code = -EINVAL;
								goto clean_all;
							}
						}
						else{
							if(strcasecmp(str_file2, last_out_buf_str) > 0){
								printk("Copy to output_buf - %s\n", str_file2);
								actual_out_buf_offset = copyToOutputBuf(output_buf, actual_out_buf_offset, str_file2, 0, str_len2, fwrite, &output_buf_offset);
								no_of_sorted_elements++;
								memset(last_out_buf_str, 0, BUFFER_SIZE);
								strcpy(last_out_buf_str, str_file2);
							} else if((args->flags & OPTION_ALREADY_SORTED) == OPTION_ALREADY_SORTED){
								printk("Flag t set and one of the file is unsorted\n");
								error_code = -EINVAL;
								goto clean_all;
							}
						}
					
						str_len2 = getStringTillNextLine(data_buf_file2, &read_output_2, str_file2, &data_buf_offset2, fread2, &read2_offset);
						printk("String 2 - %s\n", str_file2);
					}
				}
				else{

					if(strcmp(str_file1, str_file2) <= 0){
					//printk("Length of str 1 - %d\n", str_len1);

						if((args->flags & OPTION_DUPLICATES_ALLOWED) == OPTION_DUPLICATES_ALLOWED){
							if(strcmp(str_file1, last_out_buf_str) >= 0){
								printk("Copy to output_buf - %s\n", str_file1);
								actual_out_buf_offset = copyToOutputBuf(output_buf, actual_out_buf_offset, str_file1, 0, str_len1, fwrite, &output_buf_offset);
								no_of_sorted_elements++;
								memset(last_out_buf_str, 0, BUFFER_SIZE);
								strcpy(last_out_buf_str, str_file1);
							} else if((args->flags & OPTION_ALREADY_SORTED) == OPTION_ALREADY_SORTED){
								printk("Flag t set and one of the file is unsorted\n");
								error_code = -EINVAL;
								goto clean_all;
							}
						}
						else{
							if(strcmp(str_file1, last_out_buf_str) > 0){
								printk("Copy to output_buf - %s\n", str_file1);
								actual_out_buf_offset = copyToOutputBuf(output_buf, actual_out_buf_offset, str_file1, 0, str_len1, fwrite, &output_buf_offset);
								no_of_sorted_elements++;
								memset(last_out_buf_str, 0, BUFFER_SIZE);
								strcpy(last_out_buf_str, str_file1);
							} else if((args->flags & OPTION_ALREADY_SORTED) == OPTION_ALREADY_SORTED){
								printk("Flag t set and one of the file is unsorted\n");
								error_code = -EINVAL;
								goto clean_all;
							}
						}
					
						str_len1 = getStringTillNextLine(data_buf_file1, &read_output_1, str_file1, &data_buf_offset1, fread1, &read1_offset);
						printk("String 1 - %s\n", str_file1);
				
					}else{
						//printk("Printing from file2 - %s\n", str_file2);
						if((args->flags & OPTION_DUPLICATES_ALLOWED) == OPTION_DUPLICATES_ALLOWED){
							if(strcmp(str_file2, last_out_buf_str) >= 0){
								printk("Copy to output_buf - %s\n", str_file2);
								actual_out_buf_offset = copyToOutputBuf(output_buf, actual_out_buf_offset, str_file2, 0, str_len2, fwrite, &output_buf_offset);
								no_of_sorted_elements++;
								memset(last_out_buf_str, 0, BUFFER_SIZE);
								strcpy(last_out_buf_str, str_file2);
							} else if((args->flags & OPTION_ALREADY_SORTED) == OPTION_ALREADY_SORTED){
								printk("Flag t set and one of the file is unsorted\n");
								error_code = -EINVAL;
								goto clean_all;
							}
						}
						else{
							if(strcmp(str_file2, last_out_buf_str) > 0){
								printk("Copy to output_buf - %s\n", str_file2);
								actual_out_buf_offset = copyToOutputBuf(output_buf, actual_out_buf_offset, str_file2, 0, str_len2, fwrite, &output_buf_offset);
								no_of_sorted_elements++;
								memset(last_out_buf_str, 0, BUFFER_SIZE);
								strcpy(last_out_buf_str, str_file2);
							} else if((args->flags & OPTION_ALREADY_SORTED) == OPTION_ALREADY_SORTED){
								printk("Flag t set and one of the file is unsorted\n");
								error_code = -EINVAL;
								goto clean_all;
							}
						}	
					
						str_len2 = getStringTillNextLine(data_buf_file2, &read_output_2, str_file2, &data_buf_offset2, fread2, &read2_offset);
						printk("String 2 - %s\n", str_file2);
					}

				}

				

		}
		//buff 1 is exhauseted, add string from buff 2 to output
		if(str_len1 == 0){

			if((args->flags & OPTION_CASE_INSENSITIVE_COMPARE) == OPTION_CASE_INSENSITIVE_COMPARE){

				if((args->flags & OPTION_DUPLICATES_ALLOWED) == OPTION_DUPLICATES_ALLOWED){
					if(strcasecmp(str_file2, last_out_buf_str) >= 0){
						printk("Copy to output_buf - %s\n", str_file2);
						actual_out_buf_offset = copyToOutputBuf(output_buf, actual_out_buf_offset, str_file2, 0, str_len2, fwrite, &output_buf_offset);
						no_of_sorted_elements++;
						memset(last_out_buf_str, 0, BUFFER_SIZE);
						strcpy(last_out_buf_str, str_file2);
					}
					else if((args->flags & OPTION_ALREADY_SORTED) == OPTION_ALREADY_SORTED){
							printk("Flag t set and one of the file is unsorted\n");
							error_code = -EINVAL;
							goto clean_all;
					}
				}
				else{
					if(strcasecmp(str_file2, last_out_buf_str) > 0){
						printk("Copy to output_buf - %s\n", str_file2);
						actual_out_buf_offset = copyToOutputBuf(output_buf, actual_out_buf_offset, str_file2, 0, str_len2, fwrite, &output_buf_offset);
						no_of_sorted_elements++;
						memset(last_out_buf_str, 0, BUFFER_SIZE);
						strcpy(last_out_buf_str, str_file2);
					}
					else if((args->flags & OPTION_ALREADY_SORTED) == OPTION_ALREADY_SORTED){
							printk("Flag t set and one of the file is unsorted\n");
							error_code = -EINVAL;
							goto clean_all;
					}
				}
				
			}
			else{

				if((args->flags & OPTION_DUPLICATES_ALLOWED) == OPTION_DUPLICATES_ALLOWED){
					if(strcasecmp(str_file2, last_out_buf_str) >= 0){
						printk("Copy to output_buf - %s\n", str_file2);
						actual_out_buf_offset = copyToOutputBuf(output_buf, actual_out_buf_offset, str_file2, 0, str_len2, fwrite, &output_buf_offset);
						no_of_sorted_elements++;
						memset(last_out_buf_str, 0, BUFFER_SIZE);
						strcpy(last_out_buf_str, str_file2);
					}
					else if((args->flags & OPTION_ALREADY_SORTED) == OPTION_ALREADY_SORTED){
							printk("Flag t set and one of the file is unsorted\n");
							error_code = -EINVAL;
							goto clean_all;
					}
				}
				else{
					if(strcasecmp(str_file2, last_out_buf_str) > 0){
						printk("Copy to output_buf - %s\n", str_file2);
						actual_out_buf_offset = copyToOutputBuf(output_buf, actual_out_buf_offset, str_file2, 0, str_len2, fwrite, &output_buf_offset);
						no_of_sorted_elements++;
						memset(last_out_buf_str, 0, BUFFER_SIZE);
						strcpy(last_out_buf_str, str_file2);
					}
					else if((args->flags & OPTION_ALREADY_SORTED) == OPTION_ALREADY_SORTED){
							printk("Flag t set and one of the file is unsorted\n");
							error_code = -EINVAL;
							goto clean_all;
					}
				}
				
			}
		}
		//buff 2 is exhauseted, add string from buff 1 to output
		if(str_len2 == 0){

			if((args->flags & OPTION_CASE_INSENSITIVE_COMPARE) == OPTION_CASE_INSENSITIVE_COMPARE){

				if((args->flags & OPTION_DUPLICATES_ALLOWED) == OPTION_DUPLICATES_ALLOWED){
					if(strcasecmp(str_file1, last_out_buf_str) >= 0){
						printk("Copy to output_buf - %s\n", str_file1);
						actual_out_buf_offset = copyToOutputBuf(output_buf, actual_out_buf_offset, str_file1, 0, str_len1, fwrite, &output_buf_offset);
						no_of_sorted_elements++;
						memset(last_out_buf_str, 0, BUFFER_SIZE);
						strcpy(last_out_buf_str, str_file1);
					}
					else if((args->flags & OPTION_ALREADY_SORTED) == OPTION_ALREADY_SORTED){
							printk("Flag t set and one of the file is unsorted\n");
							error_code = -EINVAL;
							goto clean_all;
					}
				}
				else{

					if(strcasecmp(str_file1, last_out_buf_str) > 0){
						printk("Copy to output_buf - %s\n", str_file1);
						actual_out_buf_offset = copyToOutputBuf(output_buf, actual_out_buf_offset, str_file1, 0, str_len1, fwrite, &output_buf_offset);
						no_of_sorted_elements++;
						memset(last_out_buf_str, 0, BUFFER_SIZE);
						strcpy(last_out_buf_str, str_file1);
					}
					else if((args->flags & OPTION_ALREADY_SORTED) == OPTION_ALREADY_SORTED){
							printk("Flag t set and one of the file is unsorted\n");
							error_code = -EINVAL;
							goto clean_all;
					}

				}
				
			}
			else{

				if((args->flags & OPTION_DUPLICATES_ALLOWED) == OPTION_DUPLICATES_ALLOWED){
					if(strcmp(str_file1, last_out_buf_str) >= 0){
						printk("Copy to output_buf - %s\n", str_file1);
						actual_out_buf_offset = copyToOutputBuf(output_buf, actual_out_buf_offset, str_file1, 0, str_len1, fwrite, &output_buf_offset);
						no_of_sorted_elements++;
						memset(last_out_buf_str, 0, BUFFER_SIZE);
						strcpy(last_out_buf_str, str_file1);
					}
					else if((args->flags & OPTION_ALREADY_SORTED) == OPTION_ALREADY_SORTED){
							printk("Flag t set and one of the file is unsorted\n");
							error_code = -EINVAL;
							goto clean_all;
					}
				}
				else{
					if(strcmp(str_file1, last_out_buf_str) > 0){
						printk("Copy to output_buf - %s\n", str_file1);
						actual_out_buf_offset = copyToOutputBuf(output_buf, actual_out_buf_offset, str_file1, 0, str_len1, fwrite, &output_buf_offset);
						no_of_sorted_elements++;
						memset(last_out_buf_str, 0, BUFFER_SIZE);
						strcpy(last_out_buf_str, str_file1);
					}
					else if((args->flags & OPTION_ALREADY_SORTED) == OPTION_ALREADY_SORTED){
							printk("Flag t set and one of the file is unsorted\n");
							error_code = -EINVAL;
							goto clean_all;
					}
				}
					
			}
		}
	}

	//while you still have data in buffer 1, flush it to output buffer
	while(data_buf_offset1  < read_output_1){
		str_len1 = getStringTillNextLine(data_buf_file1, &read_output_1, str_file1, &data_buf_offset1, fread1, &read1_offset);
		printk("No more data in buf 2\n");
		printk("String 1 - %s\n", str_file1);
		
		if((args->flags & OPTION_CASE_INSENSITIVE_COMPARE) == OPTION_CASE_INSENSITIVE_COMPARE){

			if((args->flags & OPTION_DUPLICATES_ALLOWED) == OPTION_DUPLICATES_ALLOWED){
				if(strcasecmp(str_file1, last_out_buf_str) >= 0){
					printk("Copy to output_buf - %s\n", str_file1);
					actual_out_buf_offset = copyToOutputBuf(output_buf, actual_out_buf_offset, str_file1, 0, str_len1, fwrite, &output_buf_offset);
					no_of_sorted_elements++;
					memset(last_out_buf_str, 0, BUFFER_SIZE);
					strcpy(last_out_buf_str, str_file1);
				}
				else if((args->flags & OPTION_ALREADY_SORTED) == OPTION_ALREADY_SORTED){
					printk("Flag t set and one of the file is unsorted\n");
					error_code = -EINVAL;
					goto clean_all;
				}	
			}
			else{
				if(strcasecmp(str_file1, last_out_buf_str) > 0){
					printk("Copy to output_buf - %s\n", str_file1);
					actual_out_buf_offset = copyToOutputBuf(output_buf, actual_out_buf_offset, str_file1, 0, str_len1, fwrite, &output_buf_offset);
					no_of_sorted_elements++;
					memset(last_out_buf_str, 0, BUFFER_SIZE);
					strcpy(last_out_buf_str, str_file1);
				}
				else if((args->flags & OPTION_ALREADY_SORTED) == OPTION_ALREADY_SORTED){
					printk("Flag t set and one of the file is unsorted\n");
					error_code = -EINVAL;
					goto clean_all;
				}
			}			
			
		}
		else{

			if((args->flags & OPTION_DUPLICATES_ALLOWED) == OPTION_DUPLICATES_ALLOWED){
				if(strcmp(str_file1, last_out_buf_str) >= 0){
					printk("Copy to output_buf - %s\n", str_file1);
					actual_out_buf_offset = copyToOutputBuf(output_buf, actual_out_buf_offset, str_file1, 0, str_len1, fwrite, &output_buf_offset);
					no_of_sorted_elements++;
					memset(last_out_buf_str, 0, BUFFER_SIZE);
					strcpy(last_out_buf_str, str_file1);
				}
				else if((args->flags & OPTION_ALREADY_SORTED) == OPTION_ALREADY_SORTED){
					printk("Flag t set and one of the file is unsorted\n");
					error_code = -EINVAL;
					goto clean_all;
				}	
			}
			else{
				if(strcmp(str_file1, last_out_buf_str) > 0){
					printk("Copy to output_buf - %s\n", str_file1);
					actual_out_buf_offset = copyToOutputBuf(output_buf, actual_out_buf_offset, str_file1, 0, str_len1, fwrite, &output_buf_offset);
					no_of_sorted_elements++;
					memset(last_out_buf_str, 0, BUFFER_SIZE);
					strcpy(last_out_buf_str, str_file1);
				}
				else if((args->flags & OPTION_ALREADY_SORTED) == OPTION_ALREADY_SORTED){
					printk("Flag t set and one of the file is unsorted\n");
					error_code = -EINVAL;
					goto clean_all;
				}
			}
			
		}				
	}
	//while you still have data in buffer 2, flush it to output buffer
	while(data_buf_offset2 < read_output_2){
		str_len2 = getStringTillNextLine(data_buf_file2, &read_output_2, str_file2, &data_buf_offset2, fread2, &read2_offset);
		printk("No more data in buf 1\n");
		printk("String 2 - %s\n", str_file2);
		
		if((args->flags & OPTION_CASE_INSENSITIVE_COMPARE) == OPTION_CASE_INSENSITIVE_COMPARE){
			if((args->flags & OPTION_DUPLICATES_ALLOWED) == OPTION_DUPLICATES_ALLOWED){
				if(strcasecmp(str_file2, last_out_buf_str) >= 0){
					printk("Copy to output_buf - %s\n", str_file1);
					actual_out_buf_offset = copyToOutputBuf(output_buf, actual_out_buf_offset, str_file2, 0, str_len2, fwrite, &output_buf_offset);
					no_of_sorted_elements++;
					memset(last_out_buf_str, 0, BUFFER_SIZE);
					strcpy(last_out_buf_str, str_file2);
				}
				else if((args->flags & OPTION_ALREADY_SORTED) == OPTION_ALREADY_SORTED){
					printk("Flag t set and one of the file is unsorted\n");
					error_code = -EINVAL;
					goto clean_all;
				}
			}
			else{
				if(strcasecmp(str_file2, last_out_buf_str) > 0){
					printk("Copy to output_buf - %s\n", str_file1);
					actual_out_buf_offset = copyToOutputBuf(output_buf, actual_out_buf_offset, str_file2, 0, str_len2, fwrite, &output_buf_offset);
					no_of_sorted_elements++;
					memset(last_out_buf_str, 0, BUFFER_SIZE);
					strcpy(last_out_buf_str, str_file2);
				}
				else if((args->flags & OPTION_ALREADY_SORTED) == OPTION_ALREADY_SORTED){
					printk("Flag t set and one of the file is unsorted\n");
					error_code = -EINVAL;
					goto clean_all;
				}
			}

			
		}
		else{

			if((args->flags & OPTION_DUPLICATES_ALLOWED) == OPTION_DUPLICATES_ALLOWED){
				if(strcmp(str_file2, last_out_buf_str) >= 0){
					printk("Copy to output_buf - %s\n", str_file1);
					actual_out_buf_offset = copyToOutputBuf(output_buf, actual_out_buf_offset, str_file2, 0, str_len2, fwrite, &output_buf_offset);
					no_of_sorted_elements++;
					memset(last_out_buf_str, 0, BUFFER_SIZE);
					strcpy(last_out_buf_str, str_file2);
				}
				else if((args->flags & OPTION_ALREADY_SORTED) == OPTION_ALREADY_SORTED){
					printk("Flag t set and one of the file is unsorted\n");
					error_code = -EINVAL;
					goto clean_all;
				}
			}
			else{
				if(strcmp(str_file2, last_out_buf_str) > 0){
					printk("Copy to output_buf - %s\n", str_file1);
					actual_out_buf_offset = copyToOutputBuf(output_buf, actual_out_buf_offset, str_file2, 0, str_len2, fwrite, &output_buf_offset);
					no_of_sorted_elements++;
					memset(last_out_buf_str, 0, BUFFER_SIZE);
					strcpy(last_out_buf_str, str_file2);
				}
				else if((args->flags & OPTION_ALREADY_SORTED) == OPTION_ALREADY_SORTED){
					printk("Flag t set and one of the file is unsorted\n");
					error_code = -EINVAL;
					goto clean_all;
				}
			}

				
		}
		
	}

	//Flush all the out buffer data if any
	if(actual_out_buf_offset != 0){
		//printk("%s\n", output_buf);
		write_output = file_write(fwrite, &output_buf_offset, output_buf, actual_out_buf_offset);
		output_buf_offset = output_buf_offset + write_output;
	}
	
	//If OPTION_RETURN_WRITTEN_RECORDS is set, write no_of_sorted_elements value to it
	if((args->flags & OPTION_RETURN_WRITTEN_RECORDS) == OPTION_RETURN_WRITTEN_RECORDS){
		//args->data = no_of_sorted_elements;
		if(copy_to_user(args->data, &no_of_sorted_elements, sizeof(int))){
			error_code = -EFAULT;
			goto clean_all;
		}
	}

	//close all files and free all the buffers
	file_close(&fread1);
	file_close(&fread2);
	file_close(&fwrite);

	kfree(data_buf_file1);
	kfree(data_buf_file2);
	kfree(str_file1);
	kfree(str_file2);
	kfree(output_buf);
	kfree(last_out_buf_str);
	return 0;


	clean_all:
		kfree(data_buf_file1);
		kfree(data_buf_file2);
		kfree(str_file1);
		kfree(str_file2);
		kfree(output_buf);
		kfree(last_out_buf_str);
		file_close(&fread1);
		file_close(&fwrite);
		
	lable_return:
		return error_code;
}

static int __init init_sys_xmergesort(void)
{
	printk("installed new sys_xmergesort module\n");
	if (sysptr == NULL)
		sysptr = xmergesort;
	return 0;
}
static void  __exit exit_sys_xmergesort(void)
{
	if (sysptr != NULL)
		sysptr = NULL;
	printk("removed sys_xmergesort module\n");
}
module_init(init_sys_xmergesort);
module_exit(exit_sys_xmergesort);
MODULE_LICENSE("GPL");

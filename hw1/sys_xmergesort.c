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
#include <linux/namei.h>
#include "sys_xmergesort.h"

/* Flag to allow printing debug statements. Please set this to 0 and rebuild
 this module to prevent printing debug messages
*/
#define DEBUGON		1
/* Flag to allow printing  
*/
#define BUFFER_SIZE PAGE_SIZE

asmlinkage extern long (*sysptr)(void *arg);

/**
* file_open() - Wrapper to open file
* @path - File path
* @flags - Open flags
* @rights - File writes when new file is created
* @fileptr - This stores the poiter to opened file
*/
int file_open(const char* path, int flags, int rights, struct file **filePtr)
{
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

/**
* file_close() - Wrapper to close file
* @file - The file to close
*/
void file_close(struct file **file) {
	if(*file != NULL)
    	filp_close(*file, NULL);
   	*file = NULL;
}

/**
* file_read() - Wrapper function to read from file.
* @file - File to read from.
* @offset - The starting offset
* @data - data buffer to read into
* @size - the size of data to read
*/
int file_read(struct file* file, unsigned long long offset, 
	unsigned char* data, unsigned int size) 
{
    mm_segment_t oldfs;
    int ret;

    oldfs = get_fs();
    set_fs(get_ds());

    ret = vfs_read(file, data, size, &offset);

    set_fs(oldfs);
    return ret;
}

/**
* file_write() - Wrapper function to write to file.
* @file - File to write to.
* @offset - The starting offset
* @data - data to write
* @size - the size of data to write
*/
int file_write(struct file *file, unsigned long long *offset, unsigned char *data, unsigned int size) {
    mm_segment_t oldfs;
    int ret;

    oldfs = get_fs();
    set_fs(get_ds());

    ret = vfs_write(file, data, size, offset);

    set_fs(oldfs);
    return ret;
}

/**
* getStringTillNextLine() - This functions extracts one line from buffer
* using \n delimeter and returns the number of characters in the string
* @data_buf - the buffer from which line is to be extracted
* @read_output_ - size of buffer
* @str_ - another buffer that will store the extracted line
* @data_buf_offset - the offset maintained for the @data_buf buffer
* @fread - the input file from which buffer is to be refilled
* @read_offset - the offset for the input file
*/
int getStringTillNextLine(char *data_buf, int *read_output_, char *str_, int *data_buf_offset, struct file *fread, unsigned long long *read_offset){
	int i = *data_buf_offset;
	char c = ' ';
	int str_count = 0;
	memset(str_, 0, BUFFER_SIZE);
	
	if(*read_output_ == 0){
		return 0;
	}

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
	*data_buf_offset = i+1;
	if(i == *read_output_){
		memset(data_buf, 0, BUFFER_SIZE);
		*data_buf_offset = 0;
		i = 0;
		*read_output_ = file_read(fread, *read_offset, data_buf, BUFFER_SIZE);
		if(*read_output_ > 0){
			*read_offset = *read_offset + *read_output_;
			i = 0;
			while(i < *read_output_){
				c = data_buf[i];
				if(c != '\n'){
					if(str_count == BUFFER_SIZE-2){
						break;
					}
					str_[str_count] = c;
					str_count++;
					i++;
				}
				else
					break;
			}
			*data_buf_offset = ++i;	
		}
		else{
			*data_buf_offset = 0;
		}
	}
	
	str_[str_count++] = '\n';
	str_[str_count++] = '\0';
	
	return str_count;
}


/**
* copyToOutputBuf() - This function copies the string to output buffer 
* or flushes the buffer to the output file if output buffer becomes full.
* @output_buf - The output buffer
* @actual_out_buf_offset - The offset for output buffer
* @str_file - The string to be pushed in output buffer
* @str_len - The length of string @str_file
* @fwrite -The output file to flush the output buffer is it gets full
* @output_buf_offset - The offset for output file
*/
int copyToOutputBuf(char *output_buf, int actual_out_buf_offset, char *str_file, int startIndex, int str_len, struct file *fwrite, unsigned long long *output_buf_offset){
	int i, write_output;
	
	//check if there is any space in output buf to accomodate the string
	if(BUFFER_SIZE - actual_out_buf_offset < str_len){
		//As there seems to be no space now,flush the output buf to output file
		//Clean the buffer and set offet to 0
		printk("buf length %zu\n", strlen(output_buf));
		printk("buf offset %d\n", actual_out_buf_offset);
		write_output = file_write(fwrite, output_buf_offset, output_buf, actual_out_buf_offset);
		//*output_buf_offset = *output_buf_offset + write_output;
		memset(output_buf, 0, BUFFER_SIZE);
		actual_out_buf_offset = 0;
	}
	//Do it -1 for now to eliminated the \0 used for string
	for(i = startIndex; i < (startIndex + str_len - 1); i++){
		output_buf[actual_out_buf_offset++] = str_file[i];
	}
	return actual_out_buf_offset;
}

/**
* CopyArgsToKernelSpace() - This function copies translates all the user-space struct and its members to kernel space
* @args - kernel-space argument structure
* @arg - user-space void structure
* @outFileName - Output FileName structure
* @inputFileName1 - Input FileName1 structure
* @inputFileName2 - Input FileName2 structure
*/
int CopyArgsToKernelSpace(XmergesortParams *args, void *arg, struct filename *outFileName, struct filename *inputFileName1, struct filename *inputFileName2){
	int returnValue = 0;//, i = 0, j = 0;
	XmergesortParams *source = (XmergesortParams *)arg;
	

	returnValue = copy_from_user(args, source, sizeof(XmergesortParams));
	if(returnValue != 0){
		printk("copy from the user - structure failed\n");
		goto label_clean_exit;
	}


	returnValue = copy_from_user(&args->flags, &source->flags, sizeof(int));
	if (0 != returnValue){
		printk("copy from the user - flags failed\n");
		goto label_clean_exit;
	}

	returnValue = copy_from_user(&args->input_filecount, &source->input_filecount, sizeof(int));
	if (0 != returnValue){
		printk("copy from the user - input filecount failed\n");
		goto label_clean_exit;
	}

	/* Use getname() to copy the input and output file names
		from user to kernel space */

	outFileName	= getname(source->output_filename);
	if (IS_ERR(outFileName)) {
		printk(KERN_ALERT "OutFile name copy failed \n");
		returnValue = PTR_ERR(outFileName);
		goto label_clean_exit;
	}
	args->output_filename = (char *)outFileName->name;

	inputFileName1 = getname(source->input_filenames[0]);
		if(IS_ERR(inputFileName1)) {
			printk(KERN_ALERT "InFile name copy failed \n");
			returnValue = PTR_ERR(inputFileName1);
			goto label_outfile_fail;
		}
		args->input_filenames[0] = (char *)inputFileName1->name;

	inputFileName2 = getname(source->input_filenames[1]);
		if(IS_ERR(inputFileName2)) {
			printk(KERN_ALERT "InFile name copy failed \n");
			returnValue = PTR_ERR(inputFileName2);
			goto label_inputFileName1_fail;
		}
		args->input_filenames[1] = (char *)inputFileName2->name;

	#ifdef DEBUGON
		printk(KERN_ALERT "Argument Parameters copied to kernel space \n");
	#endif

	return 0;

label_inputFileName1_fail:
	putname(inputFileName1);	
label_outfile_fail:
	putname(outFileName);
label_clean_exit:
	return returnValue;
}

/**
* ValidateArgument() - This function validates structure members passed from userspace
* @arg - userspace
*/
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

	if (args->input_filecount < 2 || args->input_filecount > 2 || !(access_ok(VERIFY_READ, args->input_filecount,
			sizeof(args->input_filecount)))) {
		returnValue = -EINVAL;
		printk("Input Filecount is not qual to 2...Not supported\n");
		goto label_invalid_arg;
	}

	if (args->output_filename == NULL || !(access_ok(VERIFY_READ, args->output_filename,
			sizeof(args->output_filename)))) {
		returnValue = -EINVAL;
		printk("Error in outputfilename Validation\n");
		goto label_invalid_arg;
	}

	for(i = 0; i < args->input_filecount; i++){
		if (args->input_filenames[i] == NULL || !(access_ok(VERIFY_READ, args->input_filenames[i],
			sizeof(args->input_filenames[i])))) {
				returnValue = -EINVAL;
				printk("Error in input_filename-%d Validation\n", i + 1);
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


/*
* xmergesort() - This function is the main syscall function that merges the 2 files
*
*/
asmlinkage long xmergesort(void *arg)
{
	
	int temp1 = 0, str_len1 = 0, str_len2 = 0, actual_out_buf_offset = 0, ret_unlink;
	unsigned int no_of_sorted_elements = 0;
	XmergesortParams *args = NULL;
	struct filename *outFileName = NULL, *inputFileName1 = NULL, *inputFileName2 = NULL;
	//set highest permission to output file so as you can replace it with the smallest
	//65535 - highest range value of unsigned short (data type of umode_t)
	umode_t output_filemode = 65535, input_filemode;
	
	unsigned char *data_buf_file1 = NULL, *data_buf_file2 = NULL, *str_file1 = NULL, *str_file2 = NULL, *output_buf = NULL, *last_out_buf_str = NULL;
	int data_buf_offset1 = 0, data_buf_offset2 = 0;
	int i = 0, error_code = 0, sample_first_file = 0, sample_second_file = 0, write_output = 0, read_output_1, read_output_2;
	int fwrite_return = 0, fread_return = 0, f_temp_write_return = 0;//, fread2_return = 0;
	unsigned long long read1_offset = 0, read2_offset = 0, output_buf_offset = 0;
		
	struct file *fwrite = NULL, *fread1 = NULL, *fread2 = NULL;
	struct file  *tempFilePtr 	= NULL;
	unsigned char *tempOutFile			= NULL;	

	mm_segment_t oldfs;

	error_code = ValidateArgument(arg);
	if(error_code != 0){
		#ifdef DEBUGON
			printk(KERN_ALERT "Invalid Arguement.  Error %d \n", error_code);
		#endif
		goto label_return;
	}


	args = kmalloc(sizeof(XmergesortParams), GFP_KERNEL);
	if(args == NULL){
		error_code = -ENOMEM;
		#ifdef DEBUGON
			printk(KERN_ALERT "Could not copy user args to kernel	\n");
		#endif
		goto label_return;
	}
	memset(args, 0, sizeof(XmergesortParams));

	error_code = CopyArgsToKernelSpace(args, arg, inputFileName1, inputFileName2, outFileName);
	if (0 != error_code) {
		#ifdef DEBUGON
			printk(KERN_ALERT "Could not copy arguements to Kernel Space");
		#endif
		goto label_clean_args;
	}
	
	data_buf_file1 = (unsigned char *)kmalloc(sizeof(unsigned char)*BUFFER_SIZE, GFP_KERNEL);
	if(data_buf_file1 == NULL){
		kfree(args);
		return -ENOMEM;
	}
	data_buf_file2 = (unsigned char *)kmalloc(sizeof(unsigned char)*BUFFER_SIZE, GFP_KERNEL);
	if(data_buf_file2 == NULL){
		kfree(data_buf_file1);
		kfree(args);
		return -ENOMEM;
	}
	str_file1 = (unsigned char *)kmalloc(sizeof(unsigned char)*BUFFER_SIZE, GFP_KERNEL);
	if(str_file1 == NULL){
		kfree(data_buf_file1);
		kfree(data_buf_file2);
		kfree(args);
		return -ENOMEM;
	}
	str_file2 = (unsigned char *)kmalloc(sizeof(unsigned char)*BUFFER_SIZE, GFP_KERNEL);
	if(str_file2 == NULL){
		kfree(data_buf_file1);
		kfree(data_buf_file2);
		kfree(str_file1);
		kfree(args);
		return -ENOMEM;
	}
	output_buf = (unsigned char *)kmalloc(sizeof(unsigned char)*BUFFER_SIZE, GFP_KERNEL);
	if(output_buf == NULL){
		kfree(data_buf_file1);
		kfree(data_buf_file2);
		kfree(str_file1);
		kfree(str_file2);
		kfree(args);
		return -ENOMEM;
	}
	last_out_buf_str = (unsigned char *)kmalloc(sizeof(unsigned char)*BUFFER_SIZE, GFP_KERNEL);
	if(last_out_buf_str == NULL){
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
	
	/* Create the name for the temporarty file in
		which data is to be written initially
	*/
	tempOutFile = (unsigned char *)kmalloc(strlen(args->output_filename) + 5,
					GFP_KERNEL);
	if(tempOutFile == NULL){
		kfree(data_buf_file1);
		kfree(data_buf_file2);
		kfree(str_file1);
		kfree(str_file2);
		kfree(args);
		kfree(output_buf);
		kfree(last_out_buf_str);
		return -ENOMEM;
	}

	memset(tempOutFile, 0, strlen(args->output_filename) + 5);

	strcpy(tempOutFile, args->output_filename);
	tempOutFile[strlen(args->output_filename)]		 = '.';
	tempOutFile[strlen(args->output_filename) + 1] = 't';
	tempOutFile[strlen(args->output_filename) + 2] = 'm';
	tempOutFile[strlen(args->output_filename) + 3] = 'p';
	tempOutFile[strlen(args->output_filename) + 4] = '\0';


	for(i = 0; i < args->input_filecount; i++){
		fread_return = file_open(args->input_filenames[i], O_RDONLY, 0, &fread1);
		if(fread_return < 0){
			#ifdef DEBUGON
				printk(KERN_INFO "Error opening input file %s:%d", args->input_filenames[i], fread_return);
			#endif
			error_code = fread_return;
			goto clean_all;
		}

		//get the input file credentials in input_filemode
		input_filemode = fread1->f_path.dentry->d_inode->i_mode;
		if(output_filemode > input_filemode){
			output_filemode = input_filemode;
		}
		file_close(&fread1);
	}

	f_temp_write_return = file_open(tempOutFile, O_RDWR | O_CREAT | O_TRUNC, output_filemode, &tempFilePtr);
	if(f_temp_write_return < 0){
		#ifdef DEBUGON
			printk(KERN_INFO "Error opening temporary file %s:%d", tempOutFile, f_temp_write_return);
		#endif
		error_code = f_temp_write_return;
		goto clean_all;
	}

	//Open first 2 files
	sample_first_file = file_open(args->input_filenames[0], O_RDONLY, 0, &fread1);
	sample_second_file = file_open(args->input_filenames[1], O_RDONLY, 0, &fread2);

	//Initially read page size buffer from both files
	read_output_1 = file_read(fread1, read1_offset, data_buf_file1, BUFFER_SIZE);
	read1_offset = read1_offset + read_output_1;
	read_output_2 = file_read(fread2, read2_offset, data_buf_file2, BUFFER_SIZE);
	read2_offset = read2_offset + read_output_2;


		str_len1 = getStringTillNextLine(data_buf_file1, &read_output_1, str_file1, &data_buf_offset1, fread1, &read1_offset);
		str_len2 = getStringTillNextLine(data_buf_file2, &read_output_2, str_file2, &data_buf_offset2, fread2, &read2_offset);
		
		//For debugging purpose I am running this loop for just 8 times
		//while( read_output_1 != 0 && read_output_2 != 0){//till the data buf exausts){
		while(str_len1 != 0 && str_len2 != 0){
				if(temp1 > 50)
					break;
				temp1++;
				
				if((args->flags & OPTION_CASE_INSENSITIVE_COMPARE) == OPTION_CASE_INSENSITIVE_COMPARE){
					if(strcasecmp(str_file1, str_file2) <= 0){

						if((args->flags & OPTION_DUPLICATES_ALLOWED) == OPTION_DUPLICATES_ALLOWED){
							if(strcasecmp(str_file1, last_out_buf_str) >= 0){
								
								actual_out_buf_offset = copyToOutputBuf(output_buf, actual_out_buf_offset, str_file1, 0, str_len1, tempFilePtr, &output_buf_offset);
								no_of_sorted_elements++;
								memset(last_out_buf_str, 0, BUFFER_SIZE);
								strcpy(last_out_buf_str, str_file1);
							} else if((args->flags & OPTION_ALREADY_SORTED) == OPTION_ALREADY_SORTED){
								#ifdef DEBUGON
									printk("Flag t set and one of the file is unsorted\n");
								#endif
								error_code = -EINVAL;
								goto label_partial_fail;
							}
						}
						else{
							
							if(strcasecmp(str_file1, last_out_buf_str) > 0){
							
								actual_out_buf_offset = copyToOutputBuf(output_buf, actual_out_buf_offset, str_file1, 0, str_len1, tempFilePtr, &output_buf_offset);
								no_of_sorted_elements++;
								memset(last_out_buf_str, 0, BUFFER_SIZE);
								strcpy(last_out_buf_str, str_file1);
							} else if((args->flags & OPTION_ALREADY_SORTED) == OPTION_ALREADY_SORTED){
								#ifdef DEBUGON
									printk("Flag t set and one of the file is unsorted\n");
								#endif
								error_code = -EINVAL;
								goto label_partial_fail;
							}
						}						
					
						str_len1 = getStringTillNextLine(data_buf_file1, &read_output_1, str_file1, &data_buf_offset1, fread1, &read1_offset);
						
				
					}else{
						
						if((args->flags & OPTION_DUPLICATES_ALLOWED) == OPTION_DUPLICATES_ALLOWED){
							
							if(strcasecmp(str_file2, last_out_buf_str) >= 0){
							
								actual_out_buf_offset = copyToOutputBuf(output_buf, actual_out_buf_offset, str_file2, 0, str_len2, tempFilePtr, &output_buf_offset);
								no_of_sorted_elements++;
								memset(last_out_buf_str, 0, BUFFER_SIZE);
								strcpy(last_out_buf_str, str_file2);
							} else if((args->flags & OPTION_ALREADY_SORTED) == OPTION_ALREADY_SORTED){
								#ifdef DEBUGON
									printk("Flag t set and one of the file is unsorted\n");
								#endif
								error_code = -EINVAL;
								goto label_partial_fail;
							}
						}
						else{
							
							if(strcasecmp(str_file2, last_out_buf_str) > 0){
								
								actual_out_buf_offset = copyToOutputBuf(output_buf, actual_out_buf_offset, str_file2, 0, str_len2, tempFilePtr, &output_buf_offset);
								no_of_sorted_elements++;
								memset(last_out_buf_str, 0, BUFFER_SIZE);
								strcpy(last_out_buf_str, str_file2);
							} else if((args->flags & OPTION_ALREADY_SORTED) == OPTION_ALREADY_SORTED){
								#ifdef DEBUGON
									printk("Flag t set and one of the file is unsorted\n");
								#endif
								error_code = -EINVAL;
								goto label_partial_fail;
							}
						}
					
						str_len2 = getStringTillNextLine(data_buf_file2, &read_output_2, str_file2, &data_buf_offset2, fread2, &read2_offset);
						
					}
				}
				else{
					
					if(strcmp(str_file1, str_file2) <= 0){

						if((args->flags & OPTION_DUPLICATES_ALLOWED) == OPTION_DUPLICATES_ALLOWED){
							
							if(strcmp(str_file1, last_out_buf_str) >= 0){
						
								actual_out_buf_offset = copyToOutputBuf(output_buf, actual_out_buf_offset, str_file1, 0, str_len1, tempFilePtr, &output_buf_offset);
								no_of_sorted_elements++;
								memset(last_out_buf_str, 0, BUFFER_SIZE);
								strcpy(last_out_buf_str, str_file1);
							} else if((args->flags & OPTION_ALREADY_SORTED) == OPTION_ALREADY_SORTED){
								#ifdef DEBUGON
									printk("Flag t set and one of the file is unsorted\n");
								#endif
								error_code = -EINVAL;
								goto label_partial_fail;
							}
						}
						else{
						
						
							if(strcmp(str_file1, last_out_buf_str) > 0){
						
								actual_out_buf_offset = copyToOutputBuf(output_buf, actual_out_buf_offset, str_file1, 0, str_len1, tempFilePtr, &output_buf_offset);
								no_of_sorted_elements++;
								memset(last_out_buf_str, 0, BUFFER_SIZE);
								strcpy(last_out_buf_str, str_file1);
							} else if((args->flags & OPTION_ALREADY_SORTED) == OPTION_ALREADY_SORTED){
								#ifdef DEBUGON
									printk("Flag t set and one of the file is unsorted\n");
								#endif
								error_code = -EINVAL;
								goto label_partial_fail;
							}
						}
					
						str_len1 = getStringTillNextLine(data_buf_file1, &read_output_1, str_file1, &data_buf_offset1, fread1, &read1_offset);
						
				
					}else{
						if((args->flags & OPTION_DUPLICATES_ALLOWED) == OPTION_DUPLICATES_ALLOWED){
						
						
							if(strcmp(str_file2, last_out_buf_str) >= 0){
						
								actual_out_buf_offset = copyToOutputBuf(output_buf, actual_out_buf_offset, str_file2, 0, str_len2, tempFilePtr, &output_buf_offset);
								no_of_sorted_elements++;
								memset(last_out_buf_str, 0, BUFFER_SIZE);
								strcpy(last_out_buf_str, str_file2);
							} else if((args->flags & OPTION_ALREADY_SORTED) == OPTION_ALREADY_SORTED){
								#ifdef DEBUGON
									printk("Flag t set and one of the file is unsorted\n");
								#endif
								error_code = -EINVAL;
								goto label_partial_fail;
							}
						}
						else{
					
							if(strcmp(str_file2, last_out_buf_str) > 0){
					
								actual_out_buf_offset = copyToOutputBuf(output_buf, actual_out_buf_offset, str_file2, 0, str_len2, tempFilePtr, &output_buf_offset);
								no_of_sorted_elements++;
								memset(last_out_buf_str, 0, BUFFER_SIZE);
								strcpy(last_out_buf_str, str_file2);
							} else if((args->flags & OPTION_ALREADY_SORTED) == OPTION_ALREADY_SORTED){
								#ifdef DEBUGON
									printk("Flag t set and one of the file is unsorted\n");
								#endif
								error_code = -EINVAL;
								goto label_partial_fail;
							}
						}	
					
						str_len2 = getStringTillNextLine(data_buf_file2, &read_output_2, str_file2, &data_buf_offset2, fread2, &read2_offset);
						
					}

				}

		}
		
		//one of the str_file string has a word. Push it to output as the other buffer is totally explored.
		if(strlen(str_file1) != 0){
			actual_out_buf_offset = copyToOutputBuf(output_buf, actual_out_buf_offset, str_file1, 0, str_len1, tempFilePtr, &output_buf_offset);
			no_of_sorted_elements++;
			memset(last_out_buf_str, 0, BUFFER_SIZE);
			strcpy(last_out_buf_str, str_file1);

		}
		if(strlen(str_file2) != 0){
			actual_out_buf_offset = copyToOutputBuf(output_buf, actual_out_buf_offset, str_file2, 0, str_len2, tempFilePtr, &output_buf_offset);
			no_of_sorted_elements++;
			memset(last_out_buf_str, 0, BUFFER_SIZE);
			strcpy(last_out_buf_str, str_file2);
		}


	//while you still have data in buffer 1, flush it to output buffer
	while(data_buf_offset1  < read_output_1){
		str_len1 = getStringTillNextLine(data_buf_file1, &read_output_1, str_file1, &data_buf_offset1, fread1, &read1_offset);
		
		
		if((args->flags & OPTION_CASE_INSENSITIVE_COMPARE) == OPTION_CASE_INSENSITIVE_COMPARE){

			if((args->flags & OPTION_DUPLICATES_ALLOWED) == OPTION_DUPLICATES_ALLOWED){
				if(strcasecmp(str_file1, last_out_buf_str) >= 0){
					
					actual_out_buf_offset = copyToOutputBuf(output_buf, actual_out_buf_offset, str_file1, 0, str_len1, tempFilePtr, &output_buf_offset);
					no_of_sorted_elements++;
					memset(last_out_buf_str, 0, BUFFER_SIZE);
					strcpy(last_out_buf_str, str_file1);
				}
				else if((args->flags & OPTION_ALREADY_SORTED) == OPTION_ALREADY_SORTED){
					#ifdef DEBUGON
						printk("Flag t set and one of the file is unsorted\n");
					#endif
					error_code = -EINVAL;
					goto label_partial_fail;
				}	
			}
			else{
				if(strcasecmp(str_file1, last_out_buf_str) > 0){
					
					actual_out_buf_offset = copyToOutputBuf(output_buf, actual_out_buf_offset, str_file1, 0, str_len1, tempFilePtr, &output_buf_offset);
					no_of_sorted_elements++;
					memset(last_out_buf_str, 0, BUFFER_SIZE);
					strcpy(last_out_buf_str, str_file1);
				}
				else if((args->flags & OPTION_ALREADY_SORTED) == OPTION_ALREADY_SORTED){
					#ifdef DEBUGON
						printk("Flag t set and one of the file is unsorted\n");
					#endif
					error_code = -EINVAL;
					goto label_partial_fail;
				}
			}			
		}
		else{

			if((args->flags & OPTION_DUPLICATES_ALLOWED) == OPTION_DUPLICATES_ALLOWED){
				if(strcmp(str_file1, last_out_buf_str) >= 0){
					
					actual_out_buf_offset = copyToOutputBuf(output_buf, actual_out_buf_offset, str_file1, 0, str_len1, tempFilePtr, &output_buf_offset);
					no_of_sorted_elements++;
					memset(last_out_buf_str, 0, BUFFER_SIZE);
					strcpy(last_out_buf_str, str_file1);
				}
				else if((args->flags & OPTION_ALREADY_SORTED) == OPTION_ALREADY_SORTED){
					#ifdef DEBUGON
						printk("Flag t set and one of the file is unsorted\n");
					#endif
					error_code = -EINVAL;
					goto label_partial_fail;
				}	
			}
			else{
				if(strcmp(str_file1, last_out_buf_str) > 0){
					
					actual_out_buf_offset = copyToOutputBuf(output_buf, actual_out_buf_offset, str_file1, 0, str_len1, tempFilePtr, &output_buf_offset);
					no_of_sorted_elements++;
					memset(last_out_buf_str, 0, BUFFER_SIZE);
					strcpy(last_out_buf_str, str_file1);
				}
				else if((args->flags & OPTION_ALREADY_SORTED) == OPTION_ALREADY_SORTED){
					#ifdef DEBUGON
						printk("Flag t set and one of the file is unsorted\n");
					#endif
					error_code = -EINVAL;
					goto label_partial_fail;
				}
			}
			
		}				
	}
	//while you still have data in buffer 2, flush it to output buffer
	while(data_buf_offset2 < read_output_2){
		str_len2 = getStringTillNextLine(data_buf_file2, &read_output_2, str_file2, &data_buf_offset2, fread2, &read2_offset);
		
		if((args->flags & OPTION_CASE_INSENSITIVE_COMPARE) == OPTION_CASE_INSENSITIVE_COMPARE){
			if((args->flags & OPTION_DUPLICATES_ALLOWED) == OPTION_DUPLICATES_ALLOWED){
				if(strcasecmp(str_file2, last_out_buf_str) >= 0){
					
					actual_out_buf_offset = copyToOutputBuf(output_buf, actual_out_buf_offset, str_file2, 0, str_len2, tempFilePtr, &output_buf_offset);
					no_of_sorted_elements++;
					memset(last_out_buf_str, 0, BUFFER_SIZE);
					strcpy(last_out_buf_str, str_file2);
				}
				else if((args->flags & OPTION_ALREADY_SORTED) == OPTION_ALREADY_SORTED){
					#ifdef DEBUGON
						printk("Flag t set and one of the file is unsorted\n");
					#endif
					error_code = -EINVAL;
					goto label_partial_fail;
				}
			}
			else{
				if(strcasecmp(str_file2, last_out_buf_str) > 0){
					
					actual_out_buf_offset = copyToOutputBuf(output_buf, actual_out_buf_offset, str_file2, 0, str_len2, tempFilePtr, &output_buf_offset);
					no_of_sorted_elements++;
					memset(last_out_buf_str, 0, BUFFER_SIZE);
					strcpy(last_out_buf_str, str_file2);
				}
				else if((args->flags & OPTION_ALREADY_SORTED) == OPTION_ALREADY_SORTED){
					#ifdef DEBUGON
						printk("Flag t set and one of the file is unsorted\n");
					#endif
					error_code = -EINVAL;
					goto label_partial_fail;
				}
			}

			
		}
		else{

			if((args->flags & OPTION_DUPLICATES_ALLOWED) == OPTION_DUPLICATES_ALLOWED){
				if(strcmp(str_file2, last_out_buf_str) >= 0){
					
					actual_out_buf_offset = copyToOutputBuf(output_buf, actual_out_buf_offset, str_file2, 0, str_len2, tempFilePtr, &output_buf_offset);
					no_of_sorted_elements++;
					memset(last_out_buf_str, 0, BUFFER_SIZE);
					strcpy(last_out_buf_str, str_file2);
				}
				else if((args->flags & OPTION_ALREADY_SORTED) == OPTION_ALREADY_SORTED){
					#ifdef DEBUGON
						printk("Flag t set and one of the file is unsorted\n");
					#endif
					error_code = -EINVAL;
					goto label_partial_fail;
				}
			}
			else{
				if(strcmp(str_file2, last_out_buf_str) > 0){
					
					actual_out_buf_offset = copyToOutputBuf(output_buf, actual_out_buf_offset, str_file2, 0, str_len2, tempFilePtr, &output_buf_offset);
					no_of_sorted_elements++;
					memset(last_out_buf_str, 0, BUFFER_SIZE);
					strcpy(last_out_buf_str, str_file2);
				}
				else if((args->flags & OPTION_ALREADY_SORTED) == OPTION_ALREADY_SORTED){
					#ifdef DEBUGON
						printk("Flag t set and one of the file is unsorted\n");
					#endif
					error_code = -EINVAL;
					goto label_partial_fail;
				}
			}

				
		}
		
	}

	//Flush all the out buffer data if any
	if(actual_out_buf_offset != 0){
		printk("buf length %zu\n", strlen(output_buf));
		printk("buf offset %d\n", actual_out_buf_offset);
		write_output = file_write(tempFilePtr, &output_buf_offset, output_buf, actual_out_buf_offset);
		//output_buf_offset = output_buf_offset + write_output;
	}
	
	//If OPTION_RETURN_WRITTEN_RECORDS is set, write no_of_sorted_elements value to it
	if((args->flags & OPTION_RETURN_WRITTEN_RECORDS) == OPTION_RETURN_WRITTEN_RECORDS){
		if(copy_to_user(args->data, &no_of_sorted_elements, sizeof(unsigned int))){
			#ifdef DEBUGON
				printk("Copy to user of data member failed. \n");
			#endif
			error_code = -EFAULT;
			goto label_partial_fail;
		}
	}

	fwrite_return = file_open(args->output_filename, O_RDWR | O_CREAT, 00777, &fwrite);
	if(fwrite_return < 0){
		#ifdef DEBUGON
			printk(KERN_INFO "Error opening output file %s:%d", args->output_filename, fwrite_return);
		#endif
		error_code = fwrite_return;
		goto label_partial_fail;
	}
	/* Rename the temporary output file to the final output file.
		 Obtain the lock on the parent of the files. The following
			implementation is adabted from
		 ~/source/fs/wrapfs/inode.c
		 and has been changed as per needs of assignment
	*/
	#ifdef DEBUGON
		printk("Renaming the temp file to actual output file.\n");
	#endif
	lock_rename(tempFilePtr->f_path.dentry->d_parent,
				fwrite->f_path.dentry->d_parent);

	oldfs = get_fs();
	set_fs(KERNEL_DS);

	error_code = vfs_rename(tempFilePtr->f_path.dentry->d_parent->d_inode,
			tempFilePtr->f_path.dentry,
			fwrite->f_path.dentry->d_parent->d_inode,
			fwrite->f_path.dentry, NULL, 0);

	set_fs(oldfs);

	unlock_rename(tempFilePtr->f_path.dentry->d_parent,
				fwrite->f_path.dentry->d_parent);

	if (error_code) {
		printk(KERN_ALERT "Error in rename temp file to permenant output file\n");
		goto label_rename_file_fail;
	}

	#ifdef DEBUGON
		printk(KERN_INFO "done with renaming...\n");
	#endif
	
	//close all files and free all the buffers
	file_close(&fread1);
	file_close(&fread2);
	file_close(&fwrite);
	file_close(&tempFilePtr);

	if(data_buf_file1){
		kfree(data_buf_file1);
	}
	if(data_buf_file2){
		kfree(data_buf_file2);
	}
	if(str_file1){
		kfree(str_file1);
	}
	if(str_file2){
		kfree(str_file2);
	}
	if(output_buf){
		kfree(output_buf);
	}
	if(last_out_buf_str){
		kfree(last_out_buf_str);
	}
	if(inputFileName1){
		putname(inputFileName1);
	}
	if(inputFileName2){
		putname(inputFileName2);
	}
	if(outFileName)	{
		putname(outFileName);
	}

	if(args){
		kfree(args);
	}
	if(tempOutFile){
		kfree(tempOutFile);
	}
	return 0;

label_rename_file_fail:
	#ifdef DEBUGON
		printk(KERN_ALERT "Deleting output file\n");
	#endif
	/* In case of partial failure, the temporary file is
		supposed to be removed
	*/
	oldfs = get_fs();
	set_fs(KERNEL_DS);
	ret_unlink = vfs_unlink(fwrite->f_path.dentry->d_parent->d_inode,
					 fwrite->f_path.dentry, NULL);
	set_fs(oldfs);
	if(ret_unlink)
		printk(KERN_ALERT "Could not unlink output file \n");
	file_close(&fwrite);

label_partial_fail:
	#ifdef DEBUGON
		printk(KERN_ALERT "Deleting file %s \n", tempOutFile);
	#endif
	/* In case of partial failure, the temporary file is
		supposed to be removed
	*/
	oldfs = get_fs();
	set_fs(KERNEL_DS);
	ret_unlink = vfs_unlink(tempFilePtr->f_path.dentry->d_parent->d_inode,
					 tempFilePtr->f_path.dentry, NULL);
	set_fs(oldfs);
	if(ret_unlink)
		#ifdef DEBUGON
			printk(KERN_ALERT "Could not unlink temp file \n");
		#endif
	file_close(&tempFilePtr);

clean_all:
	if(data_buf_file1)
		kfree(data_buf_file1);
	if(data_buf_file2)
		kfree(data_buf_file2);
	if(str_file1)
		kfree(str_file1);
	if(str_file2)
		kfree(str_file2);
	if(output_buf)
		kfree(output_buf);
	if(last_out_buf_str)
		kfree(last_out_buf_str);
	if(tempOutFile)
		kfree(tempOutFile);
		file_close(&fread1);
		file_close(&fread2);
		#ifdef DEBUGON
			printk("Cleaning all the kernel space struct argument members as well\n");
		#endif
	if(inputFileName1)
		putname(inputFileName1);
	if(inputFileName2)
		putname(inputFileName2);
	if(outFileName)	
		putname(outFileName);

label_clean_args:
		#ifdef DEBUGON
			printk(KERN_ALERT "Cleaned the kernel space struct argument member\n");
		#endif
		if(args)
			kfree(args);
		
label_return:
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

#include <linux/linkage.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <asm/uaccess.h>
#include <asm/segment.h>
#include <asm/page.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/moduleloader.h>
#include <linux/buffer_head.h>

#define BUFFER_SIZE PAGE_SIZE

struct my_args {
	char **input_filenames;
	unsigned int flags;
	char *output_filename;
	int input_filecount;	
	unsigned int *data;
};

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

asmlinkage long xmergesort(void *arg)
{
	//CONVERT received argument structure to its required struct i.e. my_argsread_output_1
	struct my_args *args = (struct my_args *) arg;
	unsigned char *data_buf_file1 = NULL, *data_buf_file2 = NULL;//, *outputFileBuffer = NULL;
	int i = 0, error_code = 0, write_output = 0, sample_first_file = 0, sample_second_file = 0, read_output_1, read_output_2;
	int fwrite_return = 0, fread1_return = 0;//, fread2_return = 0;
	unsigned long long pos = 0;
		
	struct file *fwrite = NULL, *fread1 = NULL, *fread2 = NULL;	

	//printk("IIII AMMMM HEERERERERERR\n");
	//If received arg is NULL or input number of files is less than 2, flag invalid argument error
	if(arg == NULL || args->input_filecount < 2)
		return -EINVAL;

	//If received arg has filecount > 10, flag EDOM - Math argument out of domain of func error
	if(args->input_filecount > 10)
		return -EDOM;
	// dummy syscall: returns 0 for non null, -EINVAL for NULL
	
	
	//mm_segment_t fs;
	//unsigned char data_buf[BUFFER_SIZE];  
	data_buf_file1 = (char *)kmalloc(sizeof(char)*BUFFER_SIZE, GFP_KERNEL);
	if(!data_buf_file1)
		return -ENOMEM;
	data_buf_file2 = (char *)kmalloc(sizeof(char)*BUFFER_SIZE, GFP_KERNEL);
	if(!data_buf_file2)
		return -ENOMEM;

	//output_file_permissions = output_file_permissions | S_IRUSR | S_IWUSR | S_IXUSR;
	fwrite_return = file_open(args->output_filename, O_RDWR | O_CREAT, S_IWUSR | S_IRUSR, &fwrite);
	if(fwrite_return < 0){
		printk(KERN_INFO "Error opening output file %s:%d", args->output_filename, fwrite_return);
		error_code = fwrite_return;
		goto clean_all;
	}


	for(i = 0; i < args->input_filecount; i++){
		fread1_return = file_open(args->input_filenames[i], O_RDONLY, 0, &fread1);
		if(fread1_return < 0){
			printk(KERN_INFO "Error opening input file %s:%d", args->input_filenames[i], fread1_return);
			error_code = fread1_return;
			goto clean_all;
		}
		if(fread1->f_inode == fwrite->f_inode){
			fread1_return = -EPERM;
			error_code = fread1_return;
			goto clean_all;
		}
		file_close(&fread1);
	}
	//file_close(&fwrite);
	
	sample_first_file = file_open(args->input_filenames[0], O_RDONLY, 0, &fread1);
	sample_second_file = file_open(args->input_filenames[1], O_RDONLY, 0, &fread2);
	read_output_1 = file_read(fread1, 0, data_buf_file1, PAGE_SIZE);		
	//printk("Number of bytes read from %s- %d\n", args->input_filenames[0], read_output1);
	read_output_2 = file_read(fread2, 0, data_buf_file2, PAGE_SIZE);
	

	write_output = file_write(fwrite, &pos, data_buf_file1, read_output_1);
	pos = pos + read_output_1;
	printk("I am heererererere!! OFFSET is %llud\n", pos);
	write_output = write_output + file_write(fwrite, &pos, data_buf_file2, read_output_2);
	//loff_t = loff_t + write_output;
	//printk("Number of bytes written in %s - %d\n", args->output_filename, write_output);
	file_close(&fread1);
	file_close(&fread2);
	file_close(&fwrite);
	//printk("args %p\n", args);
	return 0;

	clean_all:
		kfree(data_buf_file1);
		kfree(data_buf_file2);
		file_close(&fwrite);
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

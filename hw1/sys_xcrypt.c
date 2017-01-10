#include <linux/linkage.h>
#include <linux/moduleloader.h>

asmlinkage extern long (*sysptr)(void *arg);

asmlinkage long xcrypt(void *arg)
{
	/* dummy syscall: returns 0 for non null, -EINVAL for NULL */
	printk("xcrypt received arg %p\n", arg);
	if (arg == NULL)
		return -EINVAL;
	else
		return 0;
}

static int __init init_sys_xcrypt(void)
{
	printk("installed new sys_xcrypt module\n");
	if (sysptr == NULL)
		sysptr = xcrypt;
	return 0;
}
static void  __exit exit_sys_xcrypt(void)
{
	if (sysptr != NULL)
		sysptr = NULL;
	printk("removed sys_xcrypt module\n");
}
module_init(init_sys_xcrypt);
module_exit(exit_sys_xcrypt);
MODULE_LICENSE("GPL");

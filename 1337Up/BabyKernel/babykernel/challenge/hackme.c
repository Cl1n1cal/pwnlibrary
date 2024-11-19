/* 

 * hello-1.c - The simplest kernel module. 

 */ 
#define MODULE
#define LINUX

#include <linux/init.h>
#include <linux/module.h> /* Needed by all modules */ 
#include <linux/kernel.h> /* Needed for pr_info() */ 

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("A Simple Hello World Module");
MODULE_VERSION("1.0"); 

static int __init module_start(void) 

{ 

    printk(KERN_INFO "Hello world 1.\n"); 

 

    /* A non 0 return means init_module failed; module can't be loaded. */ 

    return 0; 

} 

 

static void __exit module_end(void) 

{ 

    printk(KERN_INFO "Goodbye world 1.\n"); 

} 
module_init(module_start);
module_exit(module_end);
 

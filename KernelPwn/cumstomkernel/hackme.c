#include <linux/init.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/uaccess.h> // For copy_to_user and copy_from_user
#include <linux/slab.h>    // For kmalloc and kfree

#define DEVICE_NAME "hackme"
#define BUF_SIZE 64

MODULE_LICENSE("GPL");
MODULE_AUTHOR("CTF Creator");
MODULE_DESCRIPTION("A vulnerable kernel module for CTF challenges");
MODULE_VERSION("1.0");

static char *hackme_buf;
static int major;

// Function prototypes
ssize_t hackme_read(struct file *f, char __user *data, size_t size, loff_t *off);
ssize_t hackme_write(struct file *f, const char __user *data, size_t size, loff_t *off);

ssize_t hackme_read(struct file *f, char __user *data, size_t size, loff_t *off) {
    unsigned long vulnbuf[8];

    // Just gonna put some values into vulnbuf to make understanding array layout easier
    size_t vuln_size = sizeof(vulnbuf)/sizeof(unsigned long);
    for(int i = 0; i < vuln_size; i++) {
        vulnbuf[i] = i;
    }

    pr_info("hackme_read\n"); // pr_info is prkern() with info level enabled
    if (size > 0x1000) { // Intentionally larger than bufsize of 8
        pr_warn("Buffer overflow detected in read! (%lu > %d)\n", size, BUF_SIZE);
        return -EFAULT; // Return failure if size exceeds buffer
    }

    if (raw_copy_to_user(data, vulnbuf, size)) {
        pr_warn("Failed to copy data to user space\n");
        return -EFAULT;
    }

    pr_info("Data read: %s\n", hackme_buf);
    return size;
}

ssize_t hackme_write(struct file *f, const char __user *data, size_t size, loff_t *off) {
    pr_info("hackme_write");
    unsigned long vulnbuf[8]; // Size: 8*4 = 32 bytes. Intentionally small buffer for overflow


    if (size > 0x1000) { // Intentionally larger than the buffer
        pr_warn("Buffer overflow detected in write! (%lu > %d)\n", size, BUF_SIZE);
        return -EFAULT; // Return failure if size exceeds buffer
    }

    if (raw_copy_from_user(vulnbuf, data, size)) {
        pr_warn("Failed to copy data from user space\n");
        return -EFAULT;
    }

    // Vulnerability: Unchecked memory copy
    //memcpy(vulnbuf, hackme_buf, size);

    //pr_info("Data written: %s\n", hackme_buf);
    return size;
}

static struct file_operations fops = {
    .read = hackme_read,
    .write = hackme_write,
};

static int __init hackme_init(void) {
    major = register_chrdev(0, DEVICE_NAME, &fops);
    if (major < 0) {
        pr_err("Failed to register device\n");
        return major;
    }

    hackme_buf = kmalloc(BUF_SIZE, GFP_KERNEL);
    if (!hackme_buf) {
        unregister_chrdev(major, DEVICE_NAME);
        pr_err("Failed to allocate memory\n");
        return -ENOMEM;
    }

    pr_info("Hackme module loaded! Major number: %d\n", major);
    return 0;
}

static void __exit hackme_exit(void) {
    kfree(hackme_buf);
    unregister_chrdev(major, DEVICE_NAME);
    pr_info("Hackme module unloaded\n");
}

module_init(hackme_init);
module_exit(hackme_exit);

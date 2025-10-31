// vmem_module.c
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/device.h>
#include <linux/cdev.h>
#include <linux/io.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/sched.h>
#include <linux/mm_types.h>
#include <linux/pgtable.h>

#define DEVICE_NAME "vmem"
#define CLASS_NAME "vmem"
#define MAX_DEVICES 1
#define MAX_READ_SIZE 4096

static int major_number;
static struct class* vmem_class = NULL;
static struct device* vmem_device = NULL;
static struct cdev vmem_cdev;

// IOCTL命令定义
#define VMEM_MAGIC 'v'
#define VMEM_READ _IOR(VMEM_MAGIC, 1, struct vmem_ioctl_data)
#define VMEM_WRITE _IOW(VMEM_MAGIC, 2, struct vmem_ioctl_data)
#define VMEM_GET_PHYS _IOR(VMEM_MAGIC, 3, struct vmem_ioctl_data)
#define VMEM_READ_PROCESS _IOWR(VMEM_MAGIC, 4, struct vmem_ioctl_data)

struct vmem_ioctl_data {
    unsigned long vaddr;
    unsigned long paddr;
    unsigned long size;
    unsigned long pid;
    void __user *user_buf;
};

// 通过PID查找进程
static struct task_struct *find_process_by_pid(pid_t pid)
{
    struct task_struct *task;
    
    if (pid == 0) {
        return current; // 当前进程
    }
    
    rcu_read_lock();
    task = pid_task(find_vpid(pid), PIDTYPE_PID);
    rcu_read_unlock();
    
    return task;
}

// 虚拟地址到物理地址转换
static unsigned long virt_to_phys_user(struct mm_struct *mm, unsigned long vaddr)
{
    pgd_t *pgd;
    p4d_t *p4d;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *pte;
    struct page *page;
    unsigned long paddr = 0;
    
    if (!mm) {
        return 0;
    }
    
    // 遍历页表
    pgd = pgd_offset(mm, vaddr);
    if (pgd_none(*pgd) || pgd_bad(*pgd)) {
        return 0;
    }
    
    p4d = p4d_offset(pgd, vaddr);
    if (p4d_none(*p4d) || p4d_bad(*p4d)) {
        return 0;
    }
    
    pud = pud_offset(p4d, vaddr);
    if (pud_none(*pud) || pud_bad(*pud)) {
        return 0;
    }
    
    pmd = pmd_offset(pud, vaddr);
    if (pmd_none(*pmd) || pmd_bad(*pmd)) {
        return 0;
    }
    
    pte = pte_offset_map(pmd, vaddr);
    if (!pte || pte_none(*pte)) {
        return 0;
    }
    
    if (pte_present(*pte)) {
        page = pte_page(*pte);
        if (page) {
            paddr = page_to_phys(page) | (vaddr & ~PAGE_MASK);
        }
    }
    
    pte_unmap(pte);
    return paddr;
}

// 读取进程内存
static int read_process_memory(struct task_struct *task, unsigned long vaddr, 
                              void *buffer, size_t size)
{
    struct mm_struct *mm;
    int ret = 0;
    unsigned long paddr;
    void __iomem *kvaddr;
    
    if (!task || !buffer) {
        return -EINVAL;
    }
    
    mm = get_task_mm(task);
    if (!mm) {
        return -EINVAL;
    }
    
    down_read(&mm->mmap_sem);
    
    // 首先尝试直接读取用户空间内存
    if (access_ok((void __user *)vaddr, size)) {
        if (copy_from_user(buffer, (void __user *)vaddr, size) == 0) {
            ret = size;
        } else {
            ret = -EFAULT;
        }
    } else {
        // 如果直接访问失败，尝试通过物理地址映射
        paddr = virt_to_phys_user(mm, vaddr);
        if (paddr) {
            kvaddr = ioremap(paddr, size);
            if (kvaddr) {
                memcpy(buffer, kvaddr, size);
                iounmap(kvaddr);
                ret = size;
            } else {
                ret = -EIO;
            }
        } else {
            ret = -EFAULT;
        }
    }
    
    up_read(&mm->mmap_sem);
    mmput(mm);
    
    return ret;
}

// 写入进程内存
static int write_process_memory(struct task_struct *task, unsigned long vaddr,
                               const void *buffer, size_t size)
{
    struct mm_struct *mm;
    int ret = 0;
    unsigned long paddr;
    void __iomem *kvaddr;
    
    if (!task || !buffer) {
        return -EINVAL;
    }
    
    mm = get_task_mm(task);
    if (!mm) {
        return -EINVAL;
    }
    
    down_read(&mm->mmap_sem);
    
    if (access_ok((void __user *)vaddr, size)) {
        if (copy_to_user((void __user *)vaddr, buffer, size) == 0) {
            ret = size;
        } else {
            ret = -EFAULT;
        }
    } else {
        paddr = virt_to_phys_user(mm, vaddr);
        if (paddr) {
            kvaddr = ioremap(paddr, size);
            if (kvaddr) {
                memcpy(kvaddr, buffer, size);
                iounmap(kvaddr);
                ret = size;
            } else {
                ret = -EIO;
            }
        } else {
            ret = -EFAULT;
        }
    }
    
    up_read(&mm->mmap_sem);
    mmput(mm);
    
    return ret;
}

static long vmem_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    struct vmem_ioctl_data data;
    struct task_struct *task;
    char *kernel_buf = NULL;
    int ret = 0;
    
    if (copy_from_user(&data, (void __user *)arg, sizeof(data))) {
        return -EFAULT;
    }
    
    // 限制读取大小
    if (data.size > MAX_READ_SIZE) {
        return -EINVAL;
    }
    
    switch (cmd) {
    case VMEM_READ:
        // 读取当前进程内存
        kernel_buf = kmalloc(data.size, GFP_KERNEL);
        if (!kernel_buf) {
            return -ENOMEM;
        }
        
        ret = read_process_memory(current, data.vaddr, kernel_buf, data.size);
        if (ret > 0) {
            if (copy_to_user(data.user_buf, kernel_buf, data.size)) {
                ret = -EFAULT;
            }
        }
        
        kfree(kernel_buf);
        break;
        
    case VMEM_WRITE:
        // 写入当前进程内存
        kernel_buf = kmalloc(data.size, GFP_KERNEL);
        if (!kernel_buf) {
            return -ENOMEM;
        }
        
        if (copy_from_user(kernel_buf, data.user_buf, data.size)) {
            kfree(kernel_buf);
            return -EFAULT;
        }
        
        ret = write_process_memory(current, data.vaddr, kernel_buf, data.size);
        kfree(kernel_buf);
        break;
        
    case VMEM_GET_PHYS:
        // 获取虚拟地址对应的物理地址
        task = find_process_by_pid(data.pid);
        if (!task) {
            return -ESRCH;
        }
        
        {
            struct mm_struct *mm = get_task_mm(task);
            if (mm) {
                down_read(&mm->mmap_sem);
                data.paddr = virt_to_phys_user(mm, data.vaddr);
                up_read(&mm->mmap_sem);
                mmput(mm);
            }
        }
        
        if (copy_to_user((void __user *)arg, &data, sizeof(data))) {
            return -EFAULT;
        }
        break;
        
    case VMEM_READ_PROCESS:
        // 读取指定进程的内存
        task = find_process_by_pid(data.pid);
        if (!task) {
            return -ESRCH;
        }
        
        kernel_buf = kmalloc(data.size, GFP_KERNEL);
        if (!kernel_buf) {
            return -ENOMEM;
        }
        
        ret = read_process_memory(task, data.vaddr, kernel_buf, data.size);
        if (ret > 0) {
            if (copy_to_user(data.user_buf, kernel_buf, data.size)) {
                ret = -EFAULT;
            }
        }
        
        kfree(kernel_buf);
        break;
        
    default:
        return -ENOTTY;
    }
    
    return ret;
}

static int vmem_open(struct inode *inode, struct file *file)
{
    return 0;
}

static int vmem_release(struct inode *inode, struct file *file)
{
    return 0;
}

static struct file_operations fops = {
    .owner = THIS_MODULE,
    .unlocked_ioctl = vmem_ioctl,
    .open = vmem_open,
    .release = vmem_release,
};

static int __init vmem_init(void)
{
    dev_t devno;
    int ret;
    
    printk(KERN_INFO "vmem: Initializing virtual memory access module\n");
    
    // 动态分配主设备号
    ret = alloc_chrdev_region(&devno, 0, MAX_DEVICES, DEVICE_NAME);
    if (ret < 0) {
        printk(KERN_ERR "vmem: Failed to allocate device number\n");
        return ret;
    }
    major_number = MAJOR(devno);
    
    // 创建设备类
    vmem_class = class_create(THIS_MODULE, CLASS_NAME);
    if (IS_ERR(vmem_class)) {
        unregister_chrdev_region(devno, MAX_DEVICES);
        printk(KERN_ERR "vmem: Failed to create device class\n");
        return PTR_ERR(vmem_class);
    }
    
    // 初始化字符设备
    cdev_init(&vmem_cdev, &fops);
    vmem_cdev.owner = THIS_MODULE;
    
    // 添加字符设备
    ret = cdev_add(&vmem_cdev, devno, MAX_DEVICES);
    if (ret) {
        class_destroy(vmem_class);
        unregister_chrdev_region(devno, MAX_DEVICES);
        printk(KERN_ERR "vmem: Failed to add character device\n");
        return ret;
    }
    
    // 创建设备节点
    vmem_device = device_create(vmem_class, NULL, devno, NULL, DEVICE_NAME);
    if (IS_ERR(vmem_device)) {
        cdev_del(&vmem_cdev);
        class_destroy(vmem_class);
        unregister_chrdev_region(devno, MAX_DEVICES);
        printk(KERN_ERR "vmem: Failed to create device\n");
        return PTR_ERR(vmem_device);
    }
    
    printk(KERN_INFO "vmem: Module loaded successfully with major number %d\n", major_number);
    return 0;
}

static void __exit vmem_exit(void)
{
    dev_t devno = MKDEV(major_number, 0);
    
    device_destroy(vmem_class, devno);
    cdev_del(&vmem_cdev);
    class_destroy(vmem_class);
    unregister_chrdev_region(devno, MAX_DEVICES);
    
    printk(KERN_INFO "vmem: Module unloaded\n");
}

module_init(vmem_init);
module_exit(vmem_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("Virtual Memory Access Module for Android ARM64");
MODULE_VERSION("1.0");

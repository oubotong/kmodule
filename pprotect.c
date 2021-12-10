#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/device.h>
#include <linux/cdev.h>
#include <linux/pid.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <asm/pgtable.h>
#include <linux/ioctl.h>
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Botong OU");
MODULE_DESCRIPTION("SEVMON protection invocation Linux Module.");
MODULE_VERSION("0.01");

#define KE_DATA_VAR _IOWR('k', 1, struct Info *)
extern void kmodule_call_into_secmon(int pid, unsigned long va, unsigned long pa);

dev_t dev = 0;
static int pid;
static unsigned long paddr=0;
static struct class *dev_class;
static struct cdev etx_cdev;

struct pid *p_pid_struct;
struct task_struct *p_task;
struct mm_struct *p_mm;
struct vm_area_struct *p_vma;
struct vm_area_struct *p_vma_next;
struct Info {
	int pid;
	unsigned long va;
};


static unsigned long vaddr2paddr(unsigned long vaddr)
{
    pgd_t *pgd;
    p4d_t *p4d;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *pte;;
    unsigned long page_addr = 0;
    unsigned long page_offset = 0;

    if(p_task==NULL){
      printk("task struct is empty\n");
      return -1;
    }

    pgd = pgd_offset(p_task->mm, vaddr);
    //printk("pgd_val = 0x%lx\n", pgd_val(*pgd));
    //printk("pgd_index = %lu\n", pgd_index(vaddr));
    if (pgd_none(*pgd)) {
        printk("not mapped in pgd\n");
        return -1;
    }

    p4d = p4d_offset(pgd, vaddr);
    //printk("p4d_val = 0x%lx\n", p4d_val(*p4d));
    //printk("p4d_index = %lu\n", p4d_index(vaddr));
    if (p4d_none(*p4d)) {
        printk("not mapped in p4d\n");
        return -1;
    }

    pud = pud_offset(p4d, vaddr);
    //printk("pud_val = 0x%lx\n", pud_val(*pud));
    //printk("pud_index = %lu\n", pud_index(vaddr));
    if (pud_none(*pud)) {
        printk("%-16lx           PUD:NULL\n", vaddr);
        return -1;
    }

    pmd = pmd_offset(pud, vaddr);
    //printk("pmd_val = 0x%lx\n", pmd_val(*pmd));
    //printk("pmd_index = %lu\n", pmd_index(vaddr));
    if (pmd_none(*pmd)) {
        printk("%-16lx           PMD:NULL\n", vaddr);
        return -1;
    }

    pte = pte_offset_kernel(pmd, vaddr);
    //printk("pte_val = 0x%lx\n", pte_val(*pte));
    //printk("pte_index = %lu\n", pte_index(vaddr));
    if (pte_none(*pte)) {
        printk(" %-16lx           PTE:NULL\n", vaddr);
        return -1;
    }

    page_addr = pte_val(*pte) & PAGE_MASK;
    page_offset = vaddr & ~PAGE_MASK;
    paddr = page_addr | page_offset;
    //printk("page_addr = %lx, page_offset = %lx\n", page_addr, page_offset);
    printk(" %-16lx           %-16lx", vaddr, paddr);

    return paddr;
}

static int kprotect(void){
  printk("Kernel module: Printing memory mapping of process: %d\n",pid);
  p_pid_struct = find_get_pid(pid);
  p_task = pid_task(p_pid_struct, PIDTYPE_PID);
  p_mm=p_task->active_mm;
  p_vma=p_mm->mmap;
  printk(" Virtual Address           Physical Address");
  while(p_vma!=NULL){
    //printk("VA: %lx-%lx\n", p_vma->vm_start, p_vma->vm_end);
    vaddr2paddr(p_vma->vm_start);
    vaddr2paddr((p_vma->vm_end)-1);
    //printk(KERN_CONT "\n");
    p_vma_next=p_vma->vm_next;
    p_vma=p_vma_next;
  }
  return 0;
}

static long ke_ioctl(struct file *f, unsigned int cmd, unsigned long arg){
    struct Info *obj=kmalloc(sizeof(struct Info), GFP_KERNEL);
    switch (cmd){
        case KE_DATA_VAR:
          if (copy_from_user(obj, (void *)arg, sizeof(struct Info))){
            return -EACCES;
          }
          pid=obj->pid;
          p_pid_struct = find_get_pid(pid);
          p_task = pid_task(p_pid_struct, PIDTYPE_PID);
          p_mm=p_task->active_mm;
          p_vma=p_mm->mmap;
          vaddr2paddr(obj->va);
          kmodule_call_into_secmon(pid,obj->va, paddr);
          paddr = 0;
          break;
        default:
          return -EINVAL;
    }

    return 0;
}

static struct file_operations ke_fops =
{
    .owner = THIS_MODULE,
    .unlocked_ioctl = ke_ioctl
};


static int __init pprotect_init(void) {
  printk(KERN_INFO "Intializing Kernel Module\n");

  if((alloc_chrdev_region(&dev, 0, 1, "etx_Dev")) <0){
    pr_err("Cannot allocate major number\n");
    return -1;
  }
  cdev_init(&etx_cdev,&ke_fops);
  if((cdev_add(&etx_cdev,dev,1)) < 0){
    pr_err("Cannot add the device to the system\n");
    goto r_class;
  }
 /*Creating struct class*/
 if((dev_class = class_create(THIS_MODULE,"etx_class")) == NULL){
    pr_err("Cannot create the struct class\n");
    goto r_class;
 }
 /*Creating device*/
 if((device_create(dev_class,NULL,dev,NULL,"etx_device")) == NULL){
     pr_err("Cannot create the Device 1\n");
     goto r_device;
 }
 printk("Kernel Module: Creating IOCTL Device Driver\n");
 printk("Kernel Module: Device Driver Insert...Done!!!\n");
 return 0;
r_device:
  class_destroy(dev_class);
r_class:
  unregister_chrdev_region(dev,1);
  return -1;
}


static void __exit pprotect_exit(void) {
 printk(KERN_INFO "Kernel Module Exit\n");
 device_destroy(dev_class,dev);
 class_destroy(dev_class);
 cdev_del(&etx_cdev);
 unregister_chrdev_region(dev, 1);
}

module_init(pprotect_init);
module_exit(pprotect_exit);

#include "asm-generic/errno-base.h"
#include "linux/dma-direction.h"
#include "linux/dma-mapping.h"
#include "linux/mm.h"
#include "linux/smp.h"
#include "linux/spinlock.h"
#include "linux/types.h"
#include "linux/wait.h"
#include <linux/device.h>
#include <linux/printk.h>
#include <linux/cdev.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/uaccess.h>
#include <asm/cacheflush.h>
#include <linux/delay.h>


static struct class *s_class;

static unsigned int dma_mode = 0;
module_param(dma_mode, uint, 0644);
MODULE_PARM_DESC(dma_mode, "0 - Default , 1 - Single page");

#define MINOR_BASE			(0)
#define MINOR_COUNT			(255)
#define MODULE_NAME			"qemuedu"
#define VENDOR_ID			(0x1234) // qemu vendor id
#define DEVICE_ID			(0x11e8) // qemuedu device id

// Registers
#define IO_IRQ_STATUS		(0x24)
#define IO_IRQ_ACK			(0x64)
#define IO_DMA_SRC			(0x80)
#define IO_DMA_DST			(0x88)
#define IO_DMA_CNT			(0x90)
#define IO_DMA_CMD			(0x98)
#define IO_SIZE				(0x200) //// TODO

#define DMA_BASE			(0x40000)
#define DMA_SIZE			(4096)
#define DMA_START			(0x1)
#define DMA_FROM_DEV		(0x2)
#define DMA_IRQ				(0x4)

enum dma_dir {
	DMA_DIR_WRITE = 0,
	DMA_DIR_READ,
};

enum dma_state {
	DMA_STATE_NEW = 0,
	DMA_STATE_SUBMITTED,
	DMA_STATE_COMPLETED,
	DMA_STATE_FAILED,
	DMA_STATE_ABORTED
};

struct qemuedu_dma {
	enum dma_dir dir;
	enum dma_state state;
	u32 irq_status;

	// by dma_alloc_coherent
	void *vaddr;
	dma_addr_t handle;

//	spinlock_t lock;
	struct work_struct work; // for interrupt handling
	wait_queue_head_t wait_queue;
};

struct qemuedu_cdev {
	struct qemuedu_pci_dev *qpdev; // parent
	struct cdev cdev;
	dev_t cdevno;
	void __iomem *bar;
	struct qemuedu_dma dma;

	// sysfs
	struct device *sys_device;
};

struct qemuedu_pci_dev {
	int major;
	struct pci_dev *pdev;
	void __iomem *bar[6];
	int msi_enabled;
	struct qemuedu_cdev cdev_reg;
	struct qemuedu_cdev cdev_dma;
	struct mutex lock;
};

static struct pci_device_id pci_ids[] = {
	{ PCI_DEVICE(VENDOR_ID, DEVICE_ID), },
	{ 0, }
};
MODULE_DEVICE_TABLE(pci, pci_ids);


static irqreturn_t irq_handler(int irq, void *dev_id)
{
	irqreturn_t ret;
	u32 irq_status;
	struct qemuedu_pci_dev *qpdev;

	if (!dev_id) {
		pr_err("Invalid dev on irq line %d\n", irq);
		return IRQ_NONE;
	}

	qpdev = (struct qemuedu_pci_dev*)dev_id;
	if (!qpdev) {
		WARN_ON(!qpdev);
		pr_err("%s(irq=%d) qdev=%px ??\n", __func__, irq, qpdev);
		return IRQ_NONE;
	}

	dev_dbg(&(qpdev->pdev->dev), "%s smp%d\n", __func__, smp_processor_id());
	dev_dbg(&(qpdev->pdev->dev), "(irq=%d, dev_id 0x%px) <<<< ISR.\n", irq, dev_id);

	irq_status = ioread32(qpdev->cdev_reg.bar + IO_IRQ_STATUS);
	if (irq_status) {
		dev_dbg(&(qpdev->pdev->dev), "irq_handler irq = %d irq_status = 0x%x\n", irq, irq_status);

		// In the case of legacy irq, if ack is not written here, many interrupts will occur.
		iowrite32(irq_status, qpdev->cdev_reg.bar + IO_IRQ_ACK);

		qpdev->cdev_dma.dma.irq_status = irq_status;
		schedule_work(&qpdev->cdev_dma.dma.work);

		ret = IRQ_HANDLED;

	} else {
		ret = IRQ_NONE;
	}

	return ret;
}

static void service_work(struct work_struct *work)
{
	struct pci_dev *pdev;
	struct qemuedu_cdev *qcdev;
	struct qemuedu_dma *qdma;
	struct qemuedu_cdev *qcdev_reg;
	u32 irq_status = 0;

	qdma = container_of(work, struct qemuedu_dma, work);
	qcdev = container_of(qdma, struct qemuedu_cdev, dma);
	pdev = qcdev->qpdev->pdev;
	qcdev_reg = &qcdev->qpdev->cdev_reg;

	dev_dbg(&(pdev->dev), "%s smp%d\n", __func__, smp_processor_id());

	irq_status = qcdev->dma.irq_status;
	dev_dbg(&(pdev->dev), "irq_status = 0x%x\n", irq_status);

////	iowrite32(irq_status, qcdev_reg->bar + IO_IRQ_ACK);

	irq_status = ioread32(qcdev_reg->bar + IO_IRQ_ACK);
	dev_dbg(&(pdev->dev), "ioread irq_status = 0x%x\n", irq_status);

	qcdev->dma.state = DMA_STATE_COMPLETED;
#if 1
	wake_up_interruptible(&qcdev->dma.wait_queue);
#endif
}

static int open(struct inode *inode, struct file *file)
{
	struct pci_dev *pdev;
	struct qemuedu_cdev *qcdev;

	qcdev = container_of(inode->i_cdev, struct qemuedu_cdev, cdev);
	if (qcdev == NULL) {
		pr_err("container_of\n");
		return -EFAULT;
	}
	pdev = qcdev->qpdev->pdev;

	dev_dbg(&(pdev->dev), "%s cdevno %x smp%d\n", __func__, qcdev->cdevno, smp_processor_id());
	file->private_data = qcdev;

	return 0;
}

static int close(struct inode *inode, struct file *file)
{
	struct qemuedu_cdev *qcdev = (struct qemuedu_cdev *)file->private_data;
	struct pci_dev *pdev = qcdev->qpdev->pdev;
	dev_dbg(&(pdev->dev), "%s cdevno %x smp%d\n", __func__, qcdev->cdevno, smp_processor_id());
	return 0;
}

static ssize_t read_reg(struct file *file, char __user *buf, size_t len, loff_t *off)
{
	ssize_t rv = 0;
	struct qemuedu_cdev *qcdev = file->private_data;
	struct pci_dev *pdev = qcdev->qpdev->pdev;
	u32 rbuf;

	dev_dbg(&(pdev->dev), "%s smp%d\n", __func__, smp_processor_id());
	dev_dbg(&(pdev->dev), "len = %lu, off = %llu\n", len, *off);

	if ((len % 4) != 0) {
		//TODO
	}

	if (len != 4) {
		dev_err(&(pdev->dev), "size error\n");
		return -EINVAL;
	}

	if ((len + *off) >= IO_SIZE) {
		dev_err(&(pdev->dev), "IO_SIZE over (%llx)\n", len + *off);
		return -EINVAL;
	}

	mutex_lock(&qcdev->qpdev->lock);

	rbuf = ioread32(qcdev->bar + *off);

	rv = copy_to_user(buf, &rbuf, 4);
	if (rv < 0) {
		dev_err(&(pdev->dev), "Failed to copy_to_user rv%ld\n", rv);
		rv = -EINVAL;
		goto unlock;
	}

unlock:
	mutex_unlock(&qcdev->qpdev->lock);

	if (rv >= 0)
		rv = len;
	return rv;
}

static ssize_t write_reg(struct file *file, const char __user *buf, size_t len, loff_t *off)
{
	ssize_t rv = 0;
	struct qemuedu_cdev *qcdev = file->private_data;
	struct pci_dev *pdev = qcdev->qpdev->pdev;
	struct qemuedu_cdev *qcdev_reg = &qcdev->qpdev->cdev_reg;
	u32 wbuf;

	dev_dbg(&(pdev->dev), "%s smp%d\n", __func__, smp_processor_id());
	dev_dbg(&(pdev->dev), "len = %lu, off = %llu\n", len, *off);

	if ((len % 4) != 0) {
		//TODO
	}

	if (len != 4) {
		dev_err(&(pdev->dev), "size error\n");
		return -EINVAL;
	}

	if ((len + *off) >= IO_SIZE) {
		dev_err(&(pdev->dev), "IO_SIZE over (%llx)\n", len + *off);
		return -EINVAL;
	}

	mutex_lock(&qcdev->qpdev->lock);

	rv = copy_from_user(&wbuf, buf, 4);
	if (rv < 0) {
		dev_err(&(pdev->dev), "Failed to copy_from_user rv%ld\n", rv);
		rv = -EINVAL;
		goto unlock;
	}

	iowrite32(wbuf, qcdev_reg->bar + *off);

unlock:
	mutex_unlock(&qcdev->qpdev->lock);

	if (rv >= 0)
		rv = len;
	return rv;
}

static ssize_t read_dma_normal(struct file *file, char __user *buf, size_t len, loff_t *off)
{
	ssize_t rv;
	struct qemuedu_cdev *qcdev = file->private_data;
	struct pci_dev *pdev = qcdev->qpdev->pdev;
	struct qemuedu_cdev *qcdev_reg = &qcdev->qpdev->cdev_reg;

	dev_dbg(&(pdev->dev), "%s smp%d\n", __func__, smp_processor_id());
	dev_dbg(&(pdev->dev), "vaddr = %px dma_handle = %llx\n", qcdev->dma.vaddr, qcdev->dma.handle);
	dev_dbg(&(pdev->dev), "len = %lu, off = %llu\n", len, *off);

	if ((len % 4) != 0) {
		//TODO
	}

	if ((len + *off) >= DMA_SIZE) {
		dev_err(&(pdev->dev), "DMA_SIZE over (%llx)\n", len + *off);
		return -EINVAL;
	}

	mutex_lock(&qcdev->qpdev->lock);

	qcdev->dma.dir = DMA_DIR_READ;
	qcdev->dma.state = DMA_STATE_NEW;

	iowrite32((DMA_BASE + *off)         & 0xffffffff, qcdev_reg->bar + IO_DMA_SRC);
	iowrite32(((DMA_BASE + *off) >> 32) & 0xffffffff, qcdev_reg->bar + IO_DMA_SRC + 4);

	iowrite32(qcdev->dma.handle         & 0xffffffff, qcdev_reg->bar + IO_DMA_DST);
	iowrite32((qcdev->dma.handle >> 32) & 0xffffffff, qcdev_reg->bar + IO_DMA_DST + 4);

	iowrite32(len, qcdev_reg->bar + IO_DMA_CNT);
	iowrite32(DMA_START | DMA_FROM_DEV | DMA_IRQ, qcdev_reg->bar + IO_DMA_CMD);
	qcdev->dma.state = DMA_STATE_SUBMITTED;

#if 1
	rv = wait_event_interruptible_timeout(qcdev->dma.wait_queue, qcdev->dma.state != DMA_STATE_SUBMITTED, msecs_to_jiffies(10000));
	if (!rv) {
		dev_err(&(pdev->dev), "wait_event_interruptible_timeout\n");
		qcdev->dma.state = DMA_STATE_ABORTED;
		rv = -ETIMEDOUT;
		goto unlock;
	}
#else
	while (qcdev->dma.state == DMA_STATE_SUBMITTED) {
		nop();
	}
#endif

	rv = copy_to_user(buf, qcdev->dma.vaddr, len);
	if (rv < 0) {
		dev_err(&(pdev->dev), "Failed to copy_to_user rv%ld\n", rv);
		rv = -EINVAL;
		goto unlock;
	}

unlock:
	mutex_unlock(&qcdev->qpdev->lock);

	if (rv >= 0)
		rv = len;
	return rv;
}

static ssize_t write_dma_normal(struct file *file, const char __user *buf, size_t len, loff_t *off)
{
	ssize_t rv;
	struct qemuedu_cdev *qcdev = file->private_data;
	struct pci_dev *pdev = qcdev->qpdev->pdev;
	struct qemuedu_cdev *qcdev_reg = &qcdev->qpdev->cdev_reg;

	dev_dbg(&(pdev->dev), "%s smp%d\n", __func__, smp_processor_id());
	dev_dbg(&(pdev->dev), "vaddr = %px dma_handle = %llx\n", qcdev->dma.vaddr, qcdev->dma.handle);
	dev_dbg(&(pdev->dev), "len = %lu, off = %llu\n", len, *off);

	if ((len % 4) != 0) {
		//TODO
	}

	if ((len + *off) >= DMA_SIZE) {
		dev_err(&(pdev->dev), "DMA_SIZE over (%llx)\n", len + *off);
		return -EINVAL;
	}

	mutex_lock(&qcdev->qpdev->lock);

	qcdev->dma.dir = DMA_DIR_WRITE;
	qcdev->dma.state = DMA_STATE_NEW;

	rv = copy_from_user(qcdev->dma.vaddr, buf, len);
	if (rv < 0) {
		dev_err(&(pdev->dev), "Failed to copy_from_user rv%ld\n", rv);
		rv = -EINVAL;
		goto unlock;
	}

	iowrite32(qcdev->dma.handle         & 0xffffffff, qcdev->qpdev->cdev_reg.bar + IO_DMA_SRC);
	iowrite32((qcdev->dma.handle >> 32) & 0xffffffff, qcdev->qpdev->cdev_reg.bar + IO_DMA_SRC + 4);

	iowrite32((DMA_BASE + *off)         & 0xffffffff, qcdev_reg->bar + IO_DMA_DST);
	iowrite32(((DMA_BASE + *off) >> 32) & 0xffffffff, qcdev_reg->bar + IO_DMA_DST + 4);

	iowrite32(len, qcdev_reg->bar + IO_DMA_CNT);
	iowrite32(DMA_START | DMA_IRQ, qcdev_reg->bar + IO_DMA_CMD);
	qcdev->dma.state = DMA_STATE_SUBMITTED;

	rv = wait_event_interruptible_timeout(qcdev->dma.wait_queue, qcdev->dma.state != DMA_STATE_SUBMITTED, msecs_to_jiffies(10000));
	if (!rv) {
		dev_err(&(pdev->dev), "wait_event_interruptible_timeout\n");
		qcdev->dma.state = DMA_STATE_ABORTED;
		rv = -ETIMEDOUT;
		goto unlock;
	}

unlock:
	mutex_unlock(&qcdev->qpdev->lock);

	if (rv >= 0)
		rv = len;
	return rv;
}

static ssize_t read_dma_single_page(struct file *file, char __user *buf, size_t len, loff_t *off)
{
	ssize_t rv;
	struct qemuedu_cdev *qcdev = file->private_data;
	struct pci_dev *pdev = qcdev->qpdev->pdev;
	struct qemuedu_cdev *qcdev_reg = &qcdev->qpdev->cdev_reg;

	unsigned int pages_nr = (((unsigned long)buf + len + PAGE_SIZE - 1) -
				 ((unsigned long)buf & PAGE_MASK))
				>> PAGE_SHIFT;
	struct page *page = NULL;
	dma_addr_t dma_addr = 0;
	unsigned long page_off = ((unsigned long)buf & ~PAGE_MASK);

	dev_dbg(&(pdev->dev), "%s smp%d\n", __func__, smp_processor_id());
	dev_dbg(&(pdev->dev), "len = %lu, off = %llu\n", len, *off);
	dev_dbg(&(pdev->dev), "pages_nr = %d\n", pages_nr);

	if ((len % 4) != 0) {
		//TODO
	}

	if ((len + *off) >= DMA_SIZE) {
		dev_err(&(pdev->dev), "DMA_SIZE over (%llx)\n", len + *off);
		return -EINVAL;
	}

	if (pages_nr != 1) {
		dev_err(&(pdev->dev), "pages_nr is must be 1 page. nr%d\n", pages_nr);
		return -EINVAL;
	}

	mutex_lock(&qcdev->qpdev->lock);

	qcdev->dma.dir = DMA_DIR_READ;
	qcdev->dma.state = DMA_STATE_NEW;

	rv = get_user_pages_fast((unsigned long)buf, pages_nr, FOLL_WRITE, &page);
	if (rv < 0) {
		dev_err(&(pdev->dev), "Failed to get_user_pages_fast rv%ld\n", rv);
		rv = -EINVAL;
		goto unlock;
	}
	dev_dbg(&(pdev->dev), "get_user_pages_fast page_addr=%px page_off=%lx\n", page, page_off);

	dma_addr = dma_map_page(&pdev->dev, page, page_off, len, DMA_FROM_DEVICE);
	rv = pci_dma_mapping_error(pdev, dma_addr);
	if (rv) {
		dev_err(&(pdev->dev), "Failed to dma_map_page rv%ld\n", rv);
		rv = -EINVAL;
		goto unlock;
	}
	dev_dbg(&(pdev->dev), "dma_map_page dma_addr=%llx len=%lx\n", dma_addr, len);

	iowrite32((DMA_BASE + *off)         & 0xffffffff, qcdev_reg->bar + IO_DMA_SRC);
	iowrite32(((DMA_BASE + *off) >> 32) & 0xffffffff, qcdev_reg->bar + IO_DMA_SRC + 4);

	iowrite32(dma_addr         & 0xffffffff, qcdev_reg->bar + IO_DMA_DST);
	iowrite32((dma_addr >> 32) & 0xffffffff, qcdev_reg->bar + IO_DMA_DST + 4);

	iowrite32(len, qcdev_reg->bar + IO_DMA_CNT);
	iowrite32(DMA_START | DMA_FROM_DEV | DMA_IRQ, qcdev_reg->bar + IO_DMA_CMD);
	qcdev->dma.state = DMA_STATE_SUBMITTED;

	rv = wait_event_interruptible_timeout(qcdev->dma.wait_queue, qcdev->dma.state != DMA_STATE_SUBMITTED, msecs_to_jiffies(10000));
	if (!rv) {
		dev_err(&(pdev->dev), "wait_event_interruptible_timeout\n");
		qcdev->dma.state = DMA_STATE_ABORTED;
		rv = -ETIMEDOUT;
		goto unlock;
	}

unlock:
	mutex_unlock(&qcdev->qpdev->lock);
	if (dma_addr)
		dma_unmap_page(&pdev->dev, dma_addr, len, DMA_FROM_DEVICE);
	if (page) {
		set_page_dirty_lock(page);
		put_page(page);
	}

	if (rv >= 0)
		rv = len;
	return rv;
}

static ssize_t write_dma_single_page(struct file *file, const char __user *buf, size_t len, loff_t *off)
{
	ssize_t rv;
	struct qemuedu_cdev *qcdev = file->private_data;
	struct pci_dev *pdev = qcdev->qpdev->pdev;
	struct qemuedu_cdev *qcdev_reg = &qcdev->qpdev->cdev_reg;

	unsigned int pages_nr = (((unsigned long)buf + len + PAGE_SIZE - 1) -
				 ((unsigned long)buf & PAGE_MASK))
				>> PAGE_SHIFT;
	struct page *page = NULL;
	dma_addr_t dma_addr = 0;
	unsigned long page_off = ((unsigned long)buf & ~PAGE_MASK);

	dev_dbg(&(pdev->dev), "%s smp%d\n", __func__, smp_processor_id());
	dev_dbg(&(pdev->dev), "len = %lu, off = %llu\n", len, *off);
	dev_dbg(&(pdev->dev), "pages_nr = %d\n", pages_nr);

	if ((len % 4) != 0) {
		//TODO
	}

	if ((len + *off) >= DMA_SIZE) {
		dev_err(&(pdev->dev), "DMA_SIZE over (%llx)\n", len + *off);
		return -EINVAL;
	}

	if (pages_nr != 1) {
		dev_err(&(pdev->dev), "pages_nr is must be 1 page. nr%d\n", pages_nr);
		return -EINVAL;
	}

	mutex_lock(&qcdev->qpdev->lock);

	qcdev->dma.dir = DMA_DIR_WRITE;
	qcdev->dma.state = DMA_STATE_NEW;

	rv = get_user_pages_fast((unsigned long)buf, pages_nr, FOLL_WRITE, &page);
	if (rv < 0) {
		dev_err(&(pdev->dev), "Failed to get_user_pages_fast rv%ld\n", rv);
		rv = -EINVAL;
		goto unlock;
	}
	dev_dbg(&(pdev->dev), "get_user_pages_fast page_addr=%px page_off=%lx\n", page, page_off);

	dma_addr = dma_map_page(&pdev->dev, page, page_off, len, DMA_TO_DEVICE);
	rv = pci_dma_mapping_error(pdev, dma_addr);
	if (rv) {
		dev_err(&(pdev->dev), "Failed to dma_map_page rv%ld\n", rv);
		rv = -EINVAL;
		goto unlock;
	}
	dev_dbg(&(pdev->dev), "dma_map_page dma_addr=%llx len=%lx\n", dma_addr, len);

	iowrite32(dma_addr         & 0xffffffff, qcdev->qpdev->cdev_reg.bar + IO_DMA_SRC);
	iowrite32((dma_addr >> 32) & 0xffffffff, qcdev->qpdev->cdev_reg.bar + IO_DMA_SRC + 4);

	iowrite32((DMA_BASE + *off)         & 0xffffffff, qcdev_reg->bar + IO_DMA_DST);
	iowrite32(((DMA_BASE + *off) >> 32) & 0xffffffff, qcdev_reg->bar + IO_DMA_DST + 4);

	iowrite32(len, qcdev_reg->bar + IO_DMA_CNT);
	iowrite32(DMA_START | DMA_IRQ, qcdev_reg->bar + IO_DMA_CMD);
	qcdev->dma.state = DMA_STATE_SUBMITTED;

	rv = wait_event_interruptible_timeout(qcdev->dma.wait_queue, qcdev->dma.state != DMA_STATE_SUBMITTED, msecs_to_jiffies(10000));
	if (!rv) {
		dev_err(&(pdev->dev), "wait_event_interruptible_timeout\n");
		qcdev->dma.state = DMA_STATE_ABORTED;
		rv = -ETIMEDOUT;
		goto unlock;
	}

unlock:
	mutex_unlock(&qcdev->qpdev->lock);
	if (dma_addr)
		dma_unmap_page(&pdev->dev, dma_addr, len, DMA_TO_DEVICE);
	if (page) {
		put_page(page);
	}

	if (rv >= 0)
		rv = len;
	return rv;
}

static ssize_t read_dma(struct file *file, char __user *buf, size_t len, loff_t *off)
{
	ssize_t rv;
	struct qemuedu_cdev *qcdev = file->private_data;
	struct pci_dev *pdev = qcdev->qpdev->pdev;


	switch (dma_mode) {
	case 0:
		rv = read_dma_normal(file, buf, len, off);
		break;
	case 1:
		rv =read_dma_single_page(file, buf, len, off);
		break;
	default:
		dev_warn(&(pdev->dev), "invalid dma_mode %d\n", dma_mode);
		rv = read_dma_normal(file, buf, len, off);
		break;
	}

	return rv;
}

static ssize_t write_dma(struct file *file, const char __user *buf, size_t len, loff_t *off)
{
	ssize_t rv;
	struct qemuedu_cdev *qcdev = file->private_data;
	struct pci_dev *pdev = qcdev->qpdev->pdev;

	dev_dbg(&(pdev->dev), "dma_mode %d\n", dma_mode);

	switch (dma_mode) {
	case 0:
		rv = write_dma_normal(file, buf, len, off);
		break;
	case 1:
		rv = write_dma_single_page(file, buf, len, off);
		break;
	default:
		dev_warn(&(pdev->dev), "invalid dma_mode %d\n", dma_mode);
		rv = write_dma_normal(file, buf, len, off);
		break;
	}

	return rv;
}

static loff_t llseek_reg(struct file *file, loff_t off, int whence)
{
	loff_t newpos;
	struct qemuedu_cdev *qcdev = file->private_data;
	struct pci_dev *pdev = qcdev->qpdev->pdev;

	dev_dbg(&(pdev->dev), "%s smp%d\n", __func__, smp_processor_id());
	dev_dbg(&(qcdev->qpdev->pdev->dev), "off = %lld whence = %d\n", off, whence);

	switch(whence) {
	case SEEK_SET:
		newpos = off;
		break;
	case SEEK_CUR:
		newpos = file->f_pos + off;
		break;
	case SEEK_END:
		newpos = IO_SIZE + off;
		break;
	default:
		return -EINVAL;
	}
	if (newpos < 0) {
		return -EINVAL;
	}
	if (newpos >= IO_SIZE) {
		return -EINVAL;
	}
	file->f_pos = newpos;
	dev_dbg(&(qcdev->qpdev->pdev->dev), "newpos = %lld\n", newpos);

	return newpos;
}

static loff_t llseek_dma(struct file *file, loff_t off, int whence)
{
	loff_t newpos;
	struct qemuedu_cdev *qcdev = file->private_data;
	struct pci_dev *pdev = qcdev->qpdev->pdev;

	dev_dbg(&(pdev->dev), "%s smp%d\n", __func__, smp_processor_id());
	dev_dbg(&(qcdev->qpdev->pdev->dev), "off = %lld whence = %d\n", off, whence);

	switch(whence) {
	case SEEK_SET:
		newpos = off;
		break;
	case SEEK_CUR:
		newpos = file->f_pos + off;
		break;
	case SEEK_END:
		newpos = DMA_SIZE + off;
		break;
	default:
		return -EINVAL;
	}
	if (newpos < 0) {
		return -EINVAL;
	}
	if (newpos >= DMA_SIZE) {
		return -EINVAL;
	}
	file->f_pos = newpos;
	dev_dbg(&(qcdev->qpdev->pdev->dev), "newpos = %lld\n", newpos);

	return newpos;
}

int mmap(struct file *file, struct vm_area_struct *vma)
{
	unsigned long off;
	unsigned long phys;
	unsigned long vsize;
	unsigned long psize;
	int rv;
	struct qemuedu_cdev *qcdev = file->private_data;
	struct pci_dev *pdev = qcdev->qpdev->pdev;
	int bar_idx = 0;

	off = vma->vm_pgoff << PAGE_SHIFT;
	// BAR physical address
	phys = pci_resource_start(pdev, bar_idx) + off;
	vsize = vma->vm_end - vma->vm_start;
	psize = pci_resource_end(pdev, bar_idx) -
		pci_resource_start(pdev, bar_idx) + 1 - off;

	dev_dbg(&(pdev->dev), "%s smp%d\n", __func__, smp_processor_id());
	dev_dbg(&(pdev->dev), "off = 0x%lx, vsize 0x%lu, psize 0x%lu.\n", off, vsize, psize);
	dev_dbg(&(pdev->dev), "start = 0x%llx\n", pci_resource_start(pdev, bar_idx));
	dev_dbg(&(pdev->dev), "phys = 0x%lx\n", phys);

	if (vsize > psize)
		return -EINVAL;

	// pages must not be cached as this would result in cache line sized
	// accesses to the end point
	vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);

	// prevent touching the pages (byte access) for swap-in,
	// and prevent the pages from being swapped out
	vma->vm_flags |= VM_IO | VM_DONTEXPAND | VM_DONTDUMP;

	// make MMIO accessible to user space
	rv = io_remap_pfn_range(vma, vma->vm_start, phys >> PAGE_SHIFT,
			vsize, vma->vm_page_prot);

	dev_dbg(&(pdev->dev), "vma=0x%px, vma->vm_start=0x%lx, phys=0x%lx, size=%lu = %d\n",
		vma, vma->vm_start, phys >> PAGE_SHIFT, vsize, rv);

	if (rv)
		return -EAGAIN;

	return 0;
}

static struct file_operations fops_reg = {
	.owner = THIS_MODULE,
	.open = open,
	.release = close,
	.read = read_reg,
	.write = write_reg,
	.llseek = llseek_reg,
	.mmap = mmap,
};

static struct file_operations fops_dma = {
	.owner = THIS_MODULE,
	.open = open,
	.release = close,
	.read = read_dma,
	.write = write_dma,
	.llseek = llseek_dma,
};

static int msi_msix_capable(struct pci_dev *pdev, int type)
{
	struct pci_bus *bus;

	if (!pdev || pdev->no_msi)
		return 0;

	for (bus = pdev->bus; bus; bus = bus->parent)
		if (bus->bus_flags & PCI_BUS_FLAGS_NO_MSI)
			return 0;

	if (pci_find_capability(pdev, type) == 0)
		return 0;

	return 1;
}

static int set_dma_mask(struct pci_dev *pdev)
{
	if (!pdev) {
		pr_err("Invalid pdev\n");
		return -EINVAL;
	}

	dev_info(&(pdev->dev), "sizeof(dma_addr_t) == %ld\n", sizeof(dma_addr_t));
	if (!pci_set_dma_mask(pdev, DMA_BIT_MASK(64))) {
		dev_info(&(pdev->dev), "pci_set_dma_mask()\n");
		dev_info(&(pdev->dev), "Using a 64-bit DMA mask.\n");
		pci_set_consistent_dma_mask(pdev, DMA_BIT_MASK(64));

	} else if (!pci_set_dma_mask(pdev, DMA_BIT_MASK(32))) {
		dev_info(&(pdev->dev), "Could not set 64-bit DMA mask.\n");
		pci_set_consistent_dma_mask(pdev, DMA_BIT_MASK(32));
		dev_info(&(pdev->dev), "Using a 32-bit DMA mask.\n");

	} else {
		dev_err(&(pdev->dev), "No suitable DMA possible.\n");
		return -EINVAL;
	}

	return 0;
}

static void print_config(struct pci_dev *pdev)
{
	u16 vendor_id;
	u16 device_id;
	u16 class;
	u16 sub_vendor_id;
	u16 sub_device_id;
	u8 irq_no;
	u8 irq_pin;

	if (!pdev) {
		return ;
	}

	pci_read_config_word(pdev, PCI_VENDOR_ID, &vendor_id);
	pci_read_config_word(pdev, PCI_DEVICE_ID, &device_id);
	pci_read_config_word(pdev, PCI_CLASS_DEVICE, &class);
	pci_read_config_word(pdev, PCI_SUBSYSTEM_VENDOR_ID, &sub_vendor_id);
	pci_read_config_word(pdev, PCI_SUBSYSTEM_ID, &sub_device_id);
	pci_read_config_byte(pdev, PCI_INTERRUPT_LINE, &irq_no);
	pci_read_config_byte(pdev, PCI_INTERRUPT_PIN, &irq_pin);

	dev_info(&(pdev->dev), "pci_read_config vendor id = 0x%x, device id = 0x%x\n", vendor_id, device_id);
	dev_info(&(pdev->dev), "pci_read_config class = %i\n", class);
	dev_info(&(pdev->dev), "pci_read_config sub_vendor id = 0x%x, sub_device id = 0x%x\n", sub_vendor_id, sub_device_id);
	dev_info(&(pdev->dev), "pci_read_config irq no = %i, irq pin = %d\n", irq_no, irq_pin);

}

static int create_sys_device(struct qemuedu_cdev *qcdev, char *node_name)
{
	struct device *dev = &qcdev->qpdev->pdev->dev;

	if (s_class) {
		qcdev->sys_device = device_create(s_class, dev, qcdev->cdevno, NULL, node_name, 0, 0);
		if (!qcdev->sys_device) {
			dev_err(dev, "device_create(%s) failed\n", node_name);
			return -1;
		}
	}

	return 0;
}

static void destory_sys_device(struct qemuedu_cdev *qcdev)
{
	if (s_class && qcdev->sys_device) {
		device_destroy(s_class, qcdev->cdevno);
	}
}

static int pci_probe(struct pci_dev *pdev, const struct pci_device_id *id)
{
	int rv = 0;
	dev_t dev;
	struct qemuedu_pci_dev *qpdev = NULL;
	u8 val = 0;
	int bar_idx = 0;
	resource_size_t bar_start;
	resource_size_t bar_len;
	resource_size_t resource_flag;
	int irq_flags = 0;
	void *dma_vaddr;
	dma_addr_t dma_handle;

	dev_info(&(pdev->dev), "%s\n", __func__);

	qpdev = kmalloc(sizeof(struct qemuedu_pci_dev), GFP_KERNEL);
	if (!qpdev) {
		rv = -ENOMEM;
		goto err;
	}
	memset (qpdev, 0, sizeof(struct qemuedu_pci_dev));

	mutex_init(&qpdev->lock);

	rv = alloc_chrdev_region(&dev, MINOR_BASE, MINOR_COUNT, MODULE_NAME);
	if (rv != 0) {
		rv = -EINVAL;
		dev_err(&(pdev->dev), "alloc_chrdev_region\n");
		goto err_alloc_cdev;
	}

	qpdev->major = MAJOR(dev);
	dev_info(&(pdev->dev), "major %d\n", qpdev->major);

	// setup cdev_reg
	qpdev->cdev_reg.qpdev = qpdev;
	qpdev->cdev_reg.cdevno = MKDEV(qpdev->major, 0); // minor0
	qpdev->cdev_reg.cdev.owner = THIS_MODULE;
	cdev_init(&qpdev->cdev_reg.cdev, &fops_reg);
	rv = cdev_add(&qpdev->cdev_reg.cdev, qpdev->cdev_reg.cdevno, 1);
	if (rv != 0) {
		rv = -EINVAL;
		dev_err(&(pdev->dev), "cdev_add\n");
		goto err_add_cdev_reg;
	}

	// setup cdev_dma
	qpdev->cdev_dma.qpdev = qpdev;
	qpdev->cdev_dma.cdevno = MKDEV(qpdev->major, 1); // minor1
	qpdev->cdev_dma.cdev.owner = THIS_MODULE;
	cdev_init(&qpdev->cdev_dma.cdev, &fops_dma);
	rv = cdev_add(&qpdev->cdev_dma.cdev, qpdev->cdev_dma.cdevno, 1);
	if (rv != 0) {
		rv = -EINVAL;
		dev_err(&(pdev->dev), "cdev_add\n");
		goto err_add_cdev_dma;
	}

	qpdev->pdev = pdev;

	rv = create_sys_device(&qpdev->cdev_reg, "qemuedu_reg");
	if (rv != 0) {
		rv = -EINVAL;
		dev_err(&(pdev->dev), "create_sys_device qemuedu_reg\n");
		goto err_create_sysdev_reg;
	}

	rv = create_sys_device(&qpdev->cdev_dma, "qemuedu_dma");
	if (rv != 0) {
		rv = -EINVAL;
		dev_err(&(pdev->dev), "create_sys_device qemuedu_dma\n");
		goto err_create_sysdev_dma;
	}

	if (pci_enable_device(pdev) < 0) {
		rv = -EINVAL;
		dev_err(&(pdev->dev), "pci_enable_device\n");
		goto err_enable;
	}

	/* enable bus master capability */
	pci_set_master(pdev);

	if (pci_request_region(pdev, bar_idx, MODULE_NAME)) {
		rv = -EINVAL;
		dev_err(&(pdev->dev), "pci_request_region\n");
		goto err_regions;
	}

	bar_start = pci_resource_start(pdev, bar_idx);
	bar_len = pci_resource_len(pdev, bar_idx);
	if (bar_len == 0) {
		rv = -EINVAL;
		dev_err(&(pdev->dev), "pci_resource_len 0\n");
		goto err_regions;
	}

	qpdev->bar[bar_idx] = pci_iomap(pdev, bar_idx, bar_len);
	if (!qpdev->bar[bar_idx]) {
		rv = -EINVAL;
		dev_err(&(pdev->dev), "pci_iomap\n");
		goto err_map;
	}
	dev_info(&(pdev->dev), "BAR%d mapped at 0x%px, start=0x%llx, length=%llu\n", bar_idx, qpdev->bar[bar_idx], bar_start, bar_len);

	qpdev->cdev_reg.bar = qpdev->bar[0];

	resource_flag = pci_resource_flags(pdev, bar_idx);
	if (resource_flag & IORESOURCE_IO) {
		dev_info(&(pdev->dev), "IO port enable\n");
	}
	if (resource_flag & IORESOURCE_MEM) {
		dev_info(&(pdev->dev), "memory map enable\n");
	}
	if (resource_flag & IORESOURCE_PREFETCH) {
		dev_info(&(pdev->dev), "prefetchable\n");
	}
	if (resource_flag & IORESOURCE_READONLY) {
		dev_info(&(pdev->dev), "readonly\n");
	}

	rv = set_dma_mask(pdev);
	if (rv != 0) {
		rv = -EINVAL;
		goto err_mask;
	}

	dma_vaddr = dma_alloc_coherent(&(pdev->dev), DMA_SIZE, &dma_handle, GFP_KERNEL);
	if (!dma_vaddr) {
		rv = -EINVAL;
		goto err_mask;
	}
	qpdev->cdev_dma.dma.vaddr = dma_vaddr;
	qpdev->cdev_dma.dma.handle = dma_handle;

	rv = msi_msix_capable(pdev, PCI_CAP_ID_MSI);
	if (rv) {
		dev_info(&(pdev->dev), "pci_enable_msi()\n");
		rv = pci_enable_msi(pdev);
		if (rv < 0) {
			dev_info(&(pdev->dev), "Couldn't enable MSI mode: %d\n", rv);
		} else {
			dev_info(&(pdev->dev), "enabled MSI mode\n");
			qpdev->msi_enabled = 1;
		}
	}

	if (!qpdev->msi_enabled) {
		pci_read_config_byte(pdev, PCI_INTERRUPT_PIN, &val);
		if (val == 0) {
			dev_err(&(pdev->dev), "Legacy interrupt not supported\n");
			rv = -EINVAL;
			goto err_resources;
		}

		irq_flags = IRQF_SHARED;
	}

	rv = request_irq(pdev->irq, irq_handler, irq_flags, MODULE_NAME, qpdev);
	if (rv != 0) {
		dev_err(&(pdev->dev), "Couldn't use IRQ#%d, %d\n", pdev->irq, rv);
		rv = -EINVAL;
		goto err_resources;
	}

	dev_info(&(pdev->dev), "Using IRQ#%d with 0x%px\n", pdev->irq, qpdev);

	INIT_WORK(&qpdev->cdev_dma.dma.work, service_work);
	init_waitqueue_head(&qpdev->cdev_dma.dma.wait_queue);

	dev_set_drvdata(&pdev->dev, qpdev);
	dev_info(&(pdev->dev), "pci_probe done -- pdev 0x%px, qpdev 0x%px\n", pdev, qpdev);

	print_config(pdev);


	dev_info(&(pdev->dev), "module_param dma_mode %d\n", dma_mode);
	dev_info(&(pdev->dev), "dma_pfn_offset %lx\n", pdev->dev.dma_pfn_offset);

	return rv;

err_resources:
	dma_free_coherent(&pdev->dev, DMA_SIZE, qpdev->cdev_dma.dma.vaddr, qpdev->cdev_dma.dma.handle);
err_mask:
	if (qpdev->msi_enabled) {
		pci_disable_msi(pdev);
	}
	pci_iounmap(pdev, qpdev->bar[bar_idx]);
err_map:
	pci_release_regions(pdev);
err_regions:
	pci_disable_device(pdev);
err_enable:
	destory_sys_device(&qpdev->cdev_dma);
err_create_sysdev_dma:
	destory_sys_device(&qpdev->cdev_reg);
err_create_sysdev_reg:
	cdev_del(&qpdev->cdev_dma.cdev);
err_add_cdev_dma:
	cdev_del(&qpdev->cdev_reg.cdev);
err_add_cdev_reg:
	unregister_chrdev_region(dev, MINOR_COUNT);
err_alloc_cdev:
	kfree(qpdev);
err:
	return rv;
}

static void pci_remove(struct pci_dev *pdev)
{
	struct qemuedu_pci_dev *qpdev;
	int bar_idx = 0;

	if (!pdev)
		return;

	dev_info(&(pdev->dev), "%s\n", __func__);

	qpdev = dev_get_drvdata(&pdev->dev);
	if (!qpdev)
		return;

	dev_info(&(pdev->dev), "pdev 0x%px, qpdev 0x%px\n", pdev, qpdev);

	dma_free_coherent(&pdev->dev, DMA_SIZE, qpdev->cdev_dma.dma.vaddr, qpdev->cdev_dma.dma.handle);
	free_irq(pdev->irq, qpdev);

	if (qpdev->msi_enabled) {
		pci_disable_msi(pdev);
	}

	pci_iounmap(pdev, qpdev->bar[bar_idx]);
	pci_release_regions(pdev);
	pci_disable_device(pdev);
	destory_sys_device(&qpdev->cdev_reg);
	destory_sys_device(&qpdev->cdev_dma);
	cdev_del(&qpdev->cdev_reg.cdev);
	cdev_del(&qpdev->cdev_dma.cdev);
	unregister_chrdev_region(MKDEV(qpdev->major, MINOR_BASE), MINOR_COUNT);
	kfree(qpdev);

	dev_set_drvdata(&pdev->dev, NULL);
}

static struct pci_driver pci_driver = {
	.name     = MODULE_NAME,
	.id_table = pci_ids,
	.probe    = pci_probe,
	.remove   = pci_remove,
};

static int mod_init(void)
{
	s_class = class_create(THIS_MODULE, MODULE_NAME);
	if (IS_ERR(s_class)) {
		pr_err("%s: failed to create class", MODULE_NAME);
		return -EINVAL;
	}

	return pci_register_driver(&pci_driver);
}

static void mod_exit(void)
{
	pci_unregister_driver(&pci_driver);

	if (s_class)
		class_destroy(s_class);
}

module_init(mod_init);
module_exit(mod_exit);
MODULE_LICENSE("GPL");

#include "kvm/virtio-blk.h"

#include "kvm/virtio-pci-dev.h"
#include "kvm/disk-image.h"
#include "kvm/mutex.h"
#include "kvm/util.h"
#include "kvm/kvm.h"
#include "kvm/pci.h"
#include "kvm/threadpool.h"
#include "kvm/ioeventfd.h"
#include "kvm/guest_compat.h"
#include "kvm/virtio-pci.h"
#include "kvm/virtio.h"

#include <linux/vhost.h>
#include <linux/virtio_ring.h>
#include <linux/virtio_blk.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/types.h>
#include <pthread.h>

/* TODO: We can remove this after VHOST_BLK_SET_BACKEND goes in linux/vhost.h */
#define VHOST_BLK_SET_BACKEND _IOW(VHOST_VIRTIO, 0x50, struct vhost_vring_file)
#define VIRTIO_BLK_MAX_DEV		4

/*
 * the header and status consume too entries
 */
#define DISK_SEG_MAX			(VIRTIO_BLK_QUEUE_SIZE - 2)
#define VIRTIO_BLK_QUEUE_SIZE		256
#define NUM_VIRT_QUEUES			1

struct blk_dev_req {
	struct virt_queue		*vq;
	struct blk_dev			*bdev;
	struct iovec			iov[VIRTIO_BLK_QUEUE_SIZE];
	u16				out, in, head;
	struct kvm			*kvm;
};

struct blk_dev {
	pthread_mutex_t			mutex;

	struct list_head		list;

	struct virtio_device		vdev;
	struct virtio_blk_config	blk_config;
	struct disk_image		*disk;
	u32				features;

	struct virt_queue		vqs[NUM_VIRT_QUEUES];
	struct blk_dev_req		reqs[VIRTIO_BLK_QUEUE_SIZE];

	int				vhost_fd;

	pthread_t			io_thread;
	int				io_efd;

	struct kvm			*kvm;
};

static LIST_HEAD(bdevs);
static int compat_id = -1;

void virtio_blk_complete(void *param, long len)
{
	struct blk_dev_req *req = param;
	struct blk_dev *bdev = req->bdev;
	int queueid = req->vq - bdev->vqs;
	u8 *status;

	/* status */
	status	= req->iov[req->out + req->in - 1].iov_base;
	*status	= (len < 0) ? VIRTIO_BLK_S_IOERR : VIRTIO_BLK_S_OK;

	mutex_lock(&bdev->mutex);
	virt_queue__set_used_elem(req->vq, req->head, len);
	mutex_unlock(&bdev->mutex);

	if (virtio_queue__should_signal(&bdev->vqs[queueid]))
		bdev->vdev.ops->signal_vq(req->kvm, &bdev->vdev, queueid);
}

static void virtio_blk_do_io_request(struct kvm *kvm, struct blk_dev_req *req)
{
	struct virtio_blk_outhdr *req_hdr;
	ssize_t block_cnt;
	struct blk_dev *bdev;
	struct iovec *iov;
	u16 out, in;

	block_cnt	= -1;
	bdev		= req->bdev;
	iov		= req->iov;
	out		= req->out;
	in		= req->in;
	req_hdr		= iov[0].iov_base;

	switch (req_hdr->type) {
	case VIRTIO_BLK_T_IN:
		block_cnt = disk_image__read(bdev->disk, req_hdr->sector,
				iov + 1, in + out - 2, req);
		break;
	case VIRTIO_BLK_T_OUT:
		block_cnt = disk_image__write(bdev->disk, req_hdr->sector,
				iov + 1, in + out - 2, req);
		break;
	case VIRTIO_BLK_T_FLUSH:
		block_cnt = disk_image__flush(bdev->disk);
		virtio_blk_complete(req, block_cnt);
		break;
	case VIRTIO_BLK_T_GET_ID:
		block_cnt = VIRTIO_BLK_ID_BYTES;
		disk_image__get_serial(bdev->disk,
				(iov + 1)->iov_base, &block_cnt);
		virtio_blk_complete(req, block_cnt);
		break;
	default:
		pr_warning("request type %d", req_hdr->type);
		block_cnt	= -1;
		break;
	}
}

static void virtio_blk_do_io(struct kvm *kvm, struct virt_queue *vq, struct blk_dev *bdev)
{
	struct blk_dev_req *req;
	u16 head;

	while (virt_queue__available(vq)) {
		head		= virt_queue__pop(vq);
		req		= &bdev->reqs[head];
		req->head	= virt_queue__get_head_iov(vq, req->iov, &req->out,
					&req->in, head, kvm);
		req->vq		= vq;

		virtio_blk_do_io_request(kvm, req);
	}
}

static u8 *get_config(struct kvm *kvm, void *dev)
{
	struct blk_dev *bdev = dev;

	return ((u8 *)(&bdev->blk_config));
}

static u32 get_host_features(struct kvm *kvm, void *dev)
{
	return	1UL << VIRTIO_BLK_F_SEG_MAX
		| 1UL << VIRTIO_BLK_F_FLUSH
		| 1UL << VIRTIO_RING_F_EVENT_IDX
		| 1UL << VIRTIO_RING_F_INDIRECT_DESC;
}

static void set_guest_features(struct kvm *kvm, void *dev, u32 features)
{
	struct blk_dev *bdev = dev;

	bdev->features = features;
}

static int init_vq(struct kvm *kvm, void *dev, u32 vq, u32 pfn)
{
	struct vhost_vring_state state = { .index = vq };
	struct vhost_vring_addr addr;
	struct blk_dev *bdev = dev;
	struct virt_queue *queue;
	void *p;
	int r;

	compat__remove_message(compat_id);

	queue		= &bdev->vqs[vq];
	queue->pfn	= pfn;
	p		= guest_pfn_to_host(kvm, queue->pfn);

	vring_init(&queue->vring, VIRTIO_BLK_QUEUE_SIZE, p, VIRTIO_PCI_VRING_ALIGN);

	if (bdev->vhost_fd == 0)
		return 0;

	state.num = queue->vring.num;
	r = ioctl(bdev->vhost_fd, VHOST_SET_VRING_NUM, &state);
	if (r < 0)
		die_perror("VHOST_SET_VRING_NUM failed");
	state.num = 0;
	r = ioctl(bdev->vhost_fd, VHOST_SET_VRING_BASE, &state);
	if (r < 0)
		die_perror("VHOST_SET_VRING_BASE failed");

	addr = (struct vhost_vring_addr) {
		.index = vq,
		.desc_user_addr = (u64)(unsigned long)queue->vring.desc,
		.avail_user_addr = (u64)(unsigned long)queue->vring.avail,
		.used_user_addr = (u64)(unsigned long)queue->vring.used,
	};

	r = ioctl(bdev->vhost_fd, VHOST_SET_VRING_ADDR, &addr);
	if (r < 0)
		die_perror("VHOST_SET_VRING_ADDR failed");

	return 0;
}

static void notify_vq_gsi(struct kvm *kvm, void *dev, u32 vq, u32 gsi)
{
	struct vhost_vring_file file;
	struct blk_dev *bdev = dev;
	struct kvm_irqfd irq;
	int r;

	if (bdev->vhost_fd == 0)
		return;

	irq = (struct kvm_irqfd) {
		.gsi	= gsi,
		.fd	= eventfd(0, 0),
	};
	file = (struct vhost_vring_file) {
		.index	= vq,
		.fd	= irq.fd,
	};

	r = ioctl(kvm->vm_fd, KVM_IRQFD, &irq);
	if (r < 0)
		die_perror("KVM_IRQFD failed");

	r = ioctl(bdev->vhost_fd, VHOST_SET_VRING_CALL, &file);
	if (r < 0)
		die_perror("VHOST_SET_VRING_CALL failed");

	file.fd = bdev->disk->fd;
	r = ioctl(bdev->vhost_fd, VHOST_BLK_SET_BACKEND, &file);
	if (r != 0)
		die("VHOST_BLK_SET_BACKEND failed %d", errno);

}

static void notify_vq_eventfd(struct kvm *kvm, void *dev, u32 vq, u32 efd)
{
	struct blk_dev *bdev = dev;
	struct vhost_vring_file file = {
		.index	= vq,
		.fd	= efd,
	};
	int r;

	if (bdev->vhost_fd == 0)
		return;

	r = ioctl(bdev->vhost_fd, VHOST_SET_VRING_KICK, &file);
	if (r < 0)
		die_perror("VHOST_SET_VRING_KICK failed");
}

static void *virtio_blk_thread(void *dev)
{
	struct blk_dev *bdev = dev;
	u64 data;
	int r;

	while (1) {
		r = read(bdev->io_efd, &data, sizeof(u64));
		if (r < 0)
			continue;
		virtio_blk_do_io(bdev->kvm, &bdev->vqs[0], bdev);
	}

	pthread_exit(NULL);
	return NULL;
}

static int notify_vq(struct kvm *kvm, void *dev, u32 vq)
{
	struct blk_dev *bdev = dev;
	u64 data = 1;
	int r;

	r = write(bdev->io_efd, &data, sizeof(data));
	if (r < 0)
		return r;

	return 0;
}

static int get_pfn_vq(struct kvm *kvm, void *dev, u32 vq)
{
	struct blk_dev *bdev = dev;

	return bdev->vqs[vq].pfn;
}

static int get_size_vq(struct kvm *kvm, void *dev, u32 vq)
{
	/* FIXME: dynamic */
	return VIRTIO_BLK_QUEUE_SIZE;
}

static int set_size_vq(struct kvm *kvm, void *dev, u32 vq, int size)
{
	/* FIXME: dynamic */
	return size;
}

static struct virtio_ops blk_dev_virtio_ops = (struct virtio_ops) {
	.get_config		= get_config,
	.get_host_features	= get_host_features,
	.set_guest_features	= set_guest_features,
	.init_vq		= init_vq,
	.get_pfn_vq		= get_pfn_vq,
	.get_size_vq		= get_size_vq,
	.set_size_vq		= set_size_vq,
	.notify_vq		= notify_vq,
	.notify_vq_gsi		= notify_vq_gsi,
	.notify_vq_eventfd	= notify_vq_eventfd,
};

static void virtio_blk_vhost_init(struct kvm *kvm, struct blk_dev *bdev)
{
	u64 features;
	struct vhost_memory *mem;
	int r;

	bdev->vhost_fd = open("/dev/vhost-blk", O_RDWR);
	if (bdev->vhost_fd < 0)
		die_perror("Failed openning vhost-blk device");

	mem = calloc(1, sizeof(*mem) + sizeof(struct vhost_memory_region));
	if (mem == NULL)
		die("Failed allocating memory for vhost memory map");

	mem->nregions = 1;
	mem->regions[0] = (struct vhost_memory_region) {
		.guest_phys_addr	= 0,
		.memory_size		= kvm->ram_size,
		.userspace_addr		= (unsigned long)kvm->ram_start,
	};

	r = ioctl(bdev->vhost_fd, VHOST_SET_OWNER);
	if (r != 0)
		die_perror("VHOST_SET_OWNER failed");

	r = ioctl(bdev->vhost_fd, VHOST_GET_FEATURES, &features);
	if (r != 0)
		die_perror("VHOST_GET_FEATURES failed");

	r = ioctl(bdev->vhost_fd, VHOST_SET_FEATURES, &features);
	if (r != 0)
		die_perror("VHOST_SET_FEATURES failed");
	r = ioctl(bdev->vhost_fd, VHOST_SET_MEM_TABLE, mem);
	if (r != 0)
		die_perror("VHOST_SET_MEM_TABLE failed");

	bdev->vdev.use_vhost = true;

	free(mem);
}


static int virtio_blk__init_one(struct kvm *kvm, struct disk_image *disk)
{
	struct blk_dev *bdev;
	unsigned int i;

	if (!disk)
		return -EINVAL;

	bdev = calloc(1, sizeof(struct blk_dev));
	if (bdev == NULL)
		return -ENOMEM;

	*bdev = (struct blk_dev) {
		.mutex			= PTHREAD_MUTEX_INITIALIZER,
		.disk			= disk,
		.blk_config		= (struct virtio_blk_config) {
			.capacity	= disk->size / SECTOR_SIZE,
			.seg_max	= DISK_SEG_MAX,
		},
		.io_efd			= eventfd(0, 0),
		.kvm			= kvm,
	};

	virtio_init(kvm, bdev, &bdev->vdev, &blk_dev_virtio_ops,
		    VIRTIO_PCI, PCI_DEVICE_ID_VIRTIO_BLK, VIRTIO_ID_BLOCK, PCI_CLASS_BLK);

	list_add_tail(&bdev->list, &bdevs);

	for (i = 0; i < ARRAY_SIZE(bdev->reqs); i++) {
		bdev->reqs[i].bdev = bdev;
		bdev->reqs[i].kvm = kvm;
	}

	disk_image__set_callback(bdev->disk, virtio_blk_complete);

	if (disk->use_vhost)
		virtio_blk_vhost_init(kvm, bdev);
	else
		pthread_create(&bdev->io_thread, NULL, virtio_blk_thread, bdev);

	if (compat_id == -1)
		compat_id = virtio_compat_add_message("virtio-blk", "CONFIG_VIRTIO_BLK");

	return 0;
}

static int virtio_blk__exit_one(struct kvm *kvm, struct blk_dev *bdev)
{
	list_del(&bdev->list);
	free(bdev);

	return 0;
}

int virtio_blk__init(struct kvm *kvm)
{
	int i, r = 0;

	for (i = 0; i < kvm->nr_disks; i++) {
		if (kvm->disks[i]->wwpn)
			continue;
		r = virtio_blk__init_one(kvm, kvm->disks[i]);
		if (r < 0)
			goto cleanup;
	}

	return 0;
cleanup:
	return virtio_blk__exit(kvm);
}
virtio_dev_init(virtio_blk__init);

int virtio_blk__exit(struct kvm *kvm)
{
	while (!list_empty(&bdevs)) {
		struct blk_dev *bdev;

		bdev = list_first_entry(&bdevs, struct blk_dev, list);
		virtio_blk__exit_one(kvm, bdev);
	}

	return 0;
}
virtio_dev_exit(virtio_blk__exit);

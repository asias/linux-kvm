#include "kvm/virtio-vsock.h"
#include "kvm/virtio-pci-dev.h"
#include "kvm/disk-image.h"
#include "kvm/kvm.h"
#include "kvm/pci.h"
#include "kvm/ioeventfd.h"
#include "kvm/guest_compat.h"
#include "kvm/virtio-pci.h"
#include "kvm/virtio.h"

#include <linux/kernel.h>
#include <linux/vhost.h>

#define VIRTIO_VSOCK_QUEUE_SIZE		128
#define NUM_VIRT_QUEUES			3

#define VIRTIO_ID_VSOCK			13

#define VHOST_VSOCK_SET_GUEST_CID _IOW(VHOST_VIRTIO, 0x60, __u32)

static LIST_HEAD(sdevs);
static int compat_id = -1;

struct virtio_vsock_config {
	u32 guest_cid;
	u32 max_virtqueue_pairs;
} __packed;

struct vsock_dev {
	struct virt_queue		vqs[NUM_VIRT_QUEUES];
	struct virtio_vsock_config	config;
	u32				features;
	int				vhost_fd;
	struct virtio_device		vdev;
	struct list_head		list;
	struct kvm			*kvm;
};

static u8 *get_config(struct kvm *kvm, void *dev)
{
	struct vsock_dev *sdev = dev;

	return ((u8 *)(&sdev->config));
}

static u32 get_host_features(struct kvm *kvm, void *dev)
{
	return 1UL << VIRTIO_RING_F_INDIRECT_DESC;
}

static void set_guest_features(struct kvm *kvm, void *dev, u32 features)
{
	struct vsock_dev *sdev = dev;

	sdev->features = features;
}

static int init_vq(struct kvm *kvm, void *dev, u32 vq, u32 page_size, u32 align,
		   u32 pfn)
{
	struct vhost_vring_state state = { .index = vq };
	struct vhost_vring_addr addr;
	struct vsock_dev *sdev = dev;
	struct virt_queue *queue;
	void *p;
	int r;

	compat__remove_message(compat_id);

	queue		= &sdev->vqs[vq];
	queue->pfn	= pfn;
	p		= guest_flat_to_host(kvm, queue->pfn * page_size);

	vring_init(&queue->vring, VIRTIO_VSOCK_QUEUE_SIZE, p, align);

	if (!sdev->vhost_fd)
		return 0;

	state.num = queue->vring.num;
	r = ioctl(sdev->vhost_fd, VHOST_SET_VRING_NUM, &state);
	if (r < 0)
		die_perror("VHOST_SET_VRING_NUM failed");
	state.num = 0;
	r = ioctl(sdev->vhost_fd, VHOST_SET_VRING_BASE, &state);
	if (r < 0)
		die_perror("VHOST_SET_VRING_BASE failed");

	addr = (struct vhost_vring_addr) {
		.index			= vq,
		.desc_user_addr		= (u64)(unsigned long)queue->vring.desc,
		.avail_user_addr	= (u64)(unsigned long)queue->vring.avail,
		.used_user_addr		= (u64)(unsigned long)queue->vring.used,
	};

	r = ioctl(sdev->vhost_fd, VHOST_SET_VRING_ADDR, &addr);
	if (r < 0)
		die_perror("VHOST_SET_VRING_ADDR failed");

	return 0;
}

static void notify_vq_gsi(struct kvm *kvm, void *dev, u32 vq, u32 gsi)
{
	u32 guest_cid = kvm->cfg.cid;
	struct vhost_vring_file file;
	struct vsock_dev *sdev = dev;
	struct kvm_irqfd irq;
	int r;

	if (!sdev->vhost_fd)
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

	r = ioctl(sdev->vhost_fd, VHOST_SET_VRING_CALL, &file);
	if (r < 0)
		die_perror("VHOST_SET_VRING_CALL failed");

	if (vq > 0)
		return;

	r = ioctl(sdev->vhost_fd, VHOST_VSOCK_SET_GUEST_CID, &guest_cid);
	if (r)
		die("VHOST_VSOCK_SET_GUEST_CID failed %d", errno);
}

static void notify_vq_eventfd(struct kvm *kvm, void *dev, u32 vq, u32 efd)
{
	struct vsock_dev *sdev = dev;
	struct vhost_vring_file file = {
		.index	= vq,
		.fd	= efd,
	};
	int r;

	if (!sdev->vhost_fd)
		return;

	r = ioctl(sdev->vhost_fd, VHOST_SET_VRING_KICK, &file);
	if (r < 0)
		die_perror("VHOST_SET_VRING_KICK failed");
}

static int notify_vq(struct kvm *kvm, void *dev, u32 vq)
{
	return 0;
}

static int get_pfn_vq(struct kvm *kvm, void *dev, u32 vq)
{
	struct vsock_dev *sdev = dev;

	return sdev->vqs[vq].pfn;
}

static int get_size_vq(struct kvm *kvm, void *dev, u32 vq)
{
	return VIRTIO_VSOCK_QUEUE_SIZE;
}

static int set_size_vq(struct kvm *kvm, void *dev, u32 vq, int size)
{
	return size;
}

static struct virtio_ops vsock_dev_virtio_ops = (struct virtio_ops) {
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

static void virtio_vsock_vhost_init(struct kvm *kvm, struct vsock_dev *sdev)
{
	struct vhost_memory *mem;
	u64 features;
	int r;

	sdev->vhost_fd = open("/dev/vhost-vsock", O_RDWR);
	if (sdev->vhost_fd < 0)
		die_perror("Failed openning vhost-vsock device");

	mem = calloc(1, sizeof(*mem) + sizeof(struct vhost_memory_region));
	if (!mem)
		die("Failed allocating memory for vhost memory map");

	mem->nregions = 1;
	mem->regions[0] = (struct vhost_memory_region) {
		.guest_phys_addr	= 0,
		.memory_size		= kvm->ram_size,
		.userspace_addr		= (unsigned long)kvm->ram_start,
	};

	r = ioctl(sdev->vhost_fd, VHOST_SET_OWNER);
	if (r != 0)
		die_perror("VHOST_SET_OWNER failed");

	r = ioctl(sdev->vhost_fd, VHOST_GET_FEATURES, &features);
	if (r != 0)
		die_perror("VHOST_GET_FEATURES failed");

	r = ioctl(sdev->vhost_fd, VHOST_SET_FEATURES, &features);
	if (r != 0)
		die_perror("VHOST_SET_FEATURES failed");
	r = ioctl(sdev->vhost_fd, VHOST_SET_MEM_TABLE, mem);
	if (r != 0)
		die_perror("VHOST_SET_MEM_TABLE failed");

	sdev->vdev.use_vhost = true;

	free(mem);
}


static int virtio_vsock_init_one(struct kvm *kvm)
{
	struct vsock_dev *sdev;

	sdev = calloc(1, sizeof(struct vsock_dev));
	if (!sdev)
		return -ENOMEM;

	*sdev = (struct vsock_dev) {
		.config	= (struct virtio_vsock_config) {
			.max_virtqueue_pairs	= 1,
			.guest_cid		= kvm->cfg.cid,
		},
		.kvm				= kvm,
	};

	virtio_init(kvm, sdev, &sdev->vdev, &vsock_dev_virtio_ops,
		    VIRTIO_DEFAULT_TRANS, PCI_DEVICE_ID_VIRTIO_VSOCK,
		    VIRTIO_ID_VSOCK, PCI_CLASS_BLK);

	list_add_tail(&sdev->list, &sdevs);

	virtio_vsock_vhost_init(kvm, sdev);

	if (compat_id == -1)
		compat_id = virtio_compat_add_message("virtio-vsock", "CONFIG_VIRTIO_VSOCK");

	return 0;
}

static int virtio_vsock_exit_one(struct kvm *kvm, struct vsock_dev *sdev)
{

	list_del(&sdev->list);
	free(sdev);

	return 0;
}

int virtio_vsock_init(struct kvm *kvm)
{
	int r = 0;

	if (kvm->cfg.cid <= 0)
		return 0;

	r = virtio_vsock_init_one(kvm);
	if (r < 0)
		goto cleanup;

	return 0;
cleanup:
	return virtio_vsock_exit(kvm);
}
virtio_dev_init(virtio_vsock_init);

int virtio_vsock_exit(struct kvm *kvm)
{
	while (!list_empty(&sdevs)) {
		struct vsock_dev *sdev;

		sdev = list_first_entry(&sdevs, struct vsock_dev, list);
		virtio_vsock_exit_one(kvm, sdev);
	}

	return 0;
}
virtio_dev_exit(virtio_vsock_exit);

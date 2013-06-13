#ifndef KVM__SCSI_VIRTIO_H
#define KVM__SCSI_VIRTIO_H

struct kvm;
int virtio_vsock_init(struct kvm *kvm);
int virtio_vsock_exit(struct kvm *kvm);

#endif /* KVM__SCSI_VIRTIO_H */

#include "kvm/disk-image.h"
#include "kvm/read-write.h"
#include "kvm/sheepdog_proto.h"
#include "linux/kernel.h"
#include "kvm/barrier.h"

#include <linux/err.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

struct sd_info {
	struct sheepdog_inode inode;
	struct sockaddr_in addr;
	int fd;
};

static struct sd_rsp *sd_send_req(struct sd_info *sd, struct sd_req *req, char *buf, int wlen, int rlen)
{
	int ret, hdr_len;

	hdr_len = sizeof(struct sd_req);

	/* send hdr */
	ret = write(sd->fd, req, hdr_len);
	if (ret != hdr_len)
		pr_warning("tcp send error");
	/* send data */
	if (wlen) {
		ret = write_in_full(sd->fd, buf, wlen);
		if (ret != wlen)
			pr_warning("tcp send error");
	}

	/* receive hdr */
	ret = read(sd->fd, req, hdr_len);
	if (ret != hdr_len)
		pr_warning("tcp send error");
	/* receive data */
	if (rlen) {
		ret = read_in_full(sd->fd, buf, rlen);
		if (ret != rlen)
			pr_warning("tcp send error");
	}

	return (struct sd_rsp*)req;
}

static u32 sd_get_vdi_id(struct sd_info *sd)
{
	struct sd_req  req;
	struct sd_rsp  *rsp;
	char buf[SD_MAX_VDI_LEN + SD_MAX_VDI_TAG_LEN];

	memset(&req, 0, sizeof(req));
	req.opcode = SD_OP_LOCK_VDI;
	req.proto_ver = SD_PROTO_VER;
	req.data_length = 512;
	req.vdi.snapid = 0;
	req.flags = SD_FLAG_CMD_WRITE;

	memset(buf, 0, sizeof(buf));
	strncpy(buf, "small", SD_MAX_VDI_LEN);
	strncpy(buf, "test", SD_MAX_VDI_LEN);
	//strncpy(buf + SD_MAX_VDI_LEN, NULL, SD_MAX_VDI_TAG_LEN);

	rsp = sd_send_req(sd, &req, buf, SD_MAX_VDI_LEN + SD_MAX_VDI_TAG_LEN, 0);

	if (rsp->result != 0)
		pr_err("sd_get_vdi_id: sd_rw_object error =%d", rsp->result);

	return rsp->vdi.vdi_id;
}


static struct sd_rsp *sd_rw_object(struct sd_info *sd, u64 oid, u64 offset, char *buf, int len, bool write, bool create)
{
	static u64 id;
	struct sd_req  req;
	struct sd_rsp  *rsp;
	int wlen, rlen;

	memset(&req, 0, sizeof(req));
	if (write) {
		wlen = len;
		rlen = 0;
		req.flags = SD_FLAG_CMD_WRITE;
		if (create)
			req.opcode = SD_OP_CREATE_AND_WRITE_OBJ;
		else
			req.opcode = SD_OP_WRITE_OBJ;
	} else {
		wlen = 0;
		rlen = len;
		req.opcode = SD_OP_READ_OBJ;
	}
	req.id = id++;
	req.proto_ver = SD_PROTO_VER;
	req.data_length = len;
	req.obj.offset = offset;
	req.obj.oid = oid;
	req.obj.copies = sd->inode.nr_copies;
	rsp = sd_send_req(sd, &req, buf, wlen, rlen);

	return rsp;
}

static ssize_t sd_image_read(struct disk_image *disk, u64 sector, const struct iovec *iov,
				int iovcount, void *param)
{
	struct sd_info *sd = disk->priv;
	struct sheepdog_inode *inode = &sd->inode;
	u64 off, len, total, done = 0;
	u64 oid;
	u32 idx, vdi_id;
	char *buf, *pos;

	idx = sector * SECTOR_SIZE / SD_DATA_OBJ_SIZE;
	off = sector * SECTOR_SIZE % SD_DATA_OBJ_SIZE;

	total = get_iov_size(iov, iovcount);
	buf = malloc(total);
	if (!buf)
		return -ENOMEM;
	pos = buf;

	while (done != total) {
		/* vdi_id to data object id */
		vdi_id = inode->data_vdi_id[idx];
		oid = vid_to_data_oid(vdi_id, idx);
		len = min(total - done, SD_DATA_OBJ_SIZE - off);
		sd_rw_object(sd, oid, off, pos, len, false, false);
		done += len;
		pos += len;
		idx++;
		off = 0;
	}

	iov_from_buf(iov, iovcount, buf, total);

	free(buf);

	return total;
}

static ssize_t sd_image_write(struct disk_image *disk, u64 sector, const struct iovec *iov,
				int iovcount, void *param)
{
	struct sd_info *sd = disk->priv;
	struct sheepdog_inode *inode = &sd->inode;
	u64 off, len, total, done = 0;
	u64 oid;
	u32 idx, vdi_id;
	char *buf, *pos;
	struct sd_rsp *rsp;
	bool create = false;

	idx = sector * SECTOR_SIZE / SD_DATA_OBJ_SIZE;
	off = sector * SECTOR_SIZE % SD_DATA_OBJ_SIZE;

	total = get_iov_size(iov, iovcount);
	buf = malloc(total);
	if (!buf)
		return -ENOMEM;
	memset(buf, 0, total);
	pos = buf;
	iov_to_buf(iov, iovcount, buf, total);
	while (done != total) {
		/* vdi_id to data object id */
		vdi_id = inode->data_vdi_id[idx];
		if (!vdi_id) {
			create = true;
			oid = vid_to_data_oid(inode->vdi_id, idx);
		} else {
			oid = vid_to_data_oid(vdi_id, idx);
		}
		len = min(total - done, SD_DATA_OBJ_SIZE - off);
		rsp = sd_rw_object(sd, oid, off, pos, len, true, create);
		if (rsp->result != 0)
			pr_err("sd_image_write: sd_rw_object error =%d", rsp->result);
		done += len;
		pos += len;
		idx++;
		off = 0;
	}


	free(buf);

	return total;
}

static int sd_image_close(struct disk_image *disk)
{
	int ret = 0;

	return ret;
}

static struct disk_image_operations sd_image_ops = {
	.read	= sd_image_read,
	.write	= sd_image_write,
	.close	= sd_image_close,
};

struct disk_image *sd_image__probe(void)
{
	struct disk_image *disk;
	struct sd_info *sd;
	struct sd_rsp *rsp;
	u32 vdi_id;
	int ret;

	disk = malloc(sizeof(struct disk_image));
	if (!disk)
		return ERR_PTR(-ENOMEM);

	sd = malloc(sizeof(struct sd_info));
	if (!sd) {
		free(disk);
		return ERR_PTR(-ENOMEM);
	}

	sd->fd				= socket(AF_INET, SOCK_STREAM, 0);
	sd->addr.sin_family		= AF_INET;
	sd->addr.sin_addr.s_addr	= inet_addr("127.0.0.1");
	sd->addr.sin_port		= htons(7000);

	ret = connect(sd->fd, (struct sockaddr *)&sd->addr, sizeof(sd->addr));
	if (ret) {
		free(disk);
		free(sd);
		return NULL;
	}
	disk->fd = sd->fd;
	disk->sheepdog = true;
	disk->ops = &sd_image_ops;
	disk->async = 0;
	disk->priv = sd;

	vdi_id = sd_get_vdi_id(sd);
	rsp = sd_rw_object(sd, vid_to_vdi_oid(vdi_id), 0, (char *)&sd->inode, sizeof(sd->inode), false, false);
	if (rsp->result != 0)
		pr_err("sd_image__probe: sd_rw_object error =%d", rsp->result);

	disk->size = sd->inode.vdi_size;

	return disk;
}

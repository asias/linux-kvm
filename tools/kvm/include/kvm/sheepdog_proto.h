/*
 * Copyright (C) 2009-2011 Nippon Telegraph and Telephone Corporation.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */
#ifndef __SHEEPDOG_PROTO_H__
#define __SHEEPDOG_PROTO_H__

#include <inttypes.h>
#include <stdint.h>
#include "util.h"

#define SD_PROTO_VER 0x01

#define SD_LISTEN_PORT 7000

#define SD_OP_CREATE_AND_WRITE_OBJ  0x01
#define SD_OP_READ_OBJ       0x02
#define SD_OP_WRITE_OBJ      0x03
#define SD_OP_REMOVE_OBJ     0x04

#define SD_OP_NEW_VDI        0x11
#define SD_OP_LOCK_VDI       0x12
#define SD_OP_RELEASE_VDI    0x13
#define SD_OP_GET_VDI_INFO   0x14
#define SD_OP_READ_VDIS      0x15
#define SD_OP_FLUSH_VDI      0x16

#define SD_FLAG_CMD_WRITE    0x01
#define SD_FLAG_CMD_COW      0x02
#define SD_FLAG_CMD_CACHE    0x04
/* flags above 0x80 are sheepdog-internal */

#define SD_RES_SUCCESS       0x00 /* Success */
#define SD_RES_UNKNOWN       0x01 /* Unknown error */
#define SD_RES_NO_OBJ        0x02 /* No object found */
#define SD_RES_EIO           0x03 /* I/O error */
#define SD_RES_VDI_EXIST     0x04 /* VDI exists already */
#define SD_RES_INVALID_PARMS 0x05 /* Invalid parameters */
#define SD_RES_SYSTEM_ERROR  0x06 /* System error */
#define SD_RES_VDI_LOCKED    0x07 /* VDI is locked */
#define SD_RES_NO_VDI        0x08 /* No VDI found */
#define SD_RES_NO_BASE_VDI   0x09 /* No base VDI found */
#define SD_RES_VDI_READ      0x0A /* Cannot read requested VDI */
#define SD_RES_VDI_WRITE     0x0B /* Cannot write requested VDI */
#define SD_RES_BASE_VDI_READ 0x0C /* Cannot read base VDI */
#define SD_RES_BASE_VDI_WRITE   0x0D /* Cannot write base VDI */
#define SD_RES_NO_TAG        0x0E /* Requested tag is not found */
#define SD_RES_STARTUP       0x0F /* Sheepdog is on starting up */
#define SD_RES_VDI_NOT_LOCKED   0x10 /* VDI is not locked */
#define SD_RES_SHUTDOWN      0x11 /* Sheepdog is shutting down */
#define SD_RES_NO_MEM        0x12 /* Cannot allocate memory */
#define SD_RES_FULL_VDI      0x13 /* we already have the maximum VDIs */
#define SD_RES_VER_MISMATCH  0x14 /* Protocol version mismatch */
#define SD_RES_NO_SPACE      0x15 /* Server has no room for new objects */
#define SD_RES_WAIT_FOR_FORMAT  0x16 /* Sheepdog is waiting for a format operation */
#define SD_RES_WAIT_FOR_JOIN    0x17 /* Sheepdog is waiting for other nodes joining */
#define SD_RES_JOIN_FAILED   0x18 /* Target node had failed to join sheepdog */
#define SD_RES_HALT 0x19 /* Sheepdog is stopped doing IO */
#define SD_RES_FORCE_RECOVER    0x1A /* Users should not force recover this cluster */
#define SD_RES_NO_STORE         0x20 /* No targeted backend store */
#define SD_RES_NO_SUPPORT       0x21 /* Operation is not supported by backend store */
#define SD_RES_CLUSTER_RECOVERING 0x22 /* Cluster is recovering. */
#define SD_RES_OBJ_RECOVERING     0x23 /* Object is recovering */
#define SD_RES_KILLED           0x24 /* Node is killed */
#define SD_RES_OID_EXIST        0x25 /* Object ID exists already */

/* errors above 0x80 are sheepdog-internal */

/*
 * Object ID rules
 *
 *  0 - 19 (20 bits): data object space
 * 20 - 31 (12 bits): reserved data object space
 * 32 - 55 (24 bits): VDI object space
 * 56 - 59 ( 4 bits): reserved VDI object space
 * 60 - 63 ( 4 bits): object type indentifier space
 */

#define VDI_SPACE_SHIFT   32
#define VDI_BIT (1ULL << 63)
#define VMSTATE_BIT (1ULL << 62)
#define VDI_ATTR_BIT (1ULL << 61)
#define MAX_DATA_OBJS (1ULL << 20)
#define MAX_CHILDREN 1024U
#define SD_MAX_VDI_LEN 256U
#define SD_MAX_VDI_TAG_LEN 256U
#define SD_MAX_VDI_ATTR_KEY_LEN 256U
#define SD_MAX_VDI_ATTR_VALUE_LEN 65536U
#define SD_NR_VDIS   (1U << 24)
#define SD_DATA_OBJ_SIZE (1ULL << 22)
#define SD_MAX_VDI_SIZE (SD_DATA_OBJ_SIZE * MAX_DATA_OBJS)

#define SD_INODE_SIZE (sizeof(struct sheepdog_inode))
#define SD_INODE_HEADER_SIZE (sizeof(struct sheepdog_inode) - \
			      sizeof(u32) * MAX_DATA_OBJS)
#define SD_ATTR_OBJ_SIZE (sizeof(struct sheepdog_vdi_attr))
#define CURRENT_VDI_ID 0

#define STORE_LEN 16

struct sd_req {
	u8	proto_ver;
	u8	opcode;
	u16	flags;
	u32	epoch;
	u32	id;
	u32	data_length;
	union {
		struct {
			u64	oid;
			u64	cow_oid;
			u32	copies;
			u32	tgt_epoch;
			u64	offset;
		} obj;
		struct {
			u64	vdi_size;
			u32	base_vdi_id;
			u32	copies;
			u32	snapid;
		} vdi;
		u32		__pad[8];
	};
} __attribute__((packed));

struct sd_rsp {
	u8	proto_ver;
	u8	opcode;
	u16	flags;
	u32	epoch;
	u32	id;
	u32	data_length;
	u32	result;
	union {
		struct {
			u32	copies;
		} obj;
		struct {
			u32	rsvd;
			u32	vdi_id;
			u32	attr_id;
			u32	copies;
		} vdi;
		u32		__pad[7];
	};
} __attribute__((packed));

struct sheepdog_inode {
	char name[SD_MAX_VDI_LEN];
	char tag[SD_MAX_VDI_TAG_LEN];
	u64 ctime;
	u64 snap_ctime;
	u64 vm_clock_nsec;
	u64 vdi_size;
	u64 vm_state_size;
	u16 copy_policy;
	u8  nr_copies;
	u8  block_size_shift;
	u32 snap_id;
	u32 vdi_id;
	u32 parent_vdi_id;
	u32 child_vdi_id[MAX_CHILDREN];
	u32 data_vdi_id[MAX_DATA_OBJS];
} __attribute__((packed));

struct sheepdog_vdi_attr {
	char name[SD_MAX_VDI_LEN];
	char tag[SD_MAX_VDI_TAG_LEN];
	u64 ctime;
	u32 snap_id;
	u32 value_len;
	char key[SD_MAX_VDI_ATTR_KEY_LEN];
	char value[SD_MAX_VDI_ATTR_VALUE_LEN];
};

#define SHA1_LEN        20

struct snap_log {
	u32 epoch;
	u64 time;
	unsigned char sha1[SHA1_LEN];
};

/*
 * 64 bit FNV-1a non-zero initial basis
 */
#define FNV1A_64_INIT ((u64) 0xcbf29ce484222325ULL)

/*
 * 64 bit Fowler/Noll/Vo FNV-1a hash code
 */
static inline u64 fnv_64a_buf(void *buf, size_t len, u64 hval)
{
	unsigned char *bp = (unsigned char *) buf;
	unsigned char *be = bp + len;
	while (bp < be) {
		hval ^= (u64) *bp++;
		hval += (hval << 1) + (hval << 4) + (hval << 5) +
			(hval << 7) + (hval << 8) + (hval << 40);
	}
	return hval;
}

static inline u64 hash_64(u64 val, unsigned int bits)
{
	u64 hash = fnv_64a_buf(&val, sizeof(u64), FNV1A_64_INIT);

	return hash & ((1 << bits) - 1);
}

static inline int is_data_obj_writeable(struct sheepdog_inode *inode, int idx)
{
	return inode->vdi_id == inode->data_vdi_id[idx];
}

static inline int is_vdi_obj(u64 oid)
{
	return !!(oid & VDI_BIT);
}

static inline int is_vmstate_obj(u64 oid)
{
	return !!(oid & VMSTATE_BIT);
}

static inline int is_vdi_attr_obj(u64 oid)
{
	return !!(oid & VDI_ATTR_BIT);
}

static inline int is_data_obj(u64 oid)
{
	return !is_vdi_obj(oid) && !is_vmstate_obj(oid) &&
		!is_vdi_attr_obj(oid);
}

static inline size_t get_objsize(u64 oid)
{
	if (is_vdi_obj(oid))
		return SD_INODE_SIZE;

	if (is_vdi_attr_obj(oid))
		return SD_ATTR_OBJ_SIZE;

	return SD_DATA_OBJ_SIZE;
}

static inline u64 data_oid_to_idx(u64 oid)
{
	return oid & (MAX_DATA_OBJS - 1);
}

static inline u64 vid_to_vdi_oid(u32 vid)
{
	return VDI_BIT | ((u64)vid << VDI_SPACE_SHIFT);
}

static inline u64 vid_to_data_oid(u32 vid, u32 idx)
{
	return ((u64)vid << VDI_SPACE_SHIFT) | idx;
}

static inline u32 oid_to_vid(u64 oid)
{
	return (~VDI_BIT & oid) >> VDI_SPACE_SHIFT;
}

static inline u64 vid_to_attr_oid(u32 vid, u32 attrid)
{
	return ((u64)vid << VDI_SPACE_SHIFT) | VDI_ATTR_BIT | attrid;
}

#endif

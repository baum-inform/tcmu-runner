#define _GNU_SOURCE
#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <strings.h>
#include <fcntl.h>
#include <errno.h>
#include <assert.h>
#include <inttypes.h>
#include <scsi/scsi.h>

#ifdef USE_FTCLIENT
#   include <openssl/md5.h>
#   include "ftransferc/client.h"
#   define OBJECT_NAME_LEN  (MD5_DIGEST_LENGTH * 2 + 1)
#   define DEV_OPEN         ftopen
#   define DEV_CLOSE        ftclose
#   define DEV_TRUNCATE     ftftruncate
#   define TCMU_ERRNO(...)  tcmu_err(__VA_ARGS__);
#else
#   include <stdio.h>
#   include <sys/types.h>
#   include <sys/stat.h>
#   include <unistd.h>
#   include <limits.h>
#   include <linux/limits.h>
#   define OBJECT_NAME_LEN  PATH_MAX
#   define STORAGE_PATH    "/var/lib/iscsi_disk"
#   define DEV_OPEN         open
#   define DEV_CLOSE        close
#   define DEV_TRUNCATE     ftruncate
#   define TCMU_ERRNO(...) do {                             \
    const int _errno = errno;                               \
    tcmu_err(__VA_ARGS__);                                  \
    tcmu_err("errno: %d - %s\n", _errno, strerror(_errno)); \
} while(0);
#endif  // USE_FTCLIENT

// tcmu-runner headers
#include "scsi_defs.h"
#include "libtcmu.h"
#include "tcmu-runner.h"
#include "tcmur_device.h"

#define UNUSED(v)       ((void)(v))
#define BADFD           -1
#define SWARM_BLOCK_SIZE    4096

struct swarm_dev_s {
    char objname[OBJECT_NAME_LEN];
    off_t size;             // device size
    uint32_t block_size;
    int fd;                 // swarm file descriptor
};

static void swarm_close(struct swarm_dev_s *swarm_dev)
{
    assert(swarm_dev);
    if(swarm_dev->fd != BADFD) {
        DEV_CLOSE(swarm_dev->fd);
        swarm_dev->fd = BADFD;
    }
}

#ifdef USE_FTCLIENT

static char* swarm_tcmu_make_devname(const char * devname)
{
    char *objname = NULL;
    assert(devname);
    if(asprintf(& objname, "iscsi://%s/", devname) == -1) {
        return NULL;
    }
    return objname;
}

// buf length must be at least (MD5_DIGEST_LENGTH * 2 + 1)
static void md5(const char *data, char *buf) {
    unsigned char digest[MD5_DIGEST_LENGTH] = {0};
    MD5((const uint8_t*)data, strlen(data), digest);
    for(int i = 0; i < MD5_DIGEST_LENGTH; ++i, buf += 2) {
        sprintf(buf, "%02x", (unsigned int)digest[i]);
    }
}

/*
 * Генерация хэша объекта по имени.
 * Используется MD5.
 */
static void make_objhash(const char * objname, char * objhash) {
    assert(objhash && objname);
    bzero(objhash, OBJECT_NAME_LEN);
    md5(objname, objhash);
    objhash[OBJECT_NAME_LEN - 1] = '\0';
    tcmu_info("%s --md5 hash-> %s\n", objname, objhash);
}

// Для переоткрытия объекта при смене чтения/записи
//static int _swarm_open(swarm_dev_s *swarm_dev, int oflags)
//{
//    assert(swarm_dev);
//    if(oflags == swarm_dev->oflags && swarm_dev->fd != BADFD) {
//        return 0;
//    }
//    if (swarm_dev->fd != BADFD) {
//        swarm_close(swarm_dev);
//    }
//    swarm_dev->oflags = oflags;
//    swarm_dev->fd = ftopen(swarm_dev->objname, oflags);
//    if (swarm_dev->fd == BADFD) {
//        TCMU_ERRNO("Could not open file: %s\n", swarm_dev->objname);
//        return -1;
//    }
//    if(ftftruncate(swarm_dev->fd, swarm_dev->size) == -1) {
//        TCMU_ERRNO("Error truncate file to size (%" PRIi64 "): %s\n", swarm_dev->size, swarm_dev->objname);
//        return -1;
//    }
//    return 0;
//}

#endif  // USE_FTCLIENT

static int swarm_ftruncate(struct swarm_dev_s *swarm_dev, off_t new_size)
{
    assert(swarm_dev && swarm_dev->fd > BADFD && swarm_dev->block_size > 0 && new_size > 0);
    // Размер устройства должен быть кратен размеру блока
    new_size += new_size % swarm_dev->block_size == 0 ? 0 : swarm_dev->block_size - new_size % swarm_dev->block_size;
    if(new_size == swarm_dev->size) {
        tcmu_dbg("Truncating no required.\n");
        return 0;
    }
    if(DEV_TRUNCATE(swarm_dev->fd, new_size) == -1) {
        TCMU_ERRNO("Error truncate file to size (%" PRIi64 "): %s\n", new_size, swarm_dev->objname);
        return -1;
    }
    swarm_dev->size = new_size;
    tcmu_dbg("Truncated object to: %" PRIuPTR " bytes.\n", swarm_dev->size);
    return 0;
}

static int swarm_open(struct swarm_dev_s *swarm_dev, off_t new_size)
{
    assert(swarm_dev && strlen(swarm_dev->objname) > 0 && swarm_dev->fd == BADFD);
#ifdef USE_FTCLIENT
    swarm_dev->size = 0;  // TODO: Как узнать размер объекта в SWARM? Пока буду при каждом открытии вызывать ftftruncate()
//  TODO: O_CREAT | O_RDWR, when in ftopen() will supported O_RDWR
    swarm_dev->fd = DEV_OPEN(swarm_dev->objname, O_CREAT | O_WRONLY, 0660);
#else // USE_FTCLIENT
    {
        struct stat sb;
        memset(&sb, 0, sizeof(sb));
        if (stat(swarm_dev->objname, &sb) == -1) {
            if(errno != ENOENT) {
                TCMU_ERRNO("Get stat error: %s\n", swarm_dev->objname);
                return -1;
            }
        }
        swarm_dev->size = sb.st_size;
    }
    swarm_dev->fd = DEV_OPEN(swarm_dev->objname, O_CREAT | O_RDWR, 0660);
#endif  // USE_FTCLIENT
    if (swarm_dev->fd == BADFD) {
        TCMU_ERRNO("Could not open file: %s\n", swarm_dev->objname);
        return -1;
    }
    if(swarm_ftruncate(swarm_dev, new_size) != 0) {
        swarm_close(swarm_dev);
        return -1;
    }
    return 0;
}

static void swarm_tcmu_close(struct tcmu_device *dev)
{
    struct swarm_dev_s *swarm_dev = tcmur_dev_get_private(dev);
    assert(swarm_dev);
    swarm_close(swarm_dev);
    free(swarm_dev);
}

static int swarm_tcmu_open(struct tcmu_device *dev, bool reopen)
{
    struct swarm_dev_s *swarm_dev = NULL;
    int ret = 0;
    off_t dev_size = 0;
    const char * devname = NULL;

    assert(dev);

    if(reopen) {
        swarm_dev = tcmur_dev_get_private(dev);
        assert(swarm_dev);
        swarm_close(swarm_dev);
        memset(swarm_dev, 0, sizeof(*swarm_dev));
    } else {
        swarm_dev = calloc(1, sizeof(*swarm_dev));
        if (swarm_dev == NULL) {
            tcmu_err("No enough memory for swarm_dev.\n");
            return -ENOMEM;
        }
        tcmur_dev_set_private(dev, swarm_dev);
    }

    swarm_dev->fd = BADFD;

    do {
        swarm_dev->block_size = tcmu_dev_get_block_size(dev);
        if(swarm_dev->block_size != SWARM_BLOCK_SIZE) {
#ifdef HANDLER_SWARM
            tcmu_warn("Block size is bad: %u. Set new block size: %u\n", swarm_dev->block_size, SWARM_BLOCK_SIZE);
            swarm_dev->block_size = SWARM_BLOCK_SIZE;
            tcmu_dev_set_block_size(dev, SWARM_BLOCK_SIZE);
#else
            tcmu_err("Block size is bad: %u\n", swarm_dev->block_size);
            ret = -1;
            break;
#endif
        }
        dev_size = (off_t)tcmu_cfgfs_dev_get_info_u64(dev, "Size", &ret);
        if (ret < 0 || dev_size <= 0) {
            tcmu_err("Could not get device size\n");
            break;
        }

         // tcmu_dev_get_cfgstring(dev) returns a string of the form: subtype/cfgstring
        devname = tcmu_dev_get_cfgstring(dev);
        if (devname == NULL) {
            tcmu_err("No device name found in cfgstring\n");
            ret = -EINVAL;
            break;
        }
        devname = strchr(devname, '/') + 1; // get past subtype/
        tcmu_info("Device name: %s\n", devname);

#ifdef USE_FTCLIENT
        {
            char * const simple_name = swarm_tcmu_make_devname(devname);
            if (simple_name == NULL) {
                tcmu_err("Error make SWARM device name\n");
                ret = -ENOMEM;
                break;
            }
            tcmu_info("Object name: %s\n", simple_name);
            make_objhash(simple_name, swarm_dev->objname);
            tcmu_info("Object hash: %s\n", swarm_dev->objname);
            free(simple_name);
        }
#else   // USE_FTCLIENT
        strncpy(swarm_dev->objname, devname, sizeof(swarm_dev->objname));
        tcmu_info("Object name: %s\n", swarm_dev->objname);
#endif  // USE_FTCLIENT

//        tcmu_dev_set_write_cache_enabled(dev, 1);

        if(swarm_open(swarm_dev, dev_size) == -1) {
            ret = -1;
            break;
        }
        tcmu_info("Device size: %" PRIu64 " bytes, \tBlock size: %u bytes\n", swarm_dev->size, swarm_dev->block_size);

        return 0;

    } while(0);
    free(swarm_dev);
    return ret;
}
static int swarm_tcmu_read(struct tcmu_device *dev, struct tcmur_cmd *cmd,
		     struct iovec *iov, size_t iov_cnt, size_t length,
		     off_t offset)
{
    
    struct swarm_dev_s *swarm_dev = NULL;
    int ret = 0;

    assert(dev && iov && iov_cnt > 0 && offset >= 0);
    swarm_dev = tcmur_dev_get_private(dev);

    UNUSED(cmd);
    assert(swarm_dev && length % swarm_dev->block_size == 0);

    if(((size_t)offset + length) > (size_t)swarm_dev->size) {
        tcmu_err("Out of bounds on read: %" PRIuPTR ".\n", (size_t)offset + length);
        return TCMU_STS_RD_ERR;
    }
    if(length == 0) {
        tcmu_warn("Zero length read.\n");
        return TCMU_STS_OK;
    }

    ret = TCMU_STS_OK;

    tcmu_dbg("Read iov_cnt: %" PRIuPTR "\t length: %" PRIuPTR "\t offset: %" PRId64 "\n", iov_cnt, length, offset);
#ifdef USE_FTCLIENT
    for(size_t iov_idx = 0; iov_idx < iov_cnt; ++iov_idx) {
        ssize_t read_bytes = ftpread(swarm_dev->fd, iov[iov_idx].iov_base, iov[iov_idx].iov_len, offset);
        if (read_bytes == -1) {
            TCMU_ERRNO("Read failed.\n");
            ret = TCMU_STS_RD_ERR;
            break;
        }
        if (read_bytes == 0) {
            TCMU_ERRNO("\nEOF.");
            ret = TCMU_STS_RD_ERR;
            break;
        }
        assert((uint64_t)read_bytes == iov[iov_idx].iov_len);
        offset += read_bytes;
    }
#else   // USE_FTCLIENT
    while (length) {
        ssize_t read_bytes = preadv(swarm_dev->fd, iov, (int)iov_cnt, offset);
        if (read_bytes == -1) {
            TCMU_ERRNO("Read failed.\n");
            ret = TCMU_STS_RD_ERR;
            break;
        }
        if (read_bytes == 0) {
            TCMU_ERRNO("EOF.\n");
            ret = TCMU_STS_RD_ERR;
            break;
        }
        tcmu_iovec_seek(iov, (size_t)read_bytes);
        offset += read_bytes;
        length -= (size_t)read_bytes;
    }
#endif  // USE_FTCLIENT
    return ret;
}

static int swarm_tcmu_write(struct tcmu_device *dev, struct tcmur_cmd *cmd,
		      struct iovec *iov, size_t iov_cnt, size_t length,
		      off_t offset)
{
    struct swarm_dev_s *swarm_dev = NULL;
    int ret = 0;
    assert(dev && iov && iov_cnt > 0 && offset >= 0);
    swarm_dev = tcmur_dev_get_private(dev);    

    UNUSED(cmd);
    assert(swarm_dev && length % swarm_dev->block_size == 0);

    if(((size_t)offset + length) > (size_t)swarm_dev->size) {
        tcmu_err("Out of bounds on write: %" PRIuPTR ".\n", (size_t)offset + length);
        return TCMU_STS_RD_ERR;
    }
    if(length == 0) {
        tcmu_warn("Zero length write.\n");
        return TCMU_STS_OK;
    }

    ret = TCMU_STS_OK;
    tcmu_dbg("Write iov_cnt: %" PRIuPTR "\t length: %" PRIuPTR "\t offset: %" PRId64 "\n", iov_cnt, length, offset);

#ifdef USE_FTCLIENT
    for(size_t iov_idx = 0; iov_idx < iov_cnt; ++iov_idx) {
        ssize_t read_bytes = ftpwrite(swarm_dev->fd, iov[iov_idx].iov_base, iov[iov_idx].iov_len, offset);
        if (read_bytes < 0) {
            TCMU_ERRNO("Write failed.\n");
            ret = TCMU_STS_WR_ERR;
            break;
        }
        assert((uint64_t)read_bytes == iov[iov_idx].iov_len);
        offset += read_bytes;
    }
#else   // USE_FTCLIENT
    while (length) {
        ssize_t read_bytes = pwritev(swarm_dev->fd, iov, (int)iov_cnt, offset);
        if (read_bytes < 0) {
            TCMU_ERRNO("Write failed.\n");
            ret = TCMU_STS_WR_ERR;
            break;
        }
        tcmu_iovec_seek(iov, (size_t)read_bytes);
        offset += read_bytes;
        length -= (size_t)read_bytes;
    }
#endif  // USE_FTCLIENT
    return ret;
}

static int swarm_flush(struct swarm_dev_s *swarm_dev, struct tcmur_cmd *cmd)
{
    UNUSED(cmd);
#ifdef USE_FTCLIENT
    UNUSED(swarm_dev);
    // TODO: В ftclient нет реализации flush/fsync
#else   // USE_FTCLIENT
    if (fsync(swarm_dev->fd) == -1) {
        TCMU_ERRNO("Sync failed.\n");
        return TCMU_STS_WR_ERR;
    }
#endif  // USE_FTCLIENT
    return 0;
}

static int swarm_tcmu_flush(struct tcmu_device *dev, struct tcmur_cmd *cmd)
{
    struct swarm_dev_s *swarm_dev = NULL;
    assert(dev);
    swarm_dev = tcmur_dev_get_private(dev);
    
    assert(swarm_dev && swarm_dev->fd > BADFD);

    return swarm_flush(swarm_dev, cmd);
}

static int swarm_tcmu_reconfig(struct tcmu_device *dev, struct tcmulib_cfg_info *cfg)
{
    struct swarm_dev_s *swarm_dev = NULL;
    assert(dev && cfg);
    swarm_dev = tcmur_dev_get_private(dev);
    assert(swarm_dev && swarm_dev->fd > BADFD);
    switch (cfg->type) {
	case TCMULIB_CFG_DEV_SIZE:
    {
        off_t new_size = (off_t)cfg->data.dev_size;
        assert(new_size > 0);
        if(swarm_tcmu_flush(dev, NULL) != 0) {
            return TCMU_STS_WR_ERR;
        }
        if(swarm_ftruncate(swarm_dev, new_size) != 0) {
            return -1;
        }
        return 0;
    }
	case TCMULIB_CFG_DEV_CFGSTR:
	case TCMULIB_CFG_WRITE_CACHE:
    default:
		return -EOPNOTSUPP;
	}
}

#ifdef USE_FTCLIENT
    static const char swarm_cfg_desc[] = "swarm config string must contain SWARM object name.";
#else   // USE_FTCLIENT
    static const char swarm_cfg_desc[] = "swarm config string must contain path to the file to use as a backstore.";
#endif  // USE_FTCLIENT
static struct tcmur_handler swarm_handler = {
    .cfg_desc = swarm_cfg_desc,

    .reconfig = swarm_tcmu_reconfig,

    .open = swarm_tcmu_open,
    .close = swarm_tcmu_close,
    .read = swarm_tcmu_read,
    .write = swarm_tcmu_write,
    .flush = swarm_tcmu_flush,
    .name = "SWARM-backed handler",
    .subtype = "swarm",
    .nr_threads = 1,
};

#ifdef HANDLER_SWARM
// for tcmu-runner handler
/* Entry point must be named "handler_init". */
int handler_init(void)
#else
int swarm_tcmu_handler_init(void)
#endif
{
    return tcmur_register_handler(&swarm_handler);
}

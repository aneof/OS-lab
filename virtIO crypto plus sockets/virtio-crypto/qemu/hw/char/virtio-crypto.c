
/*
 * Virtio Crypto Device
 *
 * Implementation of virtio-crypto qemu backend device.
 *
 * Dimitris Siakavaras <jimsiak@cslab.ece.ntua.gr>
 * Stefanos Gerangelos <sgerag@cslab.ece.ntua.gr>
 *
 */

#include <qemu/iov.h>
#include "hw/virtio/virtio-serial.h"
#include "hw/virtio/virtio-crypto.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <crypto/cryptodev.h>

static uint32_t get_features(VirtIODevice *vdev, uint32_t features)
{
        DEBUG_IN();
        return features;
}

static void get_config(VirtIODevice *vdev, uint8_t *config_data)
{
        DEBUG_IN();
}

static void set_config(VirtIODevice *vdev, const uint8_t *config_data)
{
        DEBUG_IN();
}

static void set_status(VirtIODevice *vdev, uint8_t status)
{
        DEBUG_IN();
}

static void vser_reset(VirtIODevice *vdev)
{
        DEBUG_IN();
}

static void vq_handle_output(VirtIODevice *vdev, VirtQueue *vq)
{
        VirtQueueElement elem;
        unsigned int *syscall_type;
        int *cfd, *host_return_val;
        char ds[100];
        unsigned char *src,*dst,*iv,*seskey;
        unsigned int *cmd;
        struct session_op *sess,temp_sess;
        struct crypt_op *crypt,temp_crypt;
        uint32_t *ses_id;

        DEBUG_IN();


        if (!virtqueue_pop(vq, &elem)) {
                DEBUG("No item to pop from VQ :(");
                return;
        }

        DEBUG("I have got an item from VQ :)");

        syscall_type = elem.out_sg[0].iov_base;
        switch (*syscall_type) {
        case VIRTIO_CRYPTO_SYSCALL_TYPE_OPEN:
                DEBUG("VIRTIO_CRYPTO_SYSCALL_TYPE_OPEN");
                /* ?? */
                cfd = elem.in_sg[0].iov_base;
                if ( (*cfd = open("/dev/crypto", O_RDWR)) < 0) {
                        DEBUG("Unable to open /dev/crypto .\n");
                }
                sprintf(ds,"OPEN: This is the fd i GIVE: %d",*cfd);
                DEBUG(ds);

                break;

        case VIRTIO_CRYPTO_SYSCALL_TYPE_CLOSE:
                DEBUG("VIRTIO_CRYPTO_SYSCALL_TYPE_CLOSE");
                /* ?? */
                cfd = elem.out_sg[1].iov_base;


                sprintf(ds,"CLOSE: This is the fd i GET: %d",*cfd);
                DEBUG(ds);
                close(*cfd);
                break;

        case VIRTIO_CRYPTO_SYSCALL_TYPE_IOCTL:
                DEBUG("VIRTIO_CRYPTO_SYSCALL_TYPE_IOCTL");
                /* ?? */

                cfd = (int*)elem.out_sg[1].iov_base;
                cmd = (unsigned int*)elem.out_sg[2].iov_base;
                sprintf(ds,"IOCTL: This is the fd i GET: %d",*cfd);
                DEBUG(ds);
                switch(*cmd) {
                case CIOCGSESSION:
                        DEBUG("VIRTIO_CRYPTO_SYSCALL_TYPE_IOCTL_CIOCGSESSION");
                        sess = elem.in_sg[0].iov_base;
                        temp_sess = *sess;
                        seskey = elem.out_sg[3].iov_base;
                        temp_sess.key = seskey;
                        host_return_val = elem.in_sg[1].iov_base;
                        *host_return_val = ioctl(*cfd, CIOCGSESSION, &temp_sess);
                        if(*host_return_val) {
                                DEBUG("ioctl CIOCGSESSION problem");
                                perror("");
                        }
                        sess->ses = temp_sess.ses;
                        break;
                case CIOCFSESSION:
                        DEBUG("VIRTIO_CRYPTO_SYSCALL_TYPE_IOCTL_CIOCFSESSION");
                        ses_id = elem.out_sg[3].iov_base;

                        host_return_val = elem.in_sg[0].iov_base;
                        *host_return_val = ioctl(*cfd, CIOCFSESSION, ses_id);
                        if(*host_return_val==-1){
                                DEBUG("ioctl CIOCFSESSION problem");
                                perror("");
                        }
                        break;
                case CIOCCRYPT:
                        DEBUG("VIRTIO_CRYPTO_SYSCALL_TYPE_IOCTL_CIOCCRYPT");

                        crypt = elem.out_sg[3].iov_base;
                        src = elem.out_sg[4].iov_base;
                        iv = elem.out_sg[5].iov_base;
                        //malloc gia na exoume swsto megethos
                        //dst = malloc (sizeof(unsigned char) * crypt->len);
                        dst = elem.in_sg[0].iov_base;
                        temp_crypt = *crypt;
                        temp_crypt.src = src;
                        temp_crypt.iv = iv;
                        temp_crypt.dst = dst;
                        host_return_val = elem.in_sg[1].iov_base;
                        *host_return_val = ioctl(*cfd, CIOCCRYPT, &temp_crypt);
                        if(*host_return_val) {
                                DEBUG("ioctl CIOCCRYPT problem");
                                perror("");
                        }
                        DEBUG("IOCTL sgs ok");
                        //memcpy(dst, crypt->dst, crypt->len*sizeof(unsigned char));
                        //DEBUG("memcpy ok");
                        break;
                }

                break;

        default:
                DEBUG("Unknown syscall_type");
        }

        virtqueue_push(vq, &elem, 0);
        virtio_notify(vdev, vq);
}

static void virtio_crypto_realize(DeviceState *dev, Error **errp)
{
    VirtIODevice *vdev = VIRTIO_DEVICE(dev);

        DEBUG_IN();

    virtio_init(vdev, "virtio-crypto", 13, 0);
        virtio_add_queue(vdev, 128, vq_handle_output);
}

static void virtio_crypto_unrealize(DeviceState *dev, Error **errp)
{
        DEBUG_IN();
}

static Property virtio_crypto_properties[] = {
    DEFINE_PROP_END_OF_LIST(),
};

static void virtio_crypto_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    VirtioDeviceClass *k = VIRTIO_DEVICE_CLASS(klass);

        DEBUG_IN();
    dc->props = virtio_crypto_properties;
    set_bit(DEVICE_CATEGORY_INPUT, dc->categories);

    k->realize = virtio_crypto_realize;
    k->unrealize = virtio_crypto_unrealize;
    k->get_features = get_features;
    k->get_config = get_config;
    k->set_config = set_config;
    k->set_status = set_status;
    k->reset = vser_reset;
}

static const TypeInfo virtio_crypto_info = {
    .name          = TYPE_VIRTIO_CRYPTO,
    .parent        = TYPE_VIRTIO_DEVICE,
    .instance_size = sizeof(VirtCrypto),
    .class_init    = virtio_crypto_class_init,
};

static void virtio_crypto_register_types(void)
{
    type_register_static(&virtio_crypto_info);
}

type_init(virtio_crypto_register_types)

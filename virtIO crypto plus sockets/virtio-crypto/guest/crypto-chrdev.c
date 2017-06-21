
/*
 * crypto-chrdev.c
 *
 * Implementation of character devices
 * for virtio-crypto device
 *
 * Vangelis Koukis <vkoukis@cslab.ece.ntua.gr>
 * Dimitris Siakavaras <jimsiak@cslab.ece.ntua.gr>
 * Stefanos Gerangelos <sgerag@cslab.ece.ntua.gr>
 *
 */
#include <linux/cdev.h>
#include <linux/poll.h>
#include <linux/sched.h>
#include <linux/module.h>
#include <linux/wait.h>
#include <linux/virtio.h>
#include <linux/virtio_config.h>

#include "crypto.h"
#include "crypto-chrdev.h"
#include "debug.h"

#include "cryptodev.h"

/*
 * Global data
 */
struct cdev crypto_chrdev_cdev;

/**
 * Given the minor number of the inode return the crypto device
 * that owns that number.
 **/
static struct crypto_device *get_crypto_dev_by_minor(unsigned int minor)
{
        struct crypto_device *crdev;
        unsigned long flags;

        debug("Entering");

        spin_lock_irqsave(&crdrvdata.lock, flags);
        list_for_each_entry(crdev, &crdrvdata.devs, list) {
                if (crdev->minor == minor)
                        goto out;
        }
        crdev = NULL;

out:
        spin_unlock_irqrestore(&crdrvdata.lock, flags);

        debug("Leaving");
        return crdev;
}

/*************************************
 * Implementation of file operations
 * for the Crypto character device
 *************************************/

static int crypto_chrdev_open(struct inode *inode, struct file *filp)
{
        int ret = 0;
        int err;
        unsigned int len, num_in = 0, num_out = 0;
        struct crypto_open_file *crof;
        struct crypto_device *crdev;
        unsigned int *syscall_type;
        int *host_fd;
        struct scatterlist syscall_type_sg, host_fd_sg, *sgs[2];
        unsigned long flags;
        debug("Entering");
        syscall_type = kmalloc(sizeof(*syscall_type), GFP_KERNEL);
        host_fd = kmalloc(sizeof(*host_fd), GFP_KERNEL);
        *syscall_type = VIRTIO_CRYPTO_SYSCALL_OPEN;
        *host_fd = -1;

        ret = -ENODEV;
        if ((ret = nonseekable_open(inode, filp)) < 0)
                goto fail;

        /* Associate this open file with the relevant crypto device. */
        crdev = get_crypto_dev_by_minor(iminor(inode));
        if (!crdev) {
                debug("Could not find crypto device with %u minor", iminor(inode));
                ret = -ENODEV;
                goto fail;
        }

        crof = kzalloc(sizeof(*crof), GFP_KERNEL);
        if (!crof) {
                ret = -ENOMEM;
                goto fail;
        }
        crof->crdev = crdev;
        crof->host_fd = -1;
        filp->private_data = crof;

        /**
         * We need two sg lists, one for syscall_type and one to get the
         * file descriptor from the host.
         **/
        //syscall type
        sg_init_one(&syscall_type_sg, syscall_type, sizeof(*syscall_type));
        sgs[num_out] = &syscall_type_sg;
        num_out++;
        //hostfd
        sg_init_one(&host_fd_sg, host_fd, sizeof(*host_fd));
        sgs[num_out + num_in] = &host_fd_sg;
        num_in++;
        /* ?? */
        //lock?
        // Caller must ensure we don't call this with other virtqueue operations                                
        //at the same time (except where noted).
        spin_lock_irqsave(&crdev->lock,flags);
        virtqueue_add_sgs(crdev->vq, sgs, num_out, num_in, &syscall_type_sg , GFP_ATOMIC);
        virtqueue_kick(crdev->vq);
        /**
         * Wait for the host to process our data.
         **/
        while (virtqueue_get_buf(crdev->vq, &len) == NULL);
        spin_unlock_irqrestore(&crdev->lock,flags);
        /* ?? */

        crof->host_fd = *host_fd;

        /* If host failed to open() return -ENODEV. */
        if(crof->host_fd < 0) {
                ret = -ENODEV;
        }
        /* ?? */


fail:
        debug("Leaving");
        return ret;
}

static int crypto_chrdev_release(struct inode *inode, struct file *filp)
{
        int ret = 0,*host_fd;
        struct crypto_open_file *crof = filp->private_data;
        struct crypto_device *crdev = crof->crdev;
        unsigned int *syscall_type;
        struct scatterlist syscall_type_sg, host_fd_sg, *sgs[2];
        unsigned int len, num_in=0, num_out=0;
        unsigned long flags;
        syscall_type = kmalloc(sizeof(*syscall_type), GFP_KERNEL);
        *syscall_type = VIRTIO_CRYPTO_SYSCALL_CLOSE;
        host_fd = kmalloc(sizeof(*host_fd), GFP_KERNEL);

        debug("Entering");

        /**
         * Send data to the host.
         **/
        *host_fd = crof->host_fd;

        sg_init_one(&syscall_type_sg, syscall_type, sizeof(*syscall_type));
        sgs[num_out] = &syscall_type_sg;
        num_out++;

        sg_init_one(&host_fd_sg, host_fd, sizeof(*host_fd));
        sgs[num_out] = &host_fd_sg;
        num_out++;

        spin_lock_irqsave(&crdev->lock,flags);

        virtqueue_add_sgs(crdev->vq, sgs, num_out, num_in, &syscall_type_sg , GFP_ATOMIC);
        virtqueue_kick(crdev->vq);
        /* ?? */

        /**
         * Wait for the host to process our data.
         **/
        while (virtqueue_get_buf(crdev->vq, &len) == NULL);

        spin_unlock_irqrestore(&crdev->lock,flags);
        /* ?? */

        kfree(crof);
        debug("Leaving");
        return ret;

}

static long crypto_chrdev_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
        long ret = 0;
        int err,*host_fd,*host_return_val;
        uint32_t *id;
        struct crypto_open_file *crof = filp->private_data;
        struct crypto_device *crdev = crof->crdev;
        struct virtqueue *vq = crdev->vq;
        struct scatterlist syscall_type_sg, host_fd_sg, cmd_sg, output_msg_sg, input_msg_sg,sess_sg, sess_key_sg, host_return_val_sg, sess_id_sg,crypt_sg,crypt_src_sg,crypt_iv_sg,crypt_dst_sg, *sgs[10];
        unsigned int num_out, num_in, len;
#define MSG_LEN 100
        unsigned char *key,*src,*iv,*dst = NULL;
        unsigned int *syscall_type,*cmd1;
        struct session_op *sess;
        struct crypt_op *crypt;
        unsigned long flags;
        debug("Entering");

        /**
         * Allocate all data that will be sent to the host.
         **/
        syscall_type = kmalloc(sizeof(*syscall_type), GFP_KERNEL);
        *syscall_type = VIRTIO_CRYPTO_SYSCALL_IOCTL;
        cmd1 = kmalloc(sizeof(*cmd1), GFP_KERNEL);
        *cmd1 = cmd;
        host_fd = kmalloc(sizeof(*cmd1), GFP_KERNEL);
        *host_fd = crof->host_fd;
        host_return_val = kmalloc(sizeof(*host_return_val), GFP_KERNEL);
        sess = kmalloc(sizeof(*sess), GFP_KERNEL);
        crypt = kmalloc(sizeof(*crypt), GFP_KERNEL);
        num_out = 0;
        num_in = 0;
        debug("initial mallocs ok");
        /**
         *  These are common to all ioctl commands.
         **/
        sg_init_one(&syscall_type_sg, syscall_type, sizeof(*syscall_type));
        sg_init_one(&host_fd_sg, host_fd, sizeof(*host_fd));
        sg_init_one(&cmd_sg, cmd1, sizeof(*cmd1));
        sgs[num_out++ + num_in] = &syscall_type_sg;
        sgs[num_out++ + num_in] = &host_fd_sg;
        sgs[num_out++ + num_in] = &cmd_sg;
        debug("initial sgs ok");
        /* ?? */

        /**
         *  Add all the cmd specific sg lists.
         **/
        switch (cmd) {
        case CIOCGSESSION:
                debug("CIOCGSESSION");

                err = copy_from_user(sess, (struct session_op*)arg, sizeof(struct session_op));
                if(err){
                        debug("Copy from user CIOCGSESSION");
                        ret = -1;
                        return ret;
                }

                //edw ta sess->key klp arxika ta skipparw gia dokimi, na rwtisw velegka!!!
                key = kmalloc(sess->keylen*sizeof(char), GFP_KERNEL);
                err = copy_from_user(key, sess->key, sizeof(char)*sess->keylen);
                if(err){
                        debug("Copy from user CIOCGSESSION 2");
                        ret = -1;
                        return ret;
                }
                debug("keys: %c%c%c", key[0], key[1], key[2]);

                sg_init_one(&sess_key_sg, key, sess->keylen * sizeof(char));
                sg_init_one(&sess_sg, sess, sizeof(*sess));
                //xreiazetai to host_return_val?
                sg_init_one(&host_return_val_sg, host_return_val, sizeof(*host_return_val));

                sgs[num_out++ + num_in] = &sess_key_sg;
                sgs[num_out + num_in++] = &sess_sg;
                sgs[num_out + num_in++] = &host_return_val_sg;

                spin_lock(&crdev->lock);
                err = virtqueue_add_sgs(vq, sgs, num_out, num_in, &syscall_type_sg, GFP_ATOMIC);
                virtqueue_kick(crdev->vq);
                while (virtqueue_get_buf(vq, &len) == NULL);
                spin_unlock(&crdev->lock);

                debug("CIOCGSESSION RET");
                if(copy_to_user((struct session_op*)arg, sess, sizeof(struct session_op))){
                        debug("Copy to user 1");
                        ret = -1;
                        return ret;
                }
                ret = *host_return_val;

                break;

        case CIOCFSESSION:
                debug("CIOCFSESSION");

                id = kmalloc(sizeof(*id), GFP_KERNEL);
                if(copy_from_user(id,(uint32_t *)arg,sizeof(uint32_t))){
                        debug("Copy from user CIOCFSESSION");
                        ret = -1;
                        return ret;
                }
                sg_init_one(&sess_id_sg, id, sizeof(uint32_t));
                sg_init_one(&host_return_val_sg, host_return_val, sizeof(*host_return_val));

                sgs[num_out++ + num_in] = &sess_id_sg;
                sgs[num_out + num_in++] = &host_return_val_sg;

                spin_lock(&crdev->lock);
                err = virtqueue_add_sgs(vq, sgs, num_out, num_in, &syscall_type_sg, GFP_ATOMIC);
                virtqueue_kick(crdev->vq);
                while (virtqueue_get_buf(vq, &len) == NULL);
                spin_unlock(&crdev->lock);

                ret = *host_return_val;

                break;

        case CIOCCRYPT:
                debug("CIOCCRYPT");

               // src = kmalloc(crypt->len*sizeof(char), GFP_KERNEL);
               // dst = kmalloc(crypt->len*sizeof(char), GFP_KERNEL);
               // iv = kmalloc(16*sizeof(char), GFP_KERNEL);

                err = copy_from_user(crypt, (struct crypt_op*)arg, sizeof(struct crypt_op));
                if(err){
                        debug("Copy from user CIOCCRYPT");
                        ret = -1;
                        return ret;
                }
                src = kmalloc(crypt->len*sizeof(char), GFP_KERNEL);
                dst = kmalloc(crypt->len*sizeof(char), GFP_KERNEL);
                iv = kmalloc(16*sizeof(char), GFP_KERNEL);

                err = copy_from_user(src, crypt->src, sizeof(char)*crypt->len);
                if(err){
                        debug("Copy from user CIOCCRYPT 2");
                        ret = -1;
                        return ret;
                }
                err = copy_from_user(iv, crypt->iv, sizeof(char)*16);
                if(err){
                        debug("Copy from user CIOCCRYPT 3");
                        ret = -1;
                        return ret;
                }
                err = copy_from_user(dst, crypt->dst, sizeof(char)*crypt->len);
                if(err){
                        debug("Copy from user CIOCCRYPT 4");
                        ret = -1;
                        return ret;
                }

                debug("src: %c%c%c", src[0], src[1], src[2]);
                debug("iv: %c%c%c", iv[0], iv[1], iv[2]);
                debug("dst: %c%c%c", dst[0], dst[1], dst[2]);

                //poios o rolos tou dst????? giati to stelnoume keno???
                sg_init_one(&crypt_sg, crypt, sizeof(struct crypt_op));
                sg_init_one(&crypt_src_sg, src, sizeof(char)*crypt->len);
                sg_init_one(&crypt_iv_sg, iv, sizeof(char)*16);
                sg_init_one(&crypt_dst_sg, dst, sizeof(char)*crypt->len);
                sg_init_one(&host_return_val_sg, host_return_val, sizeof(*host_return_val));

                sgs[num_out++ + num_in] = &crypt_sg;
                sgs[num_out++ + num_in] = &crypt_src_sg;
                sgs[num_out++ + num_in] = &crypt_iv_sg;
                sgs[num_out + num_in++] = &crypt_dst_sg;
                sgs[num_out + num_in++] = &host_return_val_sg;

                spin_lock_irqsave(&crdev->lock,flags);
                err = virtqueue_add_sgs(vq, sgs, num_out, num_in, &syscall_type_sg, GFP_ATOMIC);
                virtqueue_kick(crdev->vq);
                while (virtqueue_get_buf(vq, &len) == NULL);
                spin_unlock_irqrestore(&crdev->lock,flags);
                debug("CIOCCRYPT RET");
                //stekei auto??
                if(copy_to_user(((struct crypt_op*)arg)->dst, dst, crypt->len *sizeof(char))){
                        debug("Copy to user 2");
                        ret = -1;
                        return ret;
                }
                ret = *host_return_val;

                break;

        default:
                debug("Unsupported ioctl command");

                break;
        }


        /**
         * Wait for the host to process our data.
         **/
        /* ?? */
        /* ?? Lock ?? */
        /*
        spin_lock(&crdev->lock);
        err = virtqueue_add_sgs(crdev->vq, sgs, num_out, num_in, &syscall_type_sg, GFP_ATOMIC);
        virtqueue_kick(crdev->vq);
        while (virtqueue_get_buf(vq, &len) == NULL);
        spin_unlock(&crdev->lock);
//giati auta ta copy_to_user? swsta einai??
        switch(cmd){
        case CIOCGSESSION:
                debug("CIOCGSESSION RET");
                if(copy_to_user((struct session_op*)arg, sess, sizeof(struct session_op))){
                        debug("Copy to user 1");
                        ret = -1;
                        return ret;
                }

                break;

        case CIOCFSESSION:
                debug("CIOCFSESSION RET");

                break;

        case CIOCCRYPT:
                debug("CIOCCRYPT RET");
                //stekei auto??
                if(copy_to_user(((struct crypt_op*)arg)->dst, dst, crypt->len *sizeof(char))){
                        debug("Copy to user 2");
                        ret = -1;
                        return ret;
                }

                break;

        }
        */


 //       kfree(syscall_type);

        debug("Leaving");

        return ret;
}

static ssize_t crypto_chrdev_read(struct file *filp, char __user *usrbuf ,  size_t cnt, loff_t *f_pos)
{
        debug("Entering");
        debug("Leaving");
        return -EINVAL;
}

static struct file_operations crypto_chrdev_fops =
{
        .owner          = THIS_MODULE,
        .open           = crypto_chrdev_open,
        .release        = crypto_chrdev_release,
        .read           = crypto_chrdev_read,
        .unlocked_ioctl = crypto_chrdev_ioctl,
};

int crypto_chrdev_init(void)
{
        int ret;
        dev_t dev_no;
        unsigned int crypto_minor_cnt = CRYPTO_NR_DEVICES;

        debug("Initializing character device...");
        cdev_init(&crypto_chrdev_cdev, &crypto_chrdev_fops);
        crypto_chrdev_cdev.owner = THIS_MODULE;

        dev_no = MKDEV(CRYPTO_CHRDEV_MAJOR, 0);
        ret = register_chrdev_region(dev_no, crypto_minor_cnt, "crypto_devs");
        if (ret < 0) {
                debug("failed to register region, ret = %d", ret);
                goto out;
        }
        ret = cdev_add(&crypto_chrdev_cdev, dev_no, crypto_minor_cnt);
        if (ret < 0) {
                debug("failed to add character device");
                goto out_with_chrdev_region;
        }

        debug("Completed successfully");
        return 0;

out_with_chrdev_region:
        unregister_chrdev_region(dev_no, crypto_minor_cnt);
out:
        return ret;
}

void crypto_chrdev_destroy(void)
{
        dev_t dev_no;
        unsigned int crypto_minor_cnt = CRYPTO_NR_DEVICES;

        debug("entering");
        dev_no = MKDEV(CRYPTO_CHRDEV_MAJOR, 0);
        cdev_del(&crypto_chrdev_cdev);
        unregister_chrdev_region(dev_no, crypto_minor_cnt);
        debug("leaving");
}

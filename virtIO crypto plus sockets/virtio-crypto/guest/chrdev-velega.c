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
	struct crypto_open_file *crof;
	struct crypto_device *crdev;
	unsigned int *syscall_type;
	int *host_fd;
	struct scatterlist syscall_type_sg,fd_sg, *sgs[2];
	unsigned int num_in, num_out, len;
	unsigned long flags;

	num_out = num_in = 0;
	host_fd = kmalloc(sizeof(*host_fd), GFP_KERNEL);
	syscall_type = kmalloc(sizeof(*syscall_type), GFP_KERNEL);
	*host_fd = -1;
	*syscall_type = VIRTIO_CRYPTO_SYSCALL_OPEN;

	debug("Entering");

	ret = -ENODEV;
	if ((ret = nonseekable_open(inode, filp)) < 0)
		goto fail;

	/* Associate this open file with the relevant crypto device. */
	crdev = get_crypto_dev_by_minor(iminor(inode));
	if (!crdev) {
		debug("Could not find crypto device with %u minor",
				iminor(inode));
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
	/* ?? */
	sg_init_one(&syscall_type_sg,syscall_type,sizeof(*syscall_type));
	sgs[num_out++] = &syscall_type_sg;
	sg_init_one(&fd_sg,host_fd,sizeof(*host_fd));
	sgs[num_out+num_in++] = &fd_sg;


	/**
	 * Wait for the host to process our data.
	 **/
	/* ?? */
	spin_lock_irqsave(&crdev->lock,flags);
	err = virtqueue_add_sgs(crdev->vq,sgs,num_out,num_in,&syscall_type_sg,GFP_ATOMIC);
	virtqueue_kick(crdev->vq);


	/* If host failed to open() return -ENODEV. */
	/* ?? */

	while(virtqueue_get_buf(crdev->vq,&len) == NULL);
	spin_unlock_irqrestore(&crdev->lock,flags);

	crof->host_fd = *host_fd;
	printk("OPEN: %d", *host_fd);

	if (crof->host_fd < 0)
		ret = -ENODEV;



fail:
	debug("Leaving");
	return ret;
}

static int crypto_chrdev_release(struct inode *inode, struct file *filp)
{
	int ret = 0;
	struct crypto_open_file *crof = filp->private_data;
	struct crypto_device *crdev = crof->crdev;
	unsigned int *syscall_type;
	int *host_fd;
	unsigned int num_out, num_in, len;
	unsigned long flags;
	int err;
	struct scatterlist syscall_type_sg,fd_sg, *sgs[2];

	num_out = num_in = 0;
	syscall_type = kmalloc(sizeof(*syscall_type), GFP_KERNEL);
	*syscall_type = VIRTIO_CRYPTO_SYSCALL_CLOSE;

	host_fd = kmalloc(sizeof(*host_fd), GFP_KERNEL);
	*host_fd = crof->host_fd;

	debug("Entering");

	/**
	 * Send data to the host.
	 **/
	/* ?? */
	sg_init_one(&syscall_type_sg, syscall_type, sizeof(*syscall_type));
	sgs[num_out++] = &syscall_type_sg;
	sg_init_one(&fd_sg,host_fd,sizeof(*host_fd));
	sgs[num_out++] = &fd_sg;

	spin_lock_irqsave(&crdev->lock,flags);
	err = virtqueue_add_sgs(crdev->vq,sgs,num_out,num_in,&syscall_type_sg,GFP_ATOMIC);
	virtqueue_kick(crdev->vq);

	/**
	 * Wait for the host to process our data.
	 **/
	/* ?? */

	while(virtqueue_get_buf(crdev->vq,&len) == NULL);
	spin_unlock_irqrestore(&crdev->lock,flags);


	kfree(crof);
	debug("Leaving");
	return ret;

}

static long crypto_chrdev_ioctl(struct file *filp, unsigned int cmd,
		unsigned long arg)
{
	long ret = 0;
	struct crypto_open_file *crof = filp->private_data;
	unsigned long flags;
	struct crypto_device *crdev = crof->crdev;
	struct virtqueue *vq = crdev->vq;
	struct scatterlist syscall_type_sg, host_fd_sg, ioctl_cmd_sg,
			   session_key_sg, ses_id_sg, crypt_op_sg, crypt_src_sg, crypt_iv_sg,//Read sgs
			   session_op_sg, host_return_sg, crypt_dst_sg,//Write sgs
			   *sgs[8];
	unsigned int num_out, num_in, len;
#define MSG_LEN 100
	unsigned char *output_msg, *input_msg;
	unsigned int *syscall_type;
	int *host_fd;
	unsigned int *cmd1;
	struct session_op *sess;
	struct crypt_op *crypt;
	unsigned char *src, *iv, *dst = NULL;
	uint32_t *sess_id;
	unsigned char *key;
	int *host_ret_val;
	int err;

	debug("Entering");
	num_out = num_in = 0;
	host_ret_val = kmalloc(sizeof(*host_ret_val), GFP_KERNEL);

	/**
	 * Allocate all data that will be sent to the host.
	 **/
	sess_id = kmalloc(sizeof(*sess_id), GFP_KERNEL);
	sess = kmalloc(sizeof(*sess), GFP_KERNEL);
	crypt = kmalloc(sizeof(*crypt), GFP_KERNEL);
	host_fd = kmalloc(sizeof(*host_fd), GFP_KERNEL);
	*host_fd = crof->host_fd;
	cmd1 = kmalloc(sizeof(*cmd1), GFP_KERNEL);
	*cmd1 = cmd;
	syscall_type = kmalloc(sizeof(*syscall_type), GFP_KERNEL);
	*syscall_type = VIRTIO_CRYPTO_SYSCALL_IOCTL;

	num_out = 0;
	num_in = 0;

	/**
	 *  These are common to all ioctl commands.
	 **/
	sg_init_one(&syscall_type_sg, syscall_type, sizeof(*syscall_type));
	sgs[num_out++] = &syscall_type_sg;
	/* ?? */

	sg_init_one(&host_fd_sg, host_fd, sizeof(*host_fd));
	sgs[num_out++] = &host_fd_sg;
	sg_init_one(&ioctl_cmd_sg, cmd1, sizeof(*cmd1));
	sgs[num_out++] = &ioctl_cmd_sg;

	/**
	 *  Add all the cmd specific sg lists.
	 **/
	switch (cmd) {
		case CIOCGSESSION:
			err = copy_from_user(sess,(struct session_op*)arg,sizeof(struct session_op));

			if(err)
				debug("something went wrong in first copy in ciocg");

			key = kmalloc(sess->keylen*sizeof(char), GFP_KERNEL);
			err = copy_from_user(key,sess->key,sizeof(char)*sess->keylen);
			if(err)
				debug("something went wrong in first copy in second ciocg");

			printk("START: %c%c%c", key[0], key[1], key[2]);
			sg_init_one(&session_key_sg,key,sess->keylen*sizeof(char));
			sgs[num_out++] = &session_key_sg;
			sg_init_one(&session_op_sg,sess,sizeof(*sess));
			sgs[num_out + num_in++] = &session_op_sg;
			sg_init_one(&host_return_sg,host_ret_val,sizeof(*host_ret_val));
			sgs[num_out + num_in++] = &host_return_sg;

			spin_lock_irqsave(&crdev->lock, flags);

			err = virtqueue_add_sgs(vq, sgs, num_out, num_in,
					&syscall_type_sg, GFP_ATOMIC);
			virtqueue_kick(vq);
			while(virtqueue_get_buf(crdev->vq, &len) == NULL);
			spin_unlock_irqrestore(&crdev->lock,flags);

			err = copy_to_user((struct session_op*)arg, sess, sizeof(struct session_op));
			if(err)
				debug("error at sess copy back");

			printk("START: %c%c%c", sess->key[0], sess->key[1], sess->key[2]);
			ret = *host_ret_val;
			break;

		case CIOCFSESSION:
			debug("CIOCFSESSION");
			err = copy_from_user(sess_id,(uint32_t *)arg, sizeof(uint32_t));
			if(err)
			{
				debug("something went wrong with first copy in ciocf");
				break;
			}
			sg_init_one(&ses_id_sg, sess_id, sizeof(*sess_id));
			sgs[num_out++] = &ses_id_sg;
			sg_init_one(&host_return_sg,host_ret_val,sizeof(*host_ret_val));
			sgs[num_out + num_in++] = &host_return_sg;


			spin_lock_irqsave(&crdev->lock, flags);
			err = virtqueue_add_sgs(vq, sgs, num_out, num_in,&syscall_type_sg, GFP_ATOMIC);
			virtqueue_kick(vq);

			while(virtqueue_get_buf(crdev->vq, &len) == NULL);
			spin_unlock_irqrestore(&crdev->lock,flags);

			ret = *host_ret_val;

			break;

		case CIOCCRYPT:
			debug("CIOCCRYPT");
			err = copy_from_user(crypt,(struct crypt_op*) arg, sizeof(struct crypt_op));
			if(err)
				debug("something went wrong in first copy CIOCC");
			src = kmalloc(crypt->len*sizeof(char), GFP_KERNEL);
			err = copy_from_user(src,crypt->src, crypt->len*sizeof(char));
			if(err)
				debug("something went wrong in second copy CIOCC");
			printk("SRC: %c%c%c", src[0], src[1], src[2]);
			iv = kmalloc(16*sizeof(char), GFP_KERNEL);				//na dw pws tha mpei swsta to 16
			err = copy_from_user(iv, crypt->iv, 16*sizeof(char));
			if(err)
				debug("something went wrong in third copy CIOCC");
			printk("IV: %c%c%c", iv[0], iv[1], iv[2]);
			dst = kmalloc(crypt->len*sizeof(char), GFP_KERNEL);

			err = copy_from_user(dst, crypt->dst, crypt->len*sizeof(char));
			if(err)
				debug("something went wrong in fourth copy CIOCC");
			printk("DST: %c%c%c", dst[0], dst[1], dst[2]);


			sg_init_one(&crypt_op_sg, crypt, sizeof(struct crypt_op));
			sgs[num_out++] = &crypt_op_sg;
			sg_init_one(&crypt_src_sg, src,sizeof(char)*crypt->len);
			sgs[num_out++] = &crypt_src_sg;
			sg_init_one(&crypt_iv_sg, iv, sizeof(char)*16);
			sgs[num_out++] = &crypt_iv_sg;
			sg_init_one(&crypt_dst_sg, dst, sizeof(char)*crypt->len);
			sgs[num_out + num_in++] = &crypt_dst_sg;
			sg_init_one(&host_return_sg,host_ret_val,sizeof(*host_ret_val));
			sgs[num_out + num_in++] = &host_return_sg;

			spin_lock_irqsave(&crdev->lock, flags);
			err = virtqueue_add_sgs(vq, sgs, num_out, num_in,&syscall_type_sg, GFP_ATOMIC);
			virtqueue_kick(vq);

			while(virtqueue_get_buf(crdev->vq, &len) == NULL);
			spin_unlock_irqrestore(&crdev->lock,flags);

			printk("DST: %c%c%c", dst[0], dst[1], dst[2]);

			err = copy_to_user(((struct crypt_op*)arg)->dst, dst, crypt->len*sizeof(char));
			if(err)
				debug("something went wrong at dst back copying, %d",err);

			ret = *host_ret_val;
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
	/*err = virtqueue_add_sgs(vq, sgs, num_out, num_in,
	  &syscall_type_sg, GFP_ATOMIC);
	  virtqueue_kick(vq);
	  spin_lock_irqsave(&crdev->lock,flags);
	  while (virtqueue_get_buf(vq, &len) == NULL);
	// do nothing
	 */


	debug("Leaving");

	return ret;
}

static ssize_t crypto_chrdev_read(struct file *filp, char __user *usrbuf,
		size_t cnt, loff_t *f_pos)
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
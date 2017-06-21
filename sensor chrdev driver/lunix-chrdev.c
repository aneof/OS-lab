/*
 * lunix-chrdev.c
 *
 * Implementation of character devices
 * for Lunix:TNG
 *
 * Alexandros Neofytou
 * Dimitris Adamis
 *
 */

#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/cdev.h>
#include <linux/poll.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/ioctl.h>
#include <linux/types.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/mmzone.h>
#include <linux/vmalloc.h>
#include <linux/spinlock.h>

#include "lunix.h"
#include "lunix-chrdev.h"
#include "lunix-lookup.h"

/*
 * Global data
 */
struct cdev lunix_chrdev_cdev;

/*
 * Just a quick [unlocked] check to see if the cached
 * chrdev state needs to be updated from sensor measurements.
 */
static int lunix_chrdev_state_needs_refresh(struct lunix_chrdev_state_struct *state)
{


        struct lunix_sensor_struct *sensor;
        debug("entering refresh\n");


        WARN_ON ( !(sensor = state->sensor));
        /* ? */ 
        if ((state->buf_timestamp) < (sensor->msr_data[state->type]->last_update)) {
                debug("new data! time: %ld %ld ",  (unsigned long)state->buf_timestamp,(unsigned long)sensor->msr_data[state->type]->last_update);
                return 1;
        }
        /* The following return is bogus, just for the stub to compile */
        debug("exiting refresh, time: %ld %ld\n", (unsigned long)state->buf_timestamp,(unsigned long)sensor->msr_data[state->type]->last_update);
        return 0; /* ? */
}

/*
 * Updates the cached state of a character device
 * based on sensor data. Must be called with the
 * character device state lock held.
 */
static int lunix_chrdev_state_update(struct lunix_chrdev_state_struct *state)
{

        struct lunix_sensor_struct *sensor;
        uint32_t raw_data;
        debug("lunix_chrdev_state_update\n");
        debug("test\n");
        WARN_ON ( !(sensor = state->sensor));

        /*
         * Grab the raw data quickly, hold the
         * spinlock for as little as possible.
         */
         if (lunix_chrdev_state_needs_refresh(state) == 0)
                return -EAGAIN;


        /* ? */
        /* Why use spinlocks? See LDD3, p. 119 */

        /*
         * Any new data available?
         */
          //disable interrupts? Or not? probably not
        debug("locking\n");
         spin_lock_irqsave(&sensor->lock);
         raw_data = sensor->msr_data[state->type]->values[0];
         state->buf_timestamp = sensor->msr_data[state->type]->last_update;
        debug("got data at %ld, data is %d\n",(unsigned long)state->buf_timestamp,(uint32_t)raw_data);
         spin_unlock_irqrestore(&sensor->lock);
        debug("unlocking\n");
        /* ? */

        /*
         * Now we can take our time to format them,
         * holding only the private state semaphore
         */


        if (state->type == BATT) {
                raw_data=lookup_voltage[raw_data];
        }
        else if (state->type == TEMP){
                raw_data=lookup_temperature[raw_data];
        }
        else raw_data=lookup_light[raw_data];
        debug("fixed data = %d", raw_data);
        debug("morfopoihsh");
        state->buf_data[0]='0'+raw_data/100000;
        raw_data = raw_data%100000;
        state->buf_data[1]='0'+raw_data/10000;
        raw_data = raw_data%10000;
        state->buf_data[2]='0'+raw_data/1000;
        raw_data = raw_data%1000;
        state->buf_data[3]='.';
        state->buf_data[4]='0'+raw_data/100;
        raw_data = raw_data%100;
        state->buf_data[5]='0'+raw_data/10;
        raw_data = raw_data%10;
        state->buf_data[6]='0'+raw_data;
        state->buf_data[7]='\n';
        state->buf_lim=8;
        //state->buf_timestamp=timestamp;
        //up(&state->lock);
        /* ? */
        debug("morfopoiimeni metrisi: %c %c %c %c %c %c %c %c",state->buf_data[0],state->buf_data[1],state->buf_data[2],state->buf_data[3],state->buf_data[4],state->buf_data[5],state->buf_data[6],state->buf_data[7]);
        debug("leaving lunix_chrdev_state_update\n");
        return 0;
}

/*************************************
 * Implementation of file operations
 * for the Lunix character device
 *************************************/

static int lunix_chrdev_open(struct inode *inode, struct file *filp)
{
        /* Declarations */
        enum lunix_msr_enum sensor_type;
        unsigned int minor, sensor_no, i;
        struct lunix_chrdev_state_struct *str;


        int ret;

        debug("entering\n");
        ret = -ENODEV;
        if ((ret = nonseekable_open(inode, filp)) < 0)
                goto out;

        /*
         * Associate this open file with the relevant sensor based on
         * the minor number of the device node [/dev/sensor<NO>-<TYPE>]
         */
         minor = iminor(inode);
         sensor_no = minor / 8;
         sensor_type = minor % 8;

        debug("allocating new struct");
        /* Allocate a new Lunix character device private state structure */
        //struct lunix_chrdev_state_struct *str;
        str = (struct lunix_chrdev_state_struct *) kmalloc (sizeof(struct lunix_chrdev_state_struct), GFP_KERNEL);
        str->type = sensor_type;
        str->sensor = &lunix_sensors[sensor_no];

        str->buf_lim = LUNIX_CHRDEV_BUFSZ;
        for(i = 0; i < str->buf_lim; i++)
                str->buf_data[i] = NULL;
        str->buf_timestamp = get_seconds();
        sema_init(&(str->lock), 1);
        debug("finished allocating");
        //save
        filp->private_data = str;
        /* ? */
out:
        debug("leaving, with ret = %d\n", ret);
        return ret;
}

static int lunix_chrdev_release(struct inode *inode, struct file *filp)
{
        /* ? */
        kfree(filp->private_data);
        return 0;
}

static long lunix_chrdev_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
        /* Why? */
        return -EINVAL;
}

static ssize_t lunix_chrdev_read(struct file *filp, char __user *usrbuf, size_t cnt, loff_t *f_pos)
{
        ssize_t ret;

        struct lunix_sensor_struct *sensor;
        struct lunix_chrdev_state_struct *state;

        state = filp->private_data;
        WARN_ON(!state);

        sensor = state->sensor;
        WARN_ON(!sensor);

        debug("locking...");
        /* Lock? */
        if(down_interruptible(&state->lock)){
                debug("couldn't lock");
                return -ERESTARTSYS;
        }
        /*
         * If the cached character device state needs to be
         * updated by actual sensor data (i.e. we need to report
         * on a "fresh" measurement, do so
         */
        debug("read is calling lunixblablaupdate");
        if (*f_pos == 0) {
                while (lunix_chrdev_state_update(state) == -EAGAIN) {
                        /* ? */
                        up(&state->lock);
                        /* The process needs to sleep */
                        debug("sleeping until new data");
                        if(wait_event_interruptible(sensor->wq,lunix_chrdev_state_needs_refresh(state)))
                                return -ERESTARTSYS;
                        if(down_interruptible(&state->lock)){
                                debug("couldn't lock 2");
                                return -ERESTARTSYS;
                        }
                        /* See LDD3, page 153 for a hint */
                }
        }

        /* End of file */
        if (*f_pos + cnt > 8) {
                debug("f_pos=%d ,cnt=%d",*f_pos,cnt);
                *f_pos = 0;
                debug("not enough space");
                cnt = 8; //gia na parei metrisi
        }
        else {
                *f_pos += cnt;
                if (*f_pos >= 8) {
                        *f_pos = 0;
                }
        }
        /* ? */

        /* Determine the number of cached bytes to copy to userspace */
        debug("data before copy_to_user : %c %c %c %c %c %c %c %c", state->buf_data[*f_pos],state->buf_data[*f_pos+1],state->buf_data[*f_pos+2],state->buf_data[*f_pos+3],state->buf_data[*f_pos+4],state->buf_data[*f_pos+5],state->buf_data[*f_pos+6],state->buf_data[*f_pos+cnt-1]);
        if (copy_to_user(usrbuf, &(state->buf_data[*f_pos]), cnt) != 0) {
                up(&state->lock);
                debug("problem in copy_to_user");
                return -EFAULT;
        }
        /* ? */

        debug("data copied: %c %c %c %c ...",*(usrbuf),*(usrbuf+1),*(usrbuf+2),*(usrbuf+3));

        /* Auto-rewind on EOF mode? */
        /* ? */
out:
        /* Unlock? */
        debug("final unlocking");
        up(&state->lock);
        ret = cnt;
        debug("leaving read");
        return ret;
}

static int lunix_chrdev_mmap(struct file *filp, struct vm_area_struct *vma)
{
        return -EINVAL;
}

static struct file_operations lunix_chrdev_fops =
{
        .owner          = THIS_MODULE,
        .open           = lunix_chrdev_open,
        .release        = lunix_chrdev_release,
        .read           = lunix_chrdev_read,
        .unlocked_ioctl = lunix_chrdev_ioctl,
        .mmap           = lunix_chrdev_mmap
};

int lunix_chrdev_init(void)
{
        /*
         * Register the character device with the kernel, asking for
         * a range of minor numbers (number of sensors * 8 measurements / sensor)
         * beginning with LINUX_CHRDEV_MAJOR:0
         */
        int ret;
        dev_t dev_no;
        unsigned int lunix_minor_cnt = lunix_sensor_cnt << 3;

        debug("initializing character device\n");
        cdev_init(&lunix_chrdev_cdev, &lunix_chrdev_fops);
        lunix_chrdev_cdev.owner = THIS_MODULE;

        dev_no = MKDEV(LUNIX_CHRDEV_MAJOR, 0);
        /* ? */
        ret = register_chrdev_region(dev_no, lunix_minor_cnt, "Strive");
        // maybe malloc_chrdev_region is better?
        /* register_chrdev_region? */
        if (ret < 0) {
                debug("failed to register region, ret = %d\n", ret);
                goto out;
        }
        /* ? */
        ret = cdev_add(&lunix_chrdev_cdev, dev_no, lunix_minor_cnt);
        /* cdev_add? */
        if (ret < 0) {
                debug("failed to add character device\n");
                goto out_with_chrdev_region;
        }
        debug("completed successfully\n");
        return 0;

out_with_chrdev_region:
        unregister_chrdev_region(dev_no, lunix_minor_cnt);
out:
        return ret;
}

void lunix_chrdev_destroy(void)
{
        dev_t dev_no;
        unsigned int lunix_minor_cnt = lunix_sensor_cnt << 3;

        debug("entering\n");
        dev_no = MKDEV(LUNIX_CHRDEV_MAJOR, 0);
        cdev_del(&lunix_chrdev_cdev);
        unregister_chrdev_region(dev_no, lunix_minor_cnt);
        debug("leaving\n");
}

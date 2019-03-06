#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>

#include <linux/kthread.h>
#include <linux/mutex.h>
#include <linux/signal.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/netdevice.h>
#include <linux/ip.h>
#include <linux/in.h>

#include <linux/pid.h>

#include <linux/delay.h>

#define DEFAULT_PORT 6666
#define CONNECT_PORT 23
#define MODULE_NAME "ktrudp"
#define INADDR_SEND INADDR_LOOPBACK

struct kthread_t
{
        struct task_struct *thread;
        struct socket *sock;
        struct sockaddr_in addr;
        struct socket *sock_send;
        struct sockaddr_in addr_send;
        int running; 
        struct mutex mut_k;
};

struct kthread_t *kthread = NULL;

int ktrudp_recv(struct socket *sock, struct sockaddr_in *addr,
        unsigned char *buf, int len);
int ktrudp_send(struct socket *sock, struct sockaddr_in *addr,
        unsigned char *buf, int len);

static void ktrudp_start(void)
{
        int size;
        int err;
        int bufsize = 10;
        unsigned char buf[bufsize + 1];
    
        mutex_lock(&kthread->mut_k);
        kthread->running = 1;
        kthread->thread->flags |= PF_NOFREEZE;
        allow_signal(SIGKILL);
        mutex_unlock(&kthread->mut_k);

        if (((err = sock_create(AF_INET, SOCK_DGRAM, IPPROTO_UDP, &kthread->sock)) < 0) ||
            ((err = sock_create(AF_INET, SOCK_DGRAM, IPPROTO_UDP, &kthread->sock_send)) < 0 )) {
                printk(KERN_INFO MODULE_NAME": Could not create a datagram socket, error = %d\n",
                        -ENXIO);
                goto out;
        }

        memset(&kthread->addr, 0, sizeof(struct sockaddr));
        memset(&kthread->addr_send, 0, sizeof(struct sockaddr));
        kthread->addr.sin_family      = AF_INET;
        kthread->addr_send.sin_family = AF_INET;

        kthread->addr.sin_addr.s_addr      = htonl(INADDR_ANY);
        kthread->addr_send.sin_addr.s_addr = htonl(INADDR_SEND);

        kthread->addr.sin_port      = htons(DEFAULT_PORT);
        kthread->addr_send.sin_port = htons(CONNECT_PORT);

        if (((err = kthread->sock->ops->bind(kthread->sock, (struct sockaddr *)&kthread->addr,
                            sizeof(struct sockaddr))) < 0) ||
             (err = kthread->sock_send->ops->connect(kthread->sock_send,
                (struct sockaddr *)&kthread->addr_send, sizeof(struct sockaddr), 0) < 0 )) {
                printk(KERN_INFO MODULE_NAME": Could not bind or connect to socket, error = %d\n",
                        -err);
                goto halt;
        }
        
        printk(KERN_INFO MODULE_NAME": listening on port %d\n", DEFAULT_PORT);

        while (1) {
                memset(&buf, 0, bufsize+1);
                size = ktrudp_recv(kthread->sock, &kthread->addr, buf, bufsize);

                if (signal_pending(current)) break;

                if (size < 0) {
                        printk(KERN_INFO MODULE_NAME": error getting datagram,"
                                "sock_recv msg error = %d\n", size);
                } else {
                        printk(KERN_INFO MODULE_NAME": received %d bytes\n", size);
                        printk("\n data: %s\n", buf);

                        memset(&buf, 0, bufsize+1);
                        strcat(buf, "Hello :-)");
                        ktrudp_send(kthread->sock_send, &kthread->addr_send, buf, strlen(buf));
                }
        }

halt:
        sock_release(kthread->sock);
        sock_release(kthread->sock_send);
        kthread->sock = NULL;
        kthread->sock_send = NULL;
out:
        kthread->thread = NULL;
        kthread->running = 0;
}

int ktrudp_recv(struct socket *sock, struct sockaddr_in *addr,
        unsigned char *buf, int len)
{
        struct msghdr msg;
        struct iovec iov;
        mm_segment_t oldfs;
        int size = 0;

        if (sock->sk==NULL) return 0;

        iov.iov_base = buf;
        iov.iov_len = len;

        msg.msg_flags = 0;
        msg.msg_name = addr;
        msg.msg_namelen  = sizeof(struct sockaddr_in);
        msg.msg_control = NULL;
        msg.msg_controllen = 0;

        iov_iter_init(&msg.msg_iter, WRITE, &iov, 1, len);
        
        msg.msg_control = NULL;

        oldfs = get_fs();
        set_fs(KERNEL_DS);
        size = sock_recvmsg(sock, &msg, msg.msg_flags);
        set_fs(oldfs);

        return size;
}

int ktrudp_send(struct socket *sock, struct sockaddr_in *addr,
        unsigned char *buf, int len)
{
        struct msghdr msg;
        struct iovec iov;
        mm_segment_t oldfs;
        int size = 0;

        if (sock->sk==NULL)
           return 0;

        iov.iov_base = buf;
        iov.iov_len = len;

        msg.msg_flags = 0;
        msg.msg_name = addr;
        msg.msg_namelen  = sizeof(struct sockaddr_in);
        msg.msg_control = NULL;
        msg.msg_controllen = 0;
        iov_iter_init(&msg.msg_iter, WRITE, &iov, 1, len);
        msg.msg_control = NULL;

        oldfs = get_fs();
        set_fs(KERNEL_DS);
        size = sock_sendmsg(sock, &msg);
        set_fs(oldfs);

        return size;
}


int __init ktrudp_init(void)
{
        kthread = kmalloc(sizeof(struct kthread_t), GFP_KERNEL);
        memset(kthread, 0, sizeof(struct kthread_t));

        /* start kernel thread */
        kthread->thread = kthread_run((void *)ktrudp_start, NULL, MODULE_NAME);
        if (IS_ERR(kthread->thread)) {
                printk(KERN_INFO MODULE_NAME": unable to start kernel thread\n");
                kfree(kthread);
                kthread = NULL;
                return -ENOMEM;
        }
        return 0;    
}

void __exit ktrudp_exit(void)
{
        int err = 0;
        struct task_struct *tsk;
        struct pid *pid;
        
        if (kthread->thread==NULL) {
                printk(KERN_INFO MODULE_NAME": no kernel thread to kill\n");
        } else {
                mutex_lock(&kthread->mut_k);
                pid = find_get_pid((pid_t)kthread->thread->pid);
                tsk = pid_task(pid, PIDTYPE_PID);
                if (tsk) err = send_sig(SIGKILL, tsk, 1);

                mutex_unlock(&kthread->mut_k);

                /* wait for kernel thread to die */
                if (err < 0) {
                        printk(KERN_INFO MODULE_NAME": unknown error %d while trying to terminate kernel thread\n",-err);
                } else {
                        while (kthread->running == 1)
                                msleep(10);
                        printk(KERN_INFO MODULE_NAME": succesfully killed kernel thread!\n");
                }
        }

        /* free allocated resources before exit */
        if (kthread->sock != NULL) 
        {
                sock_release(kthread->sock);
                kthread->sock = NULL;
        }

        kfree(kthread);
        kthread = NULL;

        printk(KERN_INFO MODULE_NAME": module unloaded\n");
}
EXPORT_SYMBOL_GPL(ktrudp_exit);

module_init(ktrudp_init);
module_exit(ktrudp_exit);

MODULE_DESCRIPTION("trudp kernel");
MODULE_AUTHOR("max <mpano91@gmail.com>");
MODULE_LICENSE("GPL");

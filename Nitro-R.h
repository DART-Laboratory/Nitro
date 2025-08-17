#define FIXED_SHRINK FULL_FIXED_LEN - 128
#define FLEX_SHRINK FULL_FLEX - 256
#define CPU_Array_Size (FULL_FIXED_LEN * 8 + FULL_FLEX)
#define Ring_Bytes_Size RSIZE * 4096
#define SYS_END 0xffffffff
#define SPLIT_ARG 0xfefefefe
#define SYS_END_S 0xff
#define SPLIT_ARG_S 0xfe
#define SPLIT_EACH 0xfd
#define Lock (Ring_Bytes_Size / CPU_Array_Size) - 300

#define DUP_TIME_WINDOW 1000000000ULL

struct log_key {
    u32 pid;
    u32 syscall;
    char args[COMMSIZE];
};

BPF_TABLE("lru_hash", struct log_key, __u64, dup_log, 1024);


struct per_syscall {
    u64 ts;
    u32 id;
    unsigned int idx;
    unsigned int fdx;
    unsigned long tag;
    unsigned long enc;
    int counter;
    u32 state[4];
    long fixed[FULL_FIXED_LEN];
    char flex[FULL_FLEX];
};

BPF_ARRAY(loss_bytes, u64, 1);
BPF_ARRAY(total_bytes, u64, 1);
BPF_RINGBUF_OUTPUT(events, RSIZE);
BPF_PERCPU_ARRAY(per_syscall, struct per_syscall, 1);

#include <uapi/asm-generic/siginfo.h>
#include <uapi/asm-generic/statfs.h>
#include <uapi/asm-generic/mman.h>
#include <uapi/linux/mman.h>
#include <uapi/linux/ptrace.h>
#include <uapi/linux/capability.h>
#include <uapi/linux/fs.h>
#include <uapi/linux/bpf.h>

#include <linux/sched.h>
#include <linux/fdtable.h>
#include <linux/fcntl.h>
#include <linux/socket.h>
#include <linux/ipv6.h>

#include <net/sock.h>
#include <net/inet_sock.h>
#include <net/af_unix.h>


#include "Nitro-R.h"

#define ROTL(x, b) (u32)(((x) >> (32 - (b))) | ( (x) << (b)))


static int gettid() {

   return bpf_get_current_pid_tgid();
}


static int __bpf_split_str(struct per_syscall *s){
    if (s->fdx > FLEX_SHRINK) {
		return 1;
	}
	if ((s->fdx < FLEX_SHRINK) && (SPLIT_EACH & 0xff) == SPLIT_EACH){
	    s->flex[s->fdx] = SPLIT_EACH;
	    s->fdx++;
        return 0;
	}
	return 1;
}


static unsigned long __bpf_unit_encrypt(u32 v[4], u32 key[4]){
    int i;
    for (i=0; i<4; i++) v[i] ^= key[i];
    for (i=0; i<8; i++) {
     v[0] += v[1]; v[1]=ROTL(v[1], 5); v[1] ^= v[0]; v[0]=ROTL(v[0],16);
     v[2] += v[3]; v[3]=ROTL(v[3], 8); v[3] ^= v[2];
     v[0] += v[3]; v[3]=ROTL(v[3], 13); v[3] ^= v[0];
     v[2] += v[1]; v[1]=ROTL(v[1], 7); v[1] ^= v[2]; v[2]=ROTL(v[2],16);
   }
   for (i=0; i<4; i++){
        v[i] ^= key[i];
   }

   return ((unsigned long)v[0]) |
          ((unsigned long)v[1] << 16) |
          ((unsigned long)v[2] << 32) |
          ((unsigned long)v[3] << 48);
}


static u32* __bpf_xor_block(u32 a[4], u32 b[4]){

#pragma unroll
	for (int i = 0; i < 4; i++) {
		a[i] ^= b[i];
	}

	return a;
}

BPF_ARRAY(threshold, u64, 1);

static u32* __bpf_permutation(u32 v[4]){
    u32 fk[4] = {0x1010, 0x0101, 0x0000, 0x1111};
    int i;
    for (i=0; i<4; i++) v[i] ^= fk[i];
    for (i=0; i<8; i++) {
     v[0] += v[1]; v[1]=ROTL(v[1], 5); v[1] ^= v[0]; v[0]=ROTL(v[0],16);
     v[2] += v[3]; v[3]=ROTL(v[3], 8); v[3] ^= v[2];
     v[0] += v[3]; v[3]=ROTL(v[3], 13); v[3] ^= v[0];
     v[2] += v[1]; v[1]=ROTL(v[1], 7); v[1] ^= v[2]; v[2]=ROTL(v[2],16);
   }
   for (i=0; i<4; i++){
        v[i] ^= fk[i];
   }

   return v;
}


static void __bpf_update_state(struct per_syscall *s){
    u32 em[4] = {0x0001, 0x0001, 0x0001, 0x0001};
    u32 *p;

    p = __bpf_xor_block(em, s->state);

    u32 ne[4] = {*(p), *(p+1), *(p+2), *(p+3)};

    u32* tp = __bpf_permutation(ne);

#pragma unroll
	for (int i = 0; i < 4; i++) {
		s->state[i] ^= *(tp + i);
	}

}

static void __bpf_update_enc(struct per_syscall *s){
    u32 em_2[4] = {0x0002, 0x0002, 0x0002, 0x0002};
    u32 tkp[4] = {0x0000, 0x0000, 0x0000, 0x0000};
    u32 *p_2;

    p_2 = __bpf_xor_block(em_2, s->state);

    u32 ne_2[4] = {*(p_2), *(p_2+1), *(p_2+2), *(p_2+3)};

    u32* tp_2 = __bpf_permutation(ne_2);

#pragma unroll
	for (int i = 0; i < 4; i++) {
		tkp[i] = s->state[i] ^ (*(tp_2 + i));
	}

    unsigned long TS = ((unsigned long)tkp[0]) | ((unsigned long)tkp[1] << 16) | ((unsigned long)tkp[2] << 32) | ((unsigned long)tkp[3] << 48);

    s->enc = s->tag ^ TS;

}


static int __bpf_encrypt_round(struct per_syscall *s, char a[16]){
    u32 b[4];

    for (int i = 0; i < 4; i++) {
        b[i] = ((u32)a[i * 4]) | ((u32)a[i * 4 + 1] << 8) |
               ((u32)a[i * 4 + 2] << 16) | ((u32)a[i * 4 + 3] << 24);
    }

    s->tag ^= __bpf_unit_encrypt(b, s->state);
    __bpf_update_state(s);

    return 1;
}


static int __bpf_read_comm_str(struct per_syscall *s, const char *ptr)
{
	if (s->fdx > FLEX_SHRINK) {
		return -1;
	}

    char w_padding[COMMSIZE] = {0};

	int n = bpf_probe_read_user_str(&s->flex[s->fdx], COMMSIZE,
					  (void *)ptr);
	if (n > COMMSIZE || n < 0) {
		return -1;
	}

    s->fdx += (n - 1);

	n = bpf_probe_read_user_str(&w_padding[0], COMMSIZE,
					  (void *)ptr);
	if (n > COMMSIZE || n < 0) {
		return -1;
	}

    char tmp[16] = {0};

     bpf_probe_read(&tmp, 16, &w_padding[0]);
    __bpf_encrypt_round(s, tmp);

    bpf_probe_read(&tmp, 16, &w_padding[16]);
    __bpf_encrypt_round(s, tmp);

    bpf_probe_read(&tmp, 16, &w_padding[32]);
    __bpf_encrypt_round(s, tmp);

    bpf_probe_read(&tmp, 16, &w_padding[48]);
    __bpf_encrypt_round(s, tmp);

    if (s->fdx > FLEX_SHRINK) {
		return -1;
	}

    s->flex[s->fdx++] = SPLIT_ARG_S;

	return 0;
}


static int __bpf_roundly_encrypt_32(struct per_syscall *s, const char *ptr)
{
    char tmp[16] = {0};

    bpf_probe_read(&tmp, 16, ptr);
    __bpf_encrypt_round(s, tmp);

    char tmp2[16] = {0};
    bpf_probe_read(&tmp2, 16, (ptr+16));
    __bpf_encrypt_round(s, tmp2);

    return 0;
}


static int __bpf_read_arg_str(struct per_syscall *s, const char *ptr)
{
	if (s->fdx > FLEX_SHRINK) {
		return -1;
	}

    char w_padding[FLEXSIZE] = {0};

	int n = bpf_probe_read_user_str(&s->flex[s->fdx], FLEXSIZE,
					  (void *)ptr);
	if (n > FLEXSIZE || n < 0) {
		return -1;
	}
	s->fdx += (n - 1);

    n = bpf_probe_read_user_str(&w_padding[0], FLEXSIZE,
					  (void *)ptr);
	if (n > COMMSIZE || n < 0) {
		return -1;
	}

    __bpf_roundly_encrypt_32(s, w_padding);

	return 0;
}


static int __bpf_enter_init(struct per_syscall *s, int a, u32 b){
    int v = b & 0xffffffff;
    if (v == b){
        if (s->idx < FIXED_SHRINK){
            s->fixed[s->idx++] = v;
            s->fixed[s->idx++] = a;
            s->fixed[s->idx++] = SYS_END;
            s->counter += 1;
            return 0;
        }
        return -1;
    }
    return -1;
}


static int __bpf_enter_init2(struct per_syscall *s, int a, u32 b, long c){
    int v = b & 0xffffffff;
    if (v == b){
        if (s->idx < FIXED_SHRINK){
            s->fixed[s->idx++] = v;
            s->fixed[s->idx++] = a;
            s->fixed[s->idx++] = c;
            s->fixed[s->idx++] = SYS_END;
            s->counter += 1;
            return 0;
        }
        return -1;
    }
    return -1;
}


static int __bpf_enter_init4(struct per_syscall *s, int a, u32 b, long c, long d, long e){
    int v = b & 0xffffffff;
    if (v == b){
        if (s->idx < FIXED_SHRINK){
            s->fixed[s->idx++] = v;
            s->fixed[s->idx++] = a;
            s->fixed[s->idx++] = c;
            s->fixed[s->idx++] = d;
            s->fixed[s->idx++] = e;
            s->fixed[s->idx++] = SYS_END;
            s->counter += 1;
            return 0;
        }
        return -1;
    }
    return -1;
}


static void __bpf_initial_state(){
    int z=0;
	struct per_syscall *s = per_syscall.lookup(&z);
	if (s != NULL){
	u32 t1 = bpf_get_prandom_u32();
    u32 t2 = bpf_get_prandom_u32();
    u32 t3 = bpf_get_prandom_u32();
    u32 t4 = bpf_get_prandom_u32();
    u32 id = bpf_get_prandom_u32();
    unsigned long t = ((unsigned long)t1) |
                           ((unsigned long)t2 << 16) |
                           ((unsigned long)t3 << 32) |
                           ((unsigned long)t4 << 48);
    s->tag = t;
    s->id = id;
#pragma unroll
	for (int i = 0; i < 4; i++) {
		u32 tk = bpf_get_prandom_u32();
		s->state[i] = tk;
	    }
    }
}


static int __bpf_ring_buffer_submit(struct per_syscall *s, int force){
    u32 key = 0;

    if (s->tag == 0){
        __bpf_initial_state();
        return 1;
    }
    u64 now = bpf_ktime_get_ns();
    if (force || now - s->ts > SGAP || s->idx > FIXED_SHRINK  || s->fdx > FLEX_SHRINK){
        int ret = 0;
        __bpf_update_enc(s);
        u64 *tr = threshold.lookup(&key);
        if (tr){
           if (now - s->ts > GAP || *tr > Lock){
                ret = events.ringbuf_output(s, sizeof(struct per_syscall), BPF_RB_FORCE_WAKEUP);
                *tr = 0;
        }
        else{
            ret = events.ringbuf_output(s, sizeof(struct per_syscall), BPF_RB_NO_WAKEUP);
            __sync_fetch_and_add(tr, 1);
        }
        }

        u64 size_event = s->idx + s->fdx;
           if (ret < 0) {
                 u64 *loss = loss_bytes.lookup(&key);
                 if (loss) {
                        __sync_fetch_and_add(loss, size_event);
                 }
           }
           u64 *total = total_bytes.lookup(&key);
           if (total) {
                __sync_fetch_and_add(total, size_event);
           }

        s->ts = now;
        s->idx = 0;
        s->fdx = 0;
        s->counter = 0;
    }
    return 0;
}


static int __bpf_crypto_fixed(struct per_syscall *s, u32 a, int b){
    u32 em[4] = {a, b, 0, 0};
    s->tag ^= __bpf_unit_encrypt(em, s->state);
    __bpf_update_state(s);

    return 1;
}


static int __bpf_crypto_fixed2(struct per_syscall *s, u32 a, int b, long c){
    u32 em[4] = {a, b, (u32)(c & 0xFFFFFFFF), (u32)(c >> 32)};
    s->tag ^= __bpf_unit_encrypt(em, s->state);
    __bpf_update_state(s);

    return 1;
}


static int __bpf_crypto_fixed4(struct per_syscall *s, u32 a, int b, long c, long d, long e){
    u32 em[4] = {a, b, (u32)(c & 0xFFFFFFFF), (u32)(c >> 32)};
    s->tag ^= __bpf_unit_encrypt(em, s->state);
    __bpf_update_state(s);

    u32 em2[4] = {(u32)(d & 0xFFFFFFFF), (u32)(d >> 32), (u32)(e & 0xFFFFFFFF), (u32)(e >> 32)};
    s->tag ^= __bpf_unit_encrypt(em2, s->state);
    __bpf_update_state(s);
    return 1;
}


static __always_inline int filter_duplicate(struct log_key *key, u64 now) {
    __u64 *prev = dup_log.lookup(key);
    if (prev) {
        if (now - *prev <= DUP_TIME_WINDOW)
            return 1;
        dup_log.update(key, &now);
        return 0;
    } else {
        dup_log.update(key, &now);
        return 0;
    }
}

TRACEPOINT_PROBE(syscalls, sys_enter_execve)
{
	const char **argv = (const char **)(args->argv);
	const char **env = (const char **)(args->envp);
    int z=0;
    u32 pid = bpf_get_current_pid_tgid();
	struct per_syscall *s = per_syscall.lookup(&z);
	if (s != NULL){

    __bpf_ring_buffer_submit(s, 0);
    struct log_key dup_key = {};
    dup_key.pid = pid;
    dup_key.syscall = 0;
    long r = bpf_probe_read_user_str(dup_key.args, sizeof(dup_key.args), (const char *)args->filename);
    if (r < 0) {
        dup_key.args[0] = '\0';
    }

    if (filter_duplicate(&dup_key, bpf_ktime_get_ns())) {goto out;}
    if (__bpf_enter_init(s, 0, pid) < 0){
	        goto out;
	}

    if(__bpf_crypto_fixed(s, pid, 0) < 0){
        goto out;
    }

    if (__bpf_read_comm_str(s, (const char *)args->filename) < 0) {
		goto out;
	}

#pragma unroll
	for (int i = 0; i < TOTAL_MAX_FLEX / 2; i++) {
		if (__bpf_split_str(s) > 0 || __bpf_read_arg_str(s, (const char *)argv[i]) < 0) {
			goto arg_end;
		}
	}

arg_end:
	if ((SYS_END_S & 0xff) == SYS_END_S && s->fdx < FULL_FLEX -1){
	    s->flex[s->fdx++] = SYS_END_S;
	}else{
	    goto out;
	}

    }

out:
    return 0;
}


TRACEPOINT_PROBE(syscalls, sys_enter_open)
{
    int tid = gettid();
    if (tid == SELF) return 0;
    int z=0;
    unsigned int tmp;
    u32 pid = bpf_get_current_pid_tgid();
	struct per_syscall *s = per_syscall.lookup(&z);
	if (s != NULL){
	    __bpf_ring_buffer_submit(s, 0);
        {
            struct log_key dup_key = {};
            dup_key.pid = pid;
            dup_key.syscall = 1;
            long r = bpf_probe_read_user_str(dup_key.args, sizeof(dup_key.args), (const char *)args->filename);
            if (r < 0) {
                dup_key.args[0] = '\0';
            }
            if (filter_duplicate(&dup_key, bpf_ktime_get_ns()))
                goto open_enter_out;
        }
	    if (__bpf_enter_init(s, 1, pid) < 0){
	        goto open_enter_out;
	    }

	    if(__bpf_crypto_fixed(s, pid, 1) < 0){
            goto open_enter_out;
        }

	    if (__bpf_read_comm_str(s, (const char *)args->filename) < 0) {
		    goto open_enter_end;
	    }

open_enter_end:
        bpf_probe_read(&tmp, 4, &s->fdx);
		if ((SYS_END_S & 0xff) == SYS_END_S && tmp < FULL_FLEX -1){
	        s->flex[tmp] = SYS_END_S;
	        s->fdx += 1;
	    }

	}

open_enter_out:
    return 0;

}


TRACEPOINT_PROBE(syscalls, sys_enter_openat)
{
    int tid = gettid();
    if (tid == SELF) return 0;
    int z=0;
    unsigned int tmp;
    u32 pid = bpf_get_current_pid_tgid();
	struct per_syscall *s = per_syscall.lookup(&z);
	if (s != NULL){
	    __bpf_ring_buffer_submit(s, 0);
        {
            struct log_key dup_key = {};
            dup_key.pid = pid;
            dup_key.syscall = 2;
            long r = bpf_probe_read_user_str(dup_key.args, sizeof(dup_key.args), (const char *)args->filename);
            if (r < 0) {
             dup_key.args[0] = '\0';
            }
            if (filter_duplicate(&dup_key, bpf_ktime_get_ns()))
                goto openat_enter_out;
        }
	    if (__bpf_enter_init(s, 2, pid) < 0){
	        goto openat_enter_out;
	    }

	    if(__bpf_crypto_fixed(s, pid, 2) < 0){
            goto openat_enter_out;
        }

	    if (__bpf_read_comm_str(s, (const char *)args->filename) < 0) {
		    goto openat_enter_end;
	    }

openat_enter_end:
        bpf_probe_read(&tmp, 4, &s->fdx);
		if ((SYS_END_S & 0xff) == SYS_END_S && tmp < FULL_FLEX -1){
	        s->flex[tmp] = SYS_END_S;
	        s->fdx += 1;
	    }

	}

openat_enter_out:
    return 0;

}


TRACEPOINT_PROBE(syscalls, sys_enter_creat)
{
    int tid = gettid();
    if (tid == SELF) return 0;
    int z=0;
    unsigned int tmp;
    u32 pid = bpf_get_current_pid_tgid();
	struct per_syscall *s = per_syscall.lookup(&z);
	if (s != NULL){
	    __bpf_ring_buffer_submit(s, 0);
        {
            struct log_key dup_key = {};
            dup_key.pid = pid;
            dup_key.syscall = 3;
            long r = bpf_probe_read_user_str(dup_key.args, sizeof(dup_key.args), (const char *)args->pathname);
            if (r < 0) {
                dup_key.args[0] = '\0';
            }
            if (filter_duplicate(&dup_key, bpf_ktime_get_ns()))
                goto creat_enter_out;
        }
	    if (__bpf_enter_init(s, 3, pid) < 0){
	        goto creat_enter_out;
	    }

	    if(__bpf_crypto_fixed(s, pid, 3) < 0){
            goto creat_enter_out;
        }

	    if (__bpf_read_comm_str(s, (const char *)args->pathname) < 0) {
		    goto creat_enter_end;
	    }

creat_enter_end:
        bpf_probe_read(&tmp, 4, &s->fdx);
		if ((SYS_END_S & 0xff) == SYS_END_S && tmp < FULL_FLEX -1){
	        s->flex[tmp] = SYS_END_S;
	        s->fdx += 1;
	    }

	}

creat_enter_out:
    return 0;

}


TRACEPOINT_PROBE(syscalls, sys_enter_truncate)
{
    int tid = gettid();
    if (tid == SELF) return 0;
    int z=0;
    unsigned int tmp;
    u32 pid = bpf_get_current_pid_tgid();
	struct per_syscall *s = per_syscall.lookup(&z);
	if (s != NULL){
	    __bpf_ring_buffer_submit(s, 0);
        {
            struct log_key dup_key = {};
            dup_key.pid = pid;
            dup_key.syscall = 4;
            long r = bpf_probe_read_user_str(dup_key.args, sizeof(dup_key.args), (const char *)args->path);
            if (r < 0) {
                dup_key.args[0] = '\0';
            }
            if (filter_duplicate(&dup_key, bpf_ktime_get_ns()))
                goto truncate_enter_out;
        }
	    if (__bpf_enter_init(s, 4, pid) < 0){
	        goto truncate_enter_out;
	    }

	    if(__bpf_crypto_fixed(s, pid, 4) < 0){
            goto truncate_enter_out;
        }

	    if (__bpf_read_comm_str(s, (const char *)args->path) < 0) {
		    goto truncate_enter_end;
	    }

truncate_enter_end:
        bpf_probe_read(&tmp, 4, &s->fdx);
		if ((SYS_END_S & 0xff) == SYS_END_S && tmp < FULL_FLEX -1){
	        s->flex[tmp] = SYS_END_S;
	        s->fdx += 1;
	    }

	}

truncate_enter_out:
    return 0;

}


TRACEPOINT_PROBE(syscalls, sys_enter_ftruncate)
{
    int z=0;
    u32 pid = bpf_get_current_pid_tgid();
	struct per_syscall *s = per_syscall.lookup(&z);
	if (s != NULL){
	    __bpf_ring_buffer_submit(s, 0);
        {
            struct log_key dup_key = {};
            dup_key.pid = pid;
            dup_key.syscall = 5;

            if (filter_duplicate(&dup_key, bpf_ktime_get_ns()))
                goto ftruncate_enter_out;
        }
	    if (__bpf_enter_init2(s, 5, pid, args->fd) < 0){
	        goto ftruncate_enter_out;
	    }

        if(__bpf_crypto_fixed2(s, pid, 5, args->fd) < 0){
            goto ftruncate_enter_out;
        }
    }

ftruncate_enter_out:
    return 0;
}


TRACEPOINT_PROBE(syscalls, sys_enter_dup)
{
    int z=0;
    u32 pid = bpf_get_current_pid_tgid();
	struct per_syscall *s = per_syscall.lookup(&z);
	if (s != NULL){
	    __bpf_ring_buffer_submit(s, 0);
        {
            struct log_key dup_key = {};
            dup_key.pid = pid;
            dup_key.syscall = 6;
            if (filter_duplicate(&dup_key, bpf_ktime_get_ns()))
                goto dup_enter_out;
        }
	    if (__bpf_enter_init2(s, 6, pid, args->fildes) < 0){
	        goto dup_enter_out;
	    }

        if(__bpf_crypto_fixed2(s, pid, 6, args->fildes) < 0){
            goto dup_enter_out;
        }
    }

dup_enter_out:
    return 0;
}


TRACEPOINT_PROBE(syscalls, sys_enter_dup2)
{
    int z=0;
    u32 pid = bpf_get_current_pid_tgid();
	struct per_syscall *s = per_syscall.lookup(&z);
	if (s != NULL){
	    __bpf_ring_buffer_submit(s, 0);
        {
            struct log_key dup_key = {};
            dup_key.pid = pid;
            dup_key.syscall = 7;
            if (filter_duplicate(&dup_key, bpf_ktime_get_ns()))
                goto dup2_enter_out;
        }
	    if (__bpf_enter_init2(s, 7, pid, args->oldfd) < 0){
	        goto dup2_enter_out;
	    }

        if(__bpf_crypto_fixed2(s, pid, 7, args->oldfd) < 0){
            goto dup2_enter_out;
        }

    }

dup2_enter_out:
    return 0;
}


TRACEPOINT_PROBE(syscalls, sys_enter_dup3)
{
    int z=0;
    u32 pid = bpf_get_current_pid_tgid();
	struct per_syscall *s = per_syscall.lookup(&z);
	if (s != NULL){
	    __bpf_ring_buffer_submit(s, 0);
        {
            struct log_key dup_key = {};
            dup_key.pid = pid;
            dup_key.syscall = 8;
            if (filter_duplicate(&dup_key, bpf_ktime_get_ns()))
                goto dup3_enter_out;
        }
	    if (__bpf_enter_init2(s, 8, pid, args->oldfd) < 0){
	        goto dup3_enter_out;
	    }

        if(__bpf_crypto_fixed2(s, pid, 8, args->oldfd) < 0){
            goto dup3_enter_out;
        }
    }

dup3_enter_out:
    return 0;
}


TRACEPOINT_PROBE(syscalls, sys_enter_fcntl)
{
    int z=0;
    u32 pid = bpf_get_current_pid_tgid();
	struct per_syscall *s = per_syscall.lookup(&z);
	if (s != NULL){
	    __bpf_ring_buffer_submit(s, 0);
        {
            struct log_key dup_key = {};
            dup_key.pid = pid;
            dup_key.syscall = 9;
            if (filter_duplicate(&dup_key, bpf_ktime_get_ns()))
                goto fcntl_enter_out;
        }
	    if (__bpf_enter_init2(s, 9, pid, args->fd) < 0){
	        goto fcntl_enter_out;
	    }

        if(__bpf_crypto_fixed2(s, pid, 9, args->fd) < 0){
            goto fcntl_enter_out;
        }
    }

fcntl_enter_out:
    return 0;
}


TRACEPOINT_PROBE(syscalls, sys_enter_pipe)
{
    int z=0;
    u32 pid = bpf_get_current_pid_tgid();
	struct per_syscall *s = per_syscall.lookup(&z);
	if (s != NULL){
	    __bpf_ring_buffer_submit(s, 0);
        {
            struct log_key dup_key = {};
            dup_key.pid = pid;
            dup_key.syscall = 10;
            if (filter_duplicate(&dup_key, bpf_ktime_get_ns()))
                goto pipe_enter_out;
        }
	    if (__bpf_enter_init2(s, 10, pid, (long)args->fildes) < 0){
	        goto pipe_enter_out;
	    }

        if(__bpf_crypto_fixed2(s, pid, 10, (long)args->fildes) < 0){
            goto pipe_enter_out;
        }
    }

pipe_enter_out:
    return 0;
}


TRACEPOINT_PROBE(syscalls, sys_enter_socketpair)
{
    int z=0;
    u32 pid = bpf_get_current_pid_tgid();
    struct per_syscall *s = per_syscall.lookup(&z);
    if (s != NULL) {
        __bpf_ring_buffer_submit(s, 0);
        {
            struct log_key dup_key = {};
            dup_key.pid = pid;
            dup_key.syscall = 11;
            if (filter_duplicate(&dup_key, bpf_ktime_get_ns()))
                goto socketpair_enter_out;
        }
        if (__bpf_enter_init2(s, 11, pid, (long)args->usockvec) < 0)
            goto socketpair_enter_out;
        if (__bpf_crypto_fixed2(s, pid, 11, (long)args->usockvec) < 0)
            goto socketpair_enter_out;
    }
socketpair_enter_out:
    return 0;
}


TRACEPOINT_PROBE(syscalls, sys_enter_pipe2)
{
    int z=0;
    u32 pid = bpf_get_current_pid_tgid();
    struct per_syscall *s = per_syscall.lookup(&z);
    if (s != NULL) {
        __bpf_ring_buffer_submit(s, 0);
        {
            struct log_key dup_key = {};
            dup_key.pid = pid;
            dup_key.syscall = 12;
            if (filter_duplicate(&dup_key, bpf_ktime_get_ns()))
                goto pipe2_enter_out;
        }
        if (__bpf_enter_init2(s, 12, pid, (long)args->fildes) < 0)
            goto pipe2_enter_out;
        if (__bpf_crypto_fixed2(s, pid, 12, (long)args->fildes) < 0)
            goto pipe2_enter_out;
    }
pipe2_enter_out:
    return 0;
}


TRACEPOINT_PROBE(syscalls, sys_enter_socket)
{
    int z=0;
    u32 pid = bpf_get_current_pid_tgid();
    struct per_syscall *s = per_syscall.lookup(&z);
    if (s != NULL) {
        __bpf_ring_buffer_submit(s, 0);
        {
            struct log_key dup_key = {};
            dup_key.pid = pid;
            dup_key.syscall = 13;
            if (filter_duplicate(&dup_key, bpf_ktime_get_ns()))
                goto socket_enter_out;
        }
        if (__bpf_enter_init4(s, 13, pid, (long)args->family, (long)args->type, (long)args->protocol) < 0)
            goto socket_enter_out;
        if (__bpf_crypto_fixed4(s, pid, 13, (long)args->family, (long)args->type, (long)args->protocol) < 0)
            goto socket_enter_out;
    }
socket_enter_out:
    return 0;
}


TRACEPOINT_PROBE(syscalls, sys_enter_accept)
{
    int z=0;
    u32 pid = bpf_get_current_pid_tgid();
    struct per_syscall *s = per_syscall.lookup(&z);
    if (s != NULL) {
        __bpf_ring_buffer_submit(s, 0);
        {
            struct log_key dup_key = {};
            dup_key.pid = pid;
            dup_key.syscall = 14;
            if (filter_duplicate(&dup_key, bpf_ktime_get_ns()))
                goto accept_enter_out;
        }
        if (__bpf_enter_init4(s, 14, pid, (long)args->upeer_sockaddr, (long)args->upeer_addrlen, (long)args->fd) < 0)
            goto accept_enter_out;
        if (__bpf_crypto_fixed4(s, pid, 14, (long)args->upeer_sockaddr, (long)args->upeer_addrlen, (long)args->fd) < 0)
            goto accept_enter_out;
    }
accept_enter_out:
    return 0;
}


TRACEPOINT_PROBE(syscalls, sys_enter_accept4)
{
    int z=0;
    u32 pid = bpf_get_current_pid_tgid();
    struct per_syscall *s = per_syscall.lookup(&z);
    if (s != NULL) {
        __bpf_ring_buffer_submit(s, 0);
        {
            struct log_key dup_key = {};
            dup_key.pid = pid;
            dup_key.syscall = 15;
            if (filter_duplicate(&dup_key, bpf_ktime_get_ns()))
                goto accept4_enter_out;
        }
        if (__bpf_enter_init4(s, 15, pid, (long)args->upeer_sockaddr, (long)args->upeer_addrlen, (long)args->fd) < 0)
            goto accept4_enter_out;
        if (__bpf_crypto_fixed4(s, pid, 15, (long)args->upeer_sockaddr, (long)args->upeer_addrlen, (long)args->fd) < 0)
            goto accept4_enter_out;
    }
accept4_enter_out:
    return 0;
}


TRACEPOINT_PROBE(syscalls, sys_enter_connect)
{
    int z=0;
    u32 pid = bpf_get_current_pid_tgid();
    struct per_syscall *s = per_syscall.lookup(&z);
    if (s != NULL) {
        __bpf_ring_buffer_submit(s, 0);
        {
            struct log_key dup_key = {};
            dup_key.pid = pid;
            dup_key.syscall = 16;
            if (filter_duplicate(&dup_key, bpf_ktime_get_ns()))
                goto connect_enter_out;
        }
        if (__bpf_enter_init4(s, 16, pid, (long)args->uservaddr, (long)args->addrlen, (long)args->fd) < 0)
            goto connect_enter_out;
        if (__bpf_crypto_fixed4(s, pid, 16, (long)args->uservaddr, (long)args->addrlen, (long)args->fd) < 0)
            goto connect_enter_out;
    }
connect_enter_out:
    return 0;
}


TRACEPOINT_PROBE(syscalls, sys_enter_getpeername)
{
    int z=0;
    u32 pid = bpf_get_current_pid_tgid();
    struct per_syscall *s = per_syscall.lookup(&z);
    if (s != NULL) {
        __bpf_ring_buffer_submit(s, 0);
        {
            struct log_key dup_key = {};
            dup_key.pid = pid;
            dup_key.syscall = 17;
            if (filter_duplicate(&dup_key, bpf_ktime_get_ns()))
                goto getpeername_enter_out;
        }
        if (__bpf_enter_init4(s, 17, pid, (long)args->usockaddr, (long)args->usockaddr_len, (long)args->fd) < 0)
            goto getpeername_enter_out;
        if (__bpf_crypto_fixed4(s, pid, 17, (long)args->usockaddr, (long)args->usockaddr_len, (long)args->fd) < 0)
            goto getpeername_enter_out;
    }
getpeername_enter_out:
    return 0;
}


TRACEPOINT_PROBE(syscalls, sys_enter_read)
{
    int tid = gettid();
    if (tid == SELF) return 0;
    int z=0;
    u32 pid = bpf_get_current_pid_tgid();
    struct per_syscall *s = per_syscall.lookup(&z);
    if (s != NULL) {
        __bpf_ring_buffer_submit(s, 0);
        {
            struct log_key dup_key = {};
            dup_key.pid = pid;
            dup_key.syscall = 18;
            if (filter_duplicate(&dup_key, bpf_ktime_get_ns()))
                goto read_enter_out;
        }
        if (__bpf_enter_init2(s, 18, pid, (long)args->fd) < 0)
            goto read_enter_out;
        if (__bpf_crypto_fixed2(s, pid, 18, (long)args->fd) < 0)
            goto read_enter_out;
    }
read_enter_out:
    return 0;
}


TRACEPOINT_PROBE(syscalls, sys_enter_readv)
{
    int tid = gettid();
    if (tid == SELF) return 0;
    int z=0;
    u32 pid = bpf_get_current_pid_tgid();
    struct per_syscall *s = per_syscall.lookup(&z);
    if (s != NULL) {
        __bpf_ring_buffer_submit(s, 0);
        {
            struct log_key dup_key = {};
            dup_key.pid = pid;
            dup_key.syscall = 19;
            if (filter_duplicate(&dup_key, bpf_ktime_get_ns()))
                goto readv_enter_out;
        }
        if (__bpf_enter_init2(s, 19, pid, (long)args->fd) < 0)
            goto readv_enter_out;
        if (__bpf_crypto_fixed2(s, pid, 19, (long)args->fd) < 0)
            goto readv_enter_out;
    }
readv_enter_out:
    return 0;
}


TRACEPOINT_PROBE(syscalls, sys_enter_recvmsg)
{
    int tid = gettid();
    if (tid == SELF) return 0;
    int z=0;
    u32 pid = bpf_get_current_pid_tgid();
    struct per_syscall *s = per_syscall.lookup(&z);
    if (s != NULL) {
        __bpf_ring_buffer_submit(s, 0);
        {
            struct log_key dup_key = {};
            dup_key.pid = pid;
            dup_key.syscall = 20;
            if (filter_duplicate(&dup_key, bpf_ktime_get_ns()))
                goto recvmsg_enter_out;
        }
        if (__bpf_enter_init2(s, 20, pid, (long)args->fd) < 0)
            goto recvmsg_enter_out;
        if (__bpf_crypto_fixed2(s, pid, 20, (long)args->fd) < 0)
            goto recvmsg_enter_out;
    }
recvmsg_enter_out:
    return 0;
}


TRACEPOINT_PROBE(syscalls, sys_enter_recvmmsg)
{
    int tid = gettid();
    if (tid == SELF) return 0;
    int z=0;
    u32 pid = bpf_get_current_pid_tgid();
    struct per_syscall *s = per_syscall.lookup(&z);
    if (s != NULL) {
        __bpf_ring_buffer_submit(s, 0);
        {
            struct log_key dup_key = {};
            dup_key.pid = pid;
            dup_key.syscall = 21;
            if (filter_duplicate(&dup_key, bpf_ktime_get_ns()))
                goto recvmmsg_enter_out;
        }
        if (__bpf_enter_init2(s, 21, pid, (long)args->fd) < 0)
            goto recvmmsg_enter_out;
        if (__bpf_crypto_fixed2(s, pid, 21, (long)args->fd) < 0)
            goto recvmmsg_enter_out;
    }
recvmmsg_enter_out:
    return 0;
}


TRACEPOINT_PROBE(syscalls, sys_enter_pread64)
{
    int tid = gettid();
    if (tid == SELF) return 0;
    int z=0;
    u32 pid = bpf_get_current_pid_tgid();
    struct per_syscall *s = per_syscall.lookup(&z);
    if (s != NULL) {
        __bpf_ring_buffer_submit(s, 0);
        {
            struct log_key dup_key = {};
            dup_key.pid = pid;
            dup_key.syscall = 22;
            if (filter_duplicate(&dup_key, bpf_ktime_get_ns()))
                goto pread64_enter_out;
        }
        if (__bpf_enter_init2(s, 22, pid, (long)args->fd) < 0)
            goto pread64_enter_out;
        if (__bpf_crypto_fixed2(s, pid, 22, (long)args->fd) < 0)
            goto pread64_enter_out;
    }
pread64_enter_out:
    return 0;
}


TRACEPOINT_PROBE(syscalls, sys_enter_preadv)
{
    int tid = gettid();
    if (tid == SELF) return 0;
    int z=0;
    u32 pid = bpf_get_current_pid_tgid();
    struct per_syscall *s = per_syscall.lookup(&z);
    if (s != NULL) {
        __bpf_ring_buffer_submit(s, 0);
        {
            struct log_key dup_key = {};
            dup_key.pid = pid;
            dup_key.syscall = 23;
            if (filter_duplicate(&dup_key, bpf_ktime_get_ns()))
                goto preadv_enter_out;
        }
        if (__bpf_enter_init2(s, 23, pid, (long)args->fd) < 0)
            goto preadv_enter_out;
        if (__bpf_crypto_fixed2(s, pid, 23, (long)args->fd) < 0)
            goto preadv_enter_out;
    }
preadv_enter_out:
    return 0;
}


TRACEPOINT_PROBE(syscalls, sys_enter_preadv2)
{
    int tid = gettid();
    if (tid == SELF) return 0;
    int z=0;
    u32 pid = bpf_get_current_pid_tgid();
    struct per_syscall *s = per_syscall.lookup(&z);
    if (s != NULL) {
        __bpf_ring_buffer_submit(s, 0);
        {
            struct log_key dup_key = {};
            dup_key.pid = pid;
            dup_key.syscall = 24;
            if (filter_duplicate(&dup_key, bpf_ktime_get_ns()))
                goto preadv2_enter_out;
        }
        if (__bpf_enter_init2(s, 24, pid, (long)args->fd) < 0)
            goto preadv2_enter_out;
        if (__bpf_crypto_fixed2(s, pid, 24, (long)args->fd) < 0)
            goto preadv2_enter_out;
    }
preadv2_enter_out:
    return 0;
}


TRACEPOINT_PROBE(syscalls, sys_enter_recvfrom)
{
    int z=0;
    u32 pid = bpf_get_current_pid_tgid();
    struct per_syscall *s = per_syscall.lookup(&z);
    if (s != NULL) {
        __bpf_ring_buffer_submit(s, 0);
        {
            struct log_key dup_key = {};
            dup_key.pid = pid;
            dup_key.syscall = 25;
            if (filter_duplicate(&dup_key, bpf_ktime_get_ns()))
                goto recvfrom_enter_out;
        }
        if (__bpf_enter_init4(s, 25, pid, (long)args->addr, (long)args->addr_len, (long)args->fd) < 0)
            goto recvfrom_enter_out;
        if (__bpf_crypto_fixed4(s, pid, 25, (long)args->addr, (long)args->addr_len, (long)args->fd) < 0)
            goto recvfrom_enter_out;
    }
recvfrom_enter_out:
    return 0;
}


TRACEPOINT_PROBE(syscalls, sys_enter_write)
{
    int tid = gettid();
    if (tid == SELF) return 0;
    int z=0;
    u32 pid = bpf_get_current_pid_tgid();
    struct per_syscall *s = per_syscall.lookup(&z);
    if (s != NULL) {
        __bpf_ring_buffer_submit(s, 0);
        {
            struct log_key dup_key = {};
            dup_key.pid = pid;
            dup_key.syscall = 26;
            if (filter_duplicate(&dup_key, bpf_ktime_get_ns()))
                goto write_enter_out;
        }
        if (__bpf_enter_init2(s, 26, pid, (long)args->fd) < 0)
            goto write_enter_out;
        if (__bpf_crypto_fixed2(s, pid, 26, (long)args->fd) < 0)
            goto write_enter_out;
    }
write_enter_out:
    return 0;
}


TRACEPOINT_PROBE(syscalls, sys_enter_writev)
{
    int tid = gettid();
    if (tid == SELF) return 0;
    int z=0;
    u32 pid = bpf_get_current_pid_tgid();
    struct per_syscall *s = per_syscall.lookup(&z);
    if (s != NULL) {
        __bpf_ring_buffer_submit(s, 0);
        {
            struct log_key dup_key = {};
            dup_key.pid = pid;
            dup_key.syscall = 27;
            if (filter_duplicate(&dup_key, bpf_ktime_get_ns()))
                goto writev_enter_out;
        }
        if (__bpf_enter_init2(s, 27, pid, (long)args->fd) < 0)
            goto writev_enter_out;
        if (__bpf_crypto_fixed2(s, pid, 27, (long)args->fd) < 0)
            goto writev_enter_out;
    }
writev_enter_out:
    return 0;
}


TRACEPOINT_PROBE(syscalls, sys_enter_sendmsg)
{
    int tid = gettid();
    if (tid == SELF) return 0;
    int z=0;
    u32 pid = bpf_get_current_pid_tgid();
    struct per_syscall *s = per_syscall.lookup(&z);
    if (s != NULL) {
        __bpf_ring_buffer_submit(s, 0);
        {
            struct log_key dup_key = {};
            dup_key.pid = pid;
            dup_key.syscall = 28;
            if (filter_duplicate(&dup_key, bpf_ktime_get_ns()))
                goto sendmsg_enter_out;
        }
        if (__bpf_enter_init2(s, 28, pid, (long)args->fd) < 0)
            goto sendmsg_enter_out;
        if (__bpf_crypto_fixed2(s, pid, 28, (long)args->fd) < 0)
            goto sendmsg_enter_out;
    }
sendmsg_enter_out:
    return 0;
}


TRACEPOINT_PROBE(syscalls, sys_enter_sendmmsg)
{
    int tid = gettid();
    if (tid == SELF) return 0;
    int z=0;
    u32 pid = bpf_get_current_pid_tgid();
    struct per_syscall *s = per_syscall.lookup(&z);
    if (s != NULL) {
        __bpf_ring_buffer_submit(s, 0);
        {
            struct log_key dup_key = {};
            dup_key.pid = pid;
            dup_key.syscall = 29;
            if (filter_duplicate(&dup_key, bpf_ktime_get_ns()))
                goto sendmmsg_enter_out;
        }
        if (__bpf_enter_init2(s, 29, pid, (long)args->fd) < 0)
            goto sendmmsg_enter_out;
        if (__bpf_crypto_fixed2(s, pid, 29, (long)args->fd) < 0)
            goto sendmmsg_enter_out;
    }
sendmmsg_enter_out:
    return 0;
}


TRACEPOINT_PROBE(syscalls, sys_enter_pwrite64)
{
    int tid = gettid();
    if (tid == SELF) return 0;
    int z=0;
    u32 pid = bpf_get_current_pid_tgid();
    struct per_syscall *s = per_syscall.lookup(&z);
    if (s != NULL) {
        __bpf_ring_buffer_submit(s, 0);
        {
            struct log_key dup_key = {};
            dup_key.pid = pid;
            dup_key.syscall = 30;
            if (filter_duplicate(&dup_key, bpf_ktime_get_ns()))
                goto pwrite64_enter_out;
        }
        if (__bpf_enter_init2(s, 30, pid, (long)args->fd) < 0)
            goto pwrite64_enter_out;
        if (__bpf_crypto_fixed2(s, pid, 30, (long)args->fd) < 0)
            goto pwrite64_enter_out;
    }
pwrite64_enter_out:
    return 0;
}


TRACEPOINT_PROBE(syscalls, sys_enter_pwritev)
{
    int tid = gettid();
    if (tid == SELF) return 0;
    int z=0;
    u32 pid = bpf_get_current_pid_tgid();
    struct per_syscall *s = per_syscall.lookup(&z);
    if (s != NULL) {
        __bpf_ring_buffer_submit(s, 0);
        {
            struct log_key dup_key = {};
            dup_key.pid = pid;
            dup_key.syscall = 31;
            if (filter_duplicate(&dup_key, bpf_ktime_get_ns()))
                goto pwritev_enter_out;
        }
        if (__bpf_enter_init2(s, 31, pid, (long)args->fd) < 0)
            goto pwritev_enter_out;
        if (__bpf_crypto_fixed2(s, pid, 31, (long)args->fd) < 0)
            goto pwritev_enter_out;
    }
pwritev_enter_out:
    return 0;
}


TRACEPOINT_PROBE(syscalls, sys_enter_pwritev2)
{
    int tid = gettid();
    if (tid == SELF) return 0;
    int z=0;
    u32 pid = bpf_get_current_pid_tgid();
    struct per_syscall *s = per_syscall.lookup(&z);
    if (s != NULL) {
        __bpf_ring_buffer_submit(s, 0);
        {
            struct log_key dup_key = {};
            dup_key.pid = pid;
            dup_key.syscall = 32;
            if (filter_duplicate(&dup_key, bpf_ktime_get_ns()))
                goto pwritev2_enter_out;
        }
        if (__bpf_enter_init2(s, 32, pid, (long)args->fd) < 0)
            goto pwritev2_enter_out;
        if (__bpf_crypto_fixed2(s, pid, 32, (long)args->fd) < 0)
            goto pwritev2_enter_out;
    }
pwritev2_enter_out:
    return 0;
}


TRACEPOINT_PROBE(syscalls, sys_enter_sendto)
{
    int z=0;
    u32 pid = bpf_get_current_pid_tgid();
    struct per_syscall *s = per_syscall.lookup(&z);
    if (s != NULL) {
        __bpf_ring_buffer_submit(s, 0);
        {
            struct log_key dup_key = {};
            dup_key.pid = pid;
            dup_key.syscall = 33;
            if (filter_duplicate(&dup_key, bpf_ktime_get_ns()))
                goto sendto_enter_out;
        }
        if (__bpf_enter_init4(s, 33, pid, (long)args->addr, (long)args->addr_len, (long)args->fd) < 0)
            goto sendto_enter_out;
        if (__bpf_crypto_fixed4(s, pid, 33, (long)args->addr, (long)args->addr_len, (long)args->fd) < 0)
            goto sendto_enter_out;
    }
sendto_enter_out:
    return 0;
}


TRACEPOINT_PROBE(syscalls, sys_enter_mprotect)
{
    int mmap_imp = (args->prot & PROT_EXEC);
    if (!mmap_imp) return 0;
    int z=0;
    u32 pid = bpf_get_current_pid_tgid();
    long prot = args->prot;
    prot = (((prot & PROT_READ) !=0) << 2) |
           (((prot & PROT_WRITE)!=0) << 1) |
           ((prot & PROT_EXEC) !=0);
    struct per_syscall *s = per_syscall.lookup(&z);
    if (s != NULL) {
        __bpf_ring_buffer_submit(s, 0);
        {
            struct log_key dup_key = {};
            dup_key.pid = pid;
            dup_key.syscall = 34;
            if (filter_duplicate(&dup_key, bpf_ktime_get_ns()))
                goto mprotect_enter_out;
        }
        if (__bpf_enter_init4(s, 34, pid, (long)args->start, (long)args->len, prot) < 0)
            goto mprotect_enter_out;
        if (__bpf_crypto_fixed4(s, pid, 34, (long)args->start, (long)args->len, prot) < 0)
            goto mprotect_enter_out;
    }
mprotect_enter_out:
    return 0;
}


TRACEPOINT_PROBE(syscalls, sys_enter_mmap)
{
    int file_backed = ((args->fd >= 0) && !(args->flags & MAP_ANONYMOUS));
    int exec_perm = (args->prot & PROT_EXEC);
    int mmap_imp = file_backed || exec_perm;
    if (!mmap_imp) return 0;
    int z=0;
    u32 pid = bpf_get_current_pid_tgid();
    struct per_syscall *s = per_syscall.lookup(&z);
    long prot = args->prot;
    prot = (((prot & PROT_READ) !=0) << 2) |
           (((prot & PROT_WRITE)!=0) << 1) |
           ((prot & PROT_EXEC) !=0);
    long flags = args->flags;
    flags = (flags << 32) | prot;
    if (s != NULL) {
        __bpf_ring_buffer_submit(s, 0);
        {
            struct log_key dup_key = {};
            dup_key.pid = pid;
            dup_key.syscall = 35;
            if (filter_duplicate(&dup_key, bpf_ktime_get_ns()))
                goto mmap_enter_out;
        }
        if (__bpf_enter_init4(s, 35, pid, (long)args->addr, (long)args->fd-1, flags) < 0)
            goto mmap_enter_out;
        if (__bpf_crypto_fixed4(s, pid, 35, (long)args->addr, (long)args->fd-1, flags) < 0)
            goto mmap_enter_out;
    }
mmap_enter_out:
    return 0;
}


TRACEPOINT_PROBE(syscalls, sys_enter_unlink)
{
    int tid = gettid();
    if (tid == SELF) return 0;
    int z=0;
    unsigned int tmp;
    u32 pid = bpf_get_current_pid_tgid();
    struct per_syscall *s = per_syscall.lookup(&z);
    if (s != NULL) {
        __bpf_ring_buffer_submit(s, 0);
        {
            struct log_key dup_key = {};
            dup_key.pid = pid;
            dup_key.syscall = 36;
            long r = bpf_probe_read_user_str(dup_key.args, sizeof(dup_key.args), (const char *)args->pathname);
            if (r < 0) {
                dup_key.args[0] = '\0';
            }
            if (filter_duplicate(&dup_key, bpf_ktime_get_ns()))
                goto unlink_enter_out;
        }
        if (__bpf_enter_init(s, 36, pid) < 0)
            goto unlink_enter_out;
        if (__bpf_crypto_fixed(s, pid, 36) < 0)
            goto unlink_enter_out;
        if (__bpf_read_comm_str(s, (const char *)args->pathname) < 0)
            goto unlink_enter_end;
unlink_enter_end:
        bpf_probe_read(&tmp, 4, &s->fdx);
        if ((SYS_END_S & 0xff) == SYS_END_S && tmp < FULL_FLEX - 1) {
            s->flex[tmp] = SYS_END_S;
            s->fdx += 1;
        }
    }
unlink_enter_out:
    return 0;
}


TRACEPOINT_PROBE(syscalls, sys_enter_unlinkat)
{
    int tid = gettid();
    if (tid == SELF) return 0;
    int z=0;
    unsigned int tmp;
    u32 pid = bpf_get_current_pid_tgid();
    struct per_syscall *s = per_syscall.lookup(&z);
    if (s != NULL) {
        __bpf_ring_buffer_submit(s, 0);
        {
            struct log_key dup_key = {};
            dup_key.pid = pid;
            dup_key.syscall = 37;
            long r = bpf_probe_read_user_str(dup_key.args, sizeof(dup_key.args), (const char *)args->pathname);
            if (r < 0) {
                dup_key.args[0] = '\0';
            }
            if (filter_duplicate(&dup_key, bpf_ktime_get_ns()))
                goto unlinkat_enter_out;
        }
        if (__bpf_enter_init(s, 37, pid) < 0)
            goto unlinkat_enter_out;
        if (__bpf_crypto_fixed(s, pid, 37) < 0)
            goto unlinkat_enter_out;
        if (__bpf_read_comm_str(s, (const char *)args->pathname) < 0)
            goto unlinkat_enter_end;
unlinkat_enter_end:
        bpf_probe_read(&tmp, 4, &s->fdx);
        if ((SYS_END_S & 0xff) == SYS_END_S && tmp < FULL_FLEX - 1) {
            s->flex[tmp] = SYS_END_S;
            s->fdx += 1;
        }
    }
unlinkat_enter_out:
    return 0;
}


TRACEPOINT_PROBE(syscalls, sys_enter_mkdir)
{
    int tid = gettid();
    if (tid == SELF) return 0;
    int z=0;
    unsigned int tmp;
    u32 pid = bpf_get_current_pid_tgid();
    struct per_syscall *s = per_syscall.lookup(&z);
    if (s != NULL) {
        __bpf_ring_buffer_submit(s, 0);
        {
            struct log_key dup_key = {};
            dup_key.pid = pid;
            dup_key.syscall = 38;
            long r = bpf_probe_read_user_str(dup_key.args, sizeof(dup_key.args), (const char *)args->pathname);
            if (r < 0) {
                dup_key.args[0] = '\0';
            }
            if (filter_duplicate(&dup_key, bpf_ktime_get_ns()))
                goto mkdir_enter_out;
        }
        if (__bpf_enter_init(s, 38, pid) < 0)
            goto mkdir_enter_out;
        if (__bpf_crypto_fixed(s, pid, 38) < 0)
            goto mkdir_enter_out;
        if (__bpf_read_comm_str(s, (const char *)args->pathname) < 0)
            goto mkdir_enter_end;
mkdir_enter_end:
        bpf_probe_read(&tmp, 4, &s->fdx);
        if ((SYS_END_S & 0xff) == SYS_END_S && tmp < FULL_FLEX - 1) {
            s->flex[tmp] = SYS_END_S;
            s->fdx += 1;
        }
    }
mkdir_enter_out:
    return 0;
}


TRACEPOINT_PROBE(syscalls, sys_enter_mkdirat)
{
    int tid = gettid();
    if (tid == SELF) return 0;
    int z=0;
    unsigned int tmp;
    u32 pid = bpf_get_current_pid_tgid();
    struct per_syscall *s = per_syscall.lookup(&z);
    if (s != NULL) {
        __bpf_ring_buffer_submit(s, 0);
        {
            struct log_key dup_key = {};
            dup_key.pid = pid;
            dup_key.syscall = 39;
            long r = bpf_probe_read_user_str(dup_key.args, sizeof(dup_key.args), (const char *)args->pathname);
            if (r < 0) {
                dup_key.args[0] = '\0';
            }
            if (filter_duplicate(&dup_key, bpf_ktime_get_ns()))
                goto mkdirat_enter_out;
        }
        if (__bpf_enter_init(s, 39, pid) < 0)
            goto mkdirat_enter_out;
        if (__bpf_crypto_fixed(s, pid, 39) < 0)
            goto mkdirat_enter_out;
        if (__bpf_read_comm_str(s, (const char *)args->pathname) < 0)
            goto mkdirat_enter_end;
mkdirat_enter_end:
        bpf_probe_read(&tmp, 4, &s->fdx);
        if ((SYS_END_S & 0xff) == SYS_END_S && tmp < FULL_FLEX - 1) {
            s->flex[tmp] = SYS_END_S;
            s->fdx += 1;
        }
    }
mkdirat_enter_out:
    return 0;
}


TRACEPOINT_PROBE(syscalls, sys_enter_rmdir)
{
    int tid = gettid();
    if (tid == SELF) return 0;
    int z=0;
    unsigned int tmp;
    u32 pid = bpf_get_current_pid_tgid();
    struct per_syscall *s = per_syscall.lookup(&z);
    if (s != NULL) {
        __bpf_ring_buffer_submit(s, 0);
        {
            struct log_key dup_key = {};
            dup_key.pid = pid;
            dup_key.syscall = 40;
            long r = bpf_probe_read_user_str(dup_key.args, sizeof(dup_key.args), (const char *)args->pathname);
            if (r < 0) {
                dup_key.args[0] = '\0';
            }
            if (filter_duplicate(&dup_key, bpf_ktime_get_ns()))
                goto rmdir_enter_out;
        }
        if (__bpf_enter_init(s, 40, pid) < 0)
            goto rmdir_enter_out;
        if (__bpf_crypto_fixed(s, pid, 40) < 0)
            goto rmdir_enter_out;
        if (__bpf_read_comm_str(s, (const char *)args->pathname) < 0)
            goto rmdir_enter_end;
rmdir_enter_end:
        bpf_probe_read(&tmp, 4, &s->fdx);
        if ((SYS_END_S & 0xff) == SYS_END_S && tmp < FULL_FLEX - 1) {
            s->flex[tmp] = SYS_END_S;
            s->fdx += 1;
        }
    }
rmdir_enter_out:
    return 0;
}


TRACEPOINT_PROBE(syscalls, sys_enter_chdir)
{
    int tid = gettid();
    if (tid == SELF) return 0;
    int z=0;
    unsigned int tmp;
    u32 pid = bpf_get_current_pid_tgid();
    struct per_syscall *s = per_syscall.lookup(&z);
    if (s != NULL) {
        __bpf_ring_buffer_submit(s, 0);
        {
            struct log_key dup_key = {};
            dup_key.pid = pid;
            dup_key.syscall = 41;
            long r = bpf_probe_read_user_str(dup_key.args, sizeof(dup_key.args), (const char *)args->filename);
            if (r < 0) {
                dup_key.args[0] = '\0';
            }
            if (filter_duplicate(&dup_key, bpf_ktime_get_ns()))
                goto chdir_enter_out;
        }
        if (__bpf_enter_init(s, 41, pid) < 0)
            goto chdir_enter_out;
        if (__bpf_crypto_fixed(s, pid, 41) < 0)
            goto chdir_enter_out;
        if (__bpf_read_comm_str(s, (const char *)args->filename) < 0)
            goto chdir_enter_end;
chdir_enter_end:
        bpf_probe_read(&tmp, 4, &s->fdx);
        if ((SYS_END_S & 0xff) == SYS_END_S && tmp < FULL_FLEX - 1) {
            s->flex[tmp] = SYS_END_S;
            s->fdx += 1;
        }
    }
chdir_enter_out:
    return 0;
}


TRACEPOINT_PROBE(syscalls, sys_enter_fchdir)
{
    int tid = gettid();
    if (tid == SELF) return 0;
    int z=0;
    u32 pid = bpf_get_current_pid_tgid();
    struct per_syscall *s = per_syscall.lookup(&z);
    if (s != NULL) {
        __bpf_ring_buffer_submit(s, 0);
        {
            struct log_key dup_key = {};
            dup_key.pid = pid;
            dup_key.syscall = 42;
            if (filter_duplicate(&dup_key, bpf_ktime_get_ns()))
                goto fchdir_enter_out;
        }
        if (__bpf_enter_init2(s, 42, pid, (long)args->fd) < 0)
            goto fchdir_enter_out;
        if (__bpf_crypto_fixed2(s, pid, 42, (long)args->fd) < 0)
            goto fchdir_enter_out;
    }
fchdir_enter_out:
    return 0;
}


TRACEPOINT_PROBE(syscalls, sys_enter_mknod)
{
    int tid = gettid();
    if (tid == SELF) return 0;
    int z=0;
    unsigned int tmp;
    u32 pid = bpf_get_current_pid_tgid();
    struct per_syscall *s = per_syscall.lookup(&z);
    if (s != NULL) {
        __bpf_ring_buffer_submit(s, 0);
        {
            struct log_key dup_key = {};
            dup_key.pid = pid;
            dup_key.syscall = 43;
            long r = bpf_probe_read_user_str(dup_key.args, sizeof(dup_key.args), (const char *)args->filename);
            if (r < 0) {
                dup_key.args[0] = '\0';
            }
            if (filter_duplicate(&dup_key, bpf_ktime_get_ns()))
                goto mknod_enter_out;
        }
        if (__bpf_enter_init(s, 43, pid) < 0)
            goto mknod_enter_out;
        if (__bpf_crypto_fixed(s, pid, 43) < 0)
            goto mknod_enter_out;
        if (__bpf_read_comm_str(s, (const char *)args->filename) < 0)
            goto mknod_enter_end;
mknod_enter_end:
        bpf_probe_read(&tmp, 4, &s->fdx);
        if ((SYS_END_S & 0xff) == SYS_END_S && tmp < FULL_FLEX - 1) {
            s->flex[tmp] = SYS_END_S;
            s->fdx += 1;
        }
    }
mknod_enter_out:
    return 0;
}


TRACEPOINT_PROBE(syscalls, sys_enter_mknodat)
{
    int tid = gettid();
    if (tid == SELF) return 0;
    int z=0;
    unsigned int tmp;
    u32 pid = bpf_get_current_pid_tgid();
    struct per_syscall *s = per_syscall.lookup(&z);
    if (s != NULL) {
        __bpf_ring_buffer_submit(s, 0);
        {
            struct log_key dup_key = {};
            dup_key.pid = pid;
            dup_key.syscall = 44;
            long r = bpf_probe_read_user_str(dup_key.args, sizeof(dup_key.args), (const char *)args->filename);
            if (r < 0) {
                dup_key.args[0] = '\0';
            }
            if (filter_duplicate(&dup_key, bpf_ktime_get_ns()))
                goto mknodat_enter_out;
        }
        if (__bpf_enter_init(s, 44, pid) < 0)
            goto mknodat_enter_out;
        if (__bpf_crypto_fixed(s, pid, 44) < 0)
            goto mknodat_enter_out;
        if (__bpf_read_comm_str(s, (const char *)args->filename) < 0)
            goto mknodat_enter_end;
mknodat_enter_end:
        bpf_probe_read(&tmp, 4, &s->fdx);
        if ((SYS_END_S & 0xff) == SYS_END_S && tmp < FULL_FLEX - 1) {
            s->flex[tmp] = SYS_END_S;
            s->fdx += 1;
        }
    }
mknodat_enter_out:
    return 0;
}


TRACEPOINT_PROBE(syscalls, sys_enter_tee)
{
    int z=0;
    u32 pid = bpf_get_current_pid_tgid();
    struct per_syscall *s = per_syscall.lookup(&z);
    if (s != NULL) {
        __bpf_ring_buffer_submit(s, 0);
        {
            struct log_key dup_key = {};
            dup_key.pid = pid;
            dup_key.syscall = 45;
            if (filter_duplicate(&dup_key, bpf_ktime_get_ns()))
                goto tee_enter_out;
        }
        if (__bpf_enter_init4(s, 45, pid, (long)args->fdin, (long)args->fdout, (long)args->len) < 0)
            goto tee_enter_out;
        if (__bpf_crypto_fixed4(s, pid, 45, (long)args->fdin, (long)args->fdout, (long)args->len) < 0)
            goto tee_enter_out;
    }
tee_enter_out:
    return 0;
}


TRACEPOINT_PROBE(syscalls, sys_enter_splice)
{
    int z=0;
    u32 pid = bpf_get_current_pid_tgid();
    struct per_syscall *s = per_syscall.lookup(&z);
    if (s != NULL) {
        __bpf_ring_buffer_submit(s, 0);
        {
            struct log_key dup_key = {};
            dup_key.pid = pid;
            dup_key.syscall = 46;
            if (filter_duplicate(&dup_key, bpf_ktime_get_ns()))
                goto splice_enter_out;
        }
        if (__bpf_enter_init4(s, 46, pid, (long)args->fd_in, (long)args->fd_out, (long)args->len) < 0)
            goto splice_enter_out;
        if (__bpf_crypto_fixed4(s, pid, 46, (long)args->fd_in, (long)args->fd_out, (long)args->len) < 0)
            goto splice_enter_out;
    }
splice_enter_out:
    return 0;
}


TRACEPOINT_PROBE(syscalls, sys_enter_vmsplice)
{
    int z=0;
    u32 pid = bpf_get_current_pid_tgid();
    struct per_syscall *s = per_syscall.lookup(&z);
    if (s != NULL) {
        __bpf_ring_buffer_submit(s, 0);
        {
            struct log_key dup_key = {};
            dup_key.pid = pid;
            dup_key.syscall = 47;
            if (filter_duplicate(&dup_key, bpf_ktime_get_ns()))
                goto vmsplice_enter_out;
        }
        if (__bpf_enter_init2(s, 47, pid, (long)args->fd) < 0)
            goto vmsplice_enter_out;
        if (__bpf_crypto_fixed2(s, pid, 47, (long)args->fd) < 0)
            goto vmsplice_enter_out;
    }
vmsplice_enter_out:
    return 0;
}


TRACEPOINT_PROBE(syscalls, sys_enter_kill)
{
    int z=0;
    u32 pid = bpf_get_current_pid_tgid();
    struct per_syscall *s = per_syscall.lookup(&z);
    if (s != NULL) {
        __bpf_ring_buffer_submit(s, 0);
        {
            struct log_key dup_key = {};
            dup_key.pid = pid;
            dup_key.syscall = 48;
            if (filter_duplicate(&dup_key, bpf_ktime_get_ns()))
                goto kill_enter_out;
        }
        if (__bpf_enter_init2(s, 48, pid, ((args->pid)<<32)|(args->pid)) < 0)
            goto kill_enter_out;
        if (__bpf_crypto_fixed2(s, pid, 48, ((args->pid)<<32)|(args->pid)) < 0)
            goto kill_enter_out;
    }
kill_enter_out:
    return 0;
}


TRACEPOINT_PROBE(syscalls, sys_enter_tgkill)
{
    int z=0;
    u32 pid = bpf_get_current_pid_tgid();
    struct per_syscall *s = per_syscall.lookup(&z);
    if (s != NULL) {
        __bpf_ring_buffer_submit(s, 0);
        {
            struct log_key dup_key = {};
            dup_key.pid = pid;
            dup_key.syscall = 49;
            if (filter_duplicate(&dup_key, bpf_ktime_get_ns()))
                goto tgkill_enter_out;
        }
        if (__bpf_enter_init2(s, 49, pid, ((args->tgid)<<32)|args->pid) < 0)
            goto tgkill_enter_out;
        if (__bpf_crypto_fixed2(s, pid, 49, ((args->tgid)<<32)|args->pid) < 0)
            goto tgkill_enter_out;
    }
tgkill_enter_out:
    return 0;
}


TRACEPOINT_PROBE(syscalls, sys_enter_ptrace)
{
    int z=0;
    u32 pid = bpf_get_current_pid_tgid();
    struct per_syscall *s = per_syscall.lookup(&z);
    if (s != NULL) {
        __bpf_ring_buffer_submit(s, 0);
        {
            struct log_key dup_key = {};
            dup_key.pid = pid;
            dup_key.syscall = 50;
            if (filter_duplicate(&dup_key, bpf_ktime_get_ns()))
                goto ptrace_enter_out;
        }
        if (__bpf_enter_init4(s, 50, pid, (long)args->request, (long)args->pid, 0) < 0)
            goto ptrace_enter_out;
        if (__bpf_crypto_fixed4(s, pid, 50, (long)args->request, (long)args->pid, 0) < 0)
            goto ptrace_enter_out;
    }
ptrace_enter_out:
    return 0;
}


TRACEPOINT_PROBE(syscalls, sys_enter_chmod)
{
    int tid = gettid();
    if (tid == SELF) return 0;
    int z=0;
    unsigned int tmp;
    u32 pid = bpf_get_current_pid_tgid();
    struct per_syscall *s = per_syscall.lookup(&z);
    if (s != NULL) {
        __bpf_ring_buffer_submit(s, 0);
        {
            struct log_key dup_key = {};
            dup_key.pid = pid;
            dup_key.syscall = 51;
            long r = bpf_probe_read_user_str(dup_key.args, sizeof(dup_key.args), (const char *)args->filename);
            if (r < 0) {
                dup_key.args[0] = '\0';
            }
            if (filter_duplicate(&dup_key, bpf_ktime_get_ns()))
                goto chmod_enter_out;
        }
        if (__bpf_enter_init(s, 51, pid) < 0)
            goto chmod_enter_out;
        if (__bpf_crypto_fixed(s, pid, 51) < 0)
            goto chmod_enter_out;
        if (__bpf_read_comm_str(s, (const char *)args->filename) < 0)
            goto chmod_enter_end;
chmod_enter_end:
        bpf_probe_read(&tmp, 4, &s->fdx);
        if ((SYS_END_S & 0xff) == SYS_END_S && tmp < FULL_FLEX - 1) {
            s->flex[tmp] = SYS_END_S;
            s->fdx += 1;
        }
    }
chmod_enter_out:
    return 0;
}


TRACEPOINT_PROBE(syscalls, sys_enter_fchmod)
{
    int z=0;
    u32 pid = bpf_get_current_pid_tgid();
    struct per_syscall *s = per_syscall.lookup(&z);
    if (s != NULL) {
        __bpf_ring_buffer_submit(s, 0);
        {
            struct log_key dup_key = {};
            dup_key.pid = pid;
            dup_key.syscall = 52;
            if (filter_duplicate(&dup_key, bpf_ktime_get_ns()))
                goto fchmod_enter_out;
        }
        if (__bpf_enter_init2(s, 52, pid, (long)args->fd) < 0)
            goto fchmod_enter_out;
        if (__bpf_crypto_fixed2(s, pid, 52, (long)args->fd) < 0)
            goto fchmod_enter_out;
    }
fchmod_enter_out:
    return 0;
}


TRACEPOINT_PROBE(syscalls, sys_enter_fchmodat)
{
    int tid = gettid();
    if (tid == SELF) return 0;
    int z=0;
    unsigned int tmp;
    u32 pid = bpf_get_current_pid_tgid();
    struct per_syscall *s = per_syscall.lookup(&z);
    if (s != NULL) {
        __bpf_ring_buffer_submit(s, 0);
        {
            struct log_key dup_key = {};
            dup_key.pid = pid;
            dup_key.syscall = 53;
            long r = bpf_probe_read_user_str(dup_key.args, sizeof(dup_key.args), (const char *)args->filename);
            if (r < 0) {
                dup_key.args[0] = '\0';
            }
            if (filter_duplicate(&dup_key, bpf_ktime_get_ns()))
                goto fchmodat_enter_out;
        }
        if (__bpf_enter_init(s, 53, pid) < 0)
            goto fchmodat_enter_out;
        if (__bpf_crypto_fixed(s, pid, 53) < 0)
            goto fchmodat_enter_out;
        if (__bpf_read_comm_str(s, (const char *)args->filename) < 0)
            goto fchmodat_enter_end;
fchmodat_enter_end:
        bpf_probe_read(&tmp, 4, &s->fdx);
        if ((SYS_END_S & 0xff) == SYS_END_S && tmp < FULL_FLEX - 1) {
            s->flex[tmp] = SYS_END_S;
            s->fdx += 1;
        }
    }
fchmodat_enter_out:
    return 0;
}


TRACEPOINT_PROBE(syscalls, sys_enter_setresuid)
{
    int z=0;
    u32 pid = bpf_get_current_pid_tgid();
    struct per_syscall *s = per_syscall.lookup(&z);
    if (s != NULL) {
        __bpf_ring_buffer_submit(s, 0);
        {
            struct log_key dup_key = {};
            dup_key.pid = pid;
            dup_key.syscall = 54;
            if (filter_duplicate(&dup_key, bpf_ktime_get_ns()))
                goto setresuid_enter_out;
        }
        if (__bpf_enter_init4(s, 54, pid, (long)args->ruid, (long)args->euid, (long)args->suid) < 0)
            goto setresuid_enter_out;
        if (__bpf_crypto_fixed4(s, pid, 54, (long)args->ruid, (long)args->euid, (long)args->suid) < 0)
            goto setresuid_enter_out;
    }
setresuid_enter_out:
    return 0;
}


TRACEPOINT_PROBE(syscalls, sys_enter_setuid)
{
    int z=0;
    u32 pid = bpf_get_current_pid_tgid();
    struct per_syscall *s = per_syscall.lookup(&z);
    if (s != NULL) {
        __bpf_ring_buffer_submit(s, 0);
        {
            struct log_key dup_key = {};
            dup_key.pid = pid;
            dup_key.syscall = 55;
            if (filter_duplicate(&dup_key, bpf_ktime_get_ns()))
                goto setuid_enter_out;
        }
        if (__bpf_enter_init4(s, 55, pid, -1, (long)args->uid, -1) < 0)
            goto setuid_enter_out;
        if (__bpf_crypto_fixed4(s, pid, 55, -1, (long)args->uid, -1) < 0)
            goto setuid_enter_out;
    }
setuid_enter_out:
    return 0;
}


TRACEPOINT_PROBE(syscalls, sys_enter_setresgid)
{
    int z=0;
    u32 pid = bpf_get_current_pid_tgid();
    struct per_syscall *s = per_syscall.lookup(&z);
    if (s != NULL) {
        __bpf_ring_buffer_submit(s, 0);
        {
            struct log_key dup_key = {};
            dup_key.pid = pid;
            dup_key.syscall = 56;
            if (filter_duplicate(&dup_key, bpf_ktime_get_ns()))
                goto setresgid_enter_out;
        }
        if (__bpf_enter_init4(s, 56, pid, (long)args->rgid, (long)args->egid, (long)args->sgid) < 0)
            goto setresgid_enter_out;
        if (__bpf_crypto_fixed4(s, pid, 56, (long)args->rgid, (long)args->egid, (long)args->sgid) < 0)
            goto setresgid_enter_out;
    }
setresgid_enter_out:
    return 0;
}


TRACEPOINT_PROBE(syscalls, sys_enter_setregid)
{
    int z=0;
    u32 pid = bpf_get_current_pid_tgid();
    struct per_syscall *s = per_syscall.lookup(&z);
    if (s != NULL) {
        __bpf_ring_buffer_submit(s, 0);
        {
            struct log_key dup_key = {};
            dup_key.pid = pid;
            dup_key.syscall = 57;
            if (filter_duplicate(&dup_key, bpf_ktime_get_ns()))
                goto setregid_enter_out;
        }
        if (__bpf_enter_init4(s, 57, pid, (long)args->rgid, (long)args->egid, -1) < 0)
            goto setregid_enter_out;
        if (__bpf_crypto_fixed4(s, pid, 57, (long)args->rgid, (long)args->egid, -1) < 0)
            goto setregid_enter_out;
    }
setregid_enter_out:
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_setgid)
{
    int z=0;
    u32 pid = bpf_get_current_pid_tgid();
    struct per_syscall *s = per_syscall.lookup(&z);
    if (s != NULL) {
        __bpf_ring_buffer_submit(s, 0);
        {
            struct log_key dup_key = {};
            dup_key.pid = pid;
            dup_key.syscall = 58;
            if (filter_duplicate(&dup_key, bpf_ktime_get_ns()))
                goto setgid_enter_out;
        }
        if (__bpf_enter_init4(s, 58, pid, -1, (long)args->gid, -1) < 0)
            goto setgid_enter_out;
        if (__bpf_crypto_fixed4(s, pid, 58, -1, (long)args->gid, -1) < 0)
            goto setgid_enter_out;
    }
setgid_enter_out:
    return 0;
}


TRACEPOINT_PROBE(syscalls, sys_enter_setfsgid)
{
    int z=0;
    u32 pid = bpf_get_current_pid_tgid();
    struct per_syscall *s = per_syscall.lookup(&z);
    if (s != NULL) {
        __bpf_ring_buffer_submit(s, 0);
        {
            struct log_key dup_key = {};
            dup_key.pid = pid;
            dup_key.syscall = 59;
            if (filter_duplicate(&dup_key, bpf_ktime_get_ns()))
                goto setfsgid_enter_out;
        }
        if (__bpf_enter_init4(s, 59, pid, -1, (long)args->gid, -1) < 0)
            goto setfsgid_enter_out;
        if (__bpf_crypto_fixed4(s, pid, 59, -1, (long)args->gid, -1) < 0)
            goto setfsgid_enter_out;
    }
setfsgid_enter_out:
    return 0;
}


TRACEPOINT_PROBE(syscalls, sys_enter_setfsuid)
{
    int z=0;
    u32 pid = bpf_get_current_pid_tgid();
    struct per_syscall *s = per_syscall.lookup(&z);
    if (s != NULL) {
        __bpf_ring_buffer_submit(s, 0);
        {
            struct log_key dup_key = {};
            dup_key.pid = pid;
            dup_key.syscall = 60;
            if (filter_duplicate(&dup_key, bpf_ktime_get_ns()))
                goto setfsuid_enter_out;
        }
        if (__bpf_enter_init4(s, 60, pid, -1, (long)args->uid, -1) < 0)
            goto setfsuid_enter_out;
        if (__bpf_crypto_fixed4(s, pid, 60, -1, (long)args->uid, -1) < 0)
            goto setfsuid_enter_out;
    }
setfsuid_enter_out:
    return 0;
}


TRACEPOINT_PROBE(syscalls, sys_enter_fork)
{
    int tid = gettid();
    if (tid == SELF) return 0;
    int z=0;
    u32 pid = bpf_get_current_pid_tgid();
    struct per_syscall *s = per_syscall.lookup(&z);
    if (s != NULL) {
        __bpf_ring_buffer_submit(s, 0);
        {
            struct log_key dup_key = {};
            dup_key.pid = pid;
            dup_key.syscall = 61;
            if (filter_duplicate(&dup_key, bpf_ktime_get_ns()))
                goto fork_enter_out;
        }
        if (__bpf_enter_init(s, 61, pid) < 0)
            goto fork_enter_out;
        if (__bpf_crypto_fixed(s, pid, 61) < 0)
            goto fork_enter_out;
    }
fork_enter_out:
    return 0;
}


TRACEPOINT_PROBE(syscalls, sys_enter_vfork)
{
    int tid = gettid();
    if (tid == SELF) return 0;
    int z=0;
    u32 pid = bpf_get_current_pid_tgid();
    struct per_syscall *s = per_syscall.lookup(&z);
    if (s != NULL) {
        __bpf_ring_buffer_submit(s, 0);
        {
            struct log_key dup_key = {};
            dup_key.pid = pid;
            dup_key.syscall = 62;
            if (filter_duplicate(&dup_key, bpf_ktime_get_ns()))
                goto vfork_enter_out;
        }
        if (__bpf_enter_init(s, 62, pid) < 0)
            goto vfork_enter_out;
        if (__bpf_crypto_fixed(s, pid, 62) < 0)
            goto vfork_enter_out;
    }
vfork_enter_out:
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_clone)
{
    int z=0;
    u32 pid = bpf_get_current_pid_tgid();
    struct per_syscall *s = per_syscall.lookup(&z);
    if (s != NULL) {
        __bpf_ring_buffer_submit(s, 0);
        {
            struct log_key dup_key = {};
            dup_key.pid = pid;
            dup_key.syscall = 63;
            if (filter_duplicate(&dup_key, bpf_ktime_get_ns()))
                goto clone_enter_out;
        }
        if (__bpf_enter_init2(s, 63, pid, (long)args->clone_flags) < 0)
            goto clone_enter_out;
        if (__bpf_crypto_fixed2(s, pid, 63, (long)args->clone_flags) < 0)
            goto clone_enter_out;
    }
clone_enter_out:
    return 0;
}


TRACEPOINT_PROBE(syscalls, sys_enter_clone3)
{
    int z=0;
    u32 pid = bpf_get_current_pid_tgid();
    struct per_syscall *s = per_syscall.lookup(&z);
    if (s != NULL) {
        __bpf_ring_buffer_submit(s, 0);
        {
            struct log_key dup_key = {};
            dup_key.pid = pid;
            dup_key.syscall = 64;
            if (filter_duplicate(&dup_key, bpf_ktime_get_ns()))
                goto clone3_enter_out;
        }
        if (__bpf_enter_init2(s, 64, pid, (long)args->uargs) < 0)
            goto clone3_enter_out;
        if (__bpf_crypto_fixed2(s, pid, 64, (long)args->uargs) < 0)
            goto clone3_enter_out;
    }
clone3_enter_out:
    return 0;
}


TRACEPOINT_PROBE(syscalls, sys_enter_exit)
{
    int z=0;
    u32 pid = bpf_get_current_pid_tgid();
    struct per_syscall *s = per_syscall.lookup(&z);
    if (s != NULL) {
        __bpf_ring_buffer_submit(s, 0);
        {
            struct log_key dup_key = {};
            dup_key.pid = pid;
            dup_key.syscall = 65;
            if (filter_duplicate(&dup_key, bpf_ktime_get_ns()))
                goto exit_enter_out;
        }
        if (__bpf_enter_init2(s, 65, pid, (long)args->error_code) < 0)
            goto exit_enter_out;
        if (__bpf_crypto_fixed2(s, pid, 65, (long)args->error_code) < 0)
            goto exit_enter_out;
    }
exit_enter_out:
    return 0;
}


TRACEPOINT_PROBE(syscalls, sys_enter_exit_group)
{
    int z=0;
    u32 pid = bpf_get_current_pid_tgid();
    struct per_syscall *s = per_syscall.lookup(&z);
    if (s != NULL) {
        __bpf_ring_buffer_submit(s, 0);
        {
            struct log_key dup_key = {};
            dup_key.pid = pid;
            dup_key.syscall = 66;
            if (filter_duplicate(&dup_key, bpf_ktime_get_ns()))
                goto exit_group_enter_out;
        }
        if (__bpf_enter_init2(s, 66, pid, (long)args->error_code) < 0)
            goto exit_group_enter_out;
        if (__bpf_crypto_fixed2(s, pid, 66, (long)args->error_code) < 0)
            goto exit_group_enter_out;
    }
exit_group_enter_out:
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_execveat)
{
    const char **argv = (const char **)(args->argv);
    const char **env = (const char **)(args->envp);
    int z=0;
    u32 pid = bpf_get_current_pid_tgid();
    struct per_syscall *s = per_syscall.lookup(&z);
    if (s != NULL) {
        __bpf_ring_buffer_submit(s, 0);
        {
            struct log_key dup_key = {};
            dup_key.pid = pid;
            dup_key.syscall = 67;
            long r = bpf_probe_read_user_str(dup_key.args, sizeof(dup_key.args), (const char *)args->filename);
            if (r < 0) {
                dup_key.args[0] = '\0';
            }
            if (filter_duplicate(&dup_key, bpf_ktime_get_ns()))
                goto out2;
        }
        if (__bpf_enter_init(s, 67, pid) < 0)
            goto out2;
        if (__bpf_crypto_fixed(s, pid, 67) < 0)
            goto out2;
        if (__bpf_read_comm_str(s, (const char *)args->filename) < 0)
            goto out2;
#pragma unroll
        for (int i = 0; i < TOTAL_MAX_FLEX / 2; i++) {
            if (__bpf_split_str(s) > 0 || __bpf_read_arg_str(s, (const char *)argv[i]) < 0)
                goto arg_end2;
        }
arg_end2:
        if ((SYS_END_S & 0xff) == SYS_END_S && s->fdx < FULL_FLEX - 1)
            s->flex[s->fdx++] = SYS_END_S;
        else
            goto out2;
    }
out2:
    return 0;
}

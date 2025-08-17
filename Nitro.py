#!/usr/bin/env python3
from bcc import BPF
import sys, os, argparse, time, multiprocessing, csv, signal
from Decoder import *


def parse_arguments():
    p = argparse.ArgumentParser()
    p.add_argument("-f", "--full-fixed-len", type=int, default=3000)
    p.add_argument("-x", "--full-flex", type=int, default=8000)
    p.add_argument("-z", "--flexsize", type=int, default=32)
    p.add_argument("-t", "--total-max-flex", type=int, default=100)
    p.add_argument("-c", "--commsize", type=int, default=64)
    p.add_argument("-r", "--ring-size", type=int, default=64)
    p.add_argument("-g", "--gap", type=int, default=10**9)
    p.add_argument("-s", "--sgap", type=int, default=2*(10**8))
    p.add_argument("-o", "--output-file", type=str, default="./log.txt")
    p.add_argument("--record-loss", action="store_true")
    p.add_argument("--loss-csv", type=str, default="./data_loss.csv")
    p.add_argument("--benchmark", type=str, default="benchmark")
    return p.parse_args()


args = parse_arguments()

def execute_command(arg):
    print("Process ID finished:", os.getpid())

    
def callback(ctx, data, size):
    e = bpf['events'].event(data)

    # We choose runtime decoding to provide users with immediately interpretable output. Alternatively, the system can emit raw data and defer decoding to further improve performance.
    output(log_decoder(e.ts, size, e.flex, e.fixed, e.tag, e.idx, e.fdx, e.counter), args.output_file)


def _is_power_of_two(n:int) -> bool:
    return n > 0 and (n & (n - 1)) == 0


def _sum_map_values(t):
    return sum(int(v.value) for _, v in t.items())

def compute_data_loss():
    lt, tt = 0, 0
    try:
        lt = _sum_map_values(bpf.get_table("loss_bytes"))
        print(bpf.get_table("loss_bytes")[0])
    except: pass
    try: tt = _sum_map_values(bpf.get_table("total_bytes"))
    except: pass
    if tt > 0: return (lt / float(tt) * 100.0, True)
    return (float(lt), False)

def append_loss_csv(path, bench, val, has_ratio):
    h = ["benchmarks", "data loss"]
    nh = True
    if os.path.exists(path):
        try:
            with open(path, "r", newline="") as f:
                if next(csv.reader(f), None) == h: nh = False
        except: pass
    with open(path, "a", newline="") as f:
        w = csv.writer(f)
        if nh: w.writerow(h)
        w.writerow([bench, f"{val:.6f}"])


if not (1 <= args.ring_size <= 64 and _is_power_of_two(args.ring_size)):
    print("error: -r/--ring-size must be a power of 2 in the range [1, 64] (MB).", file=sys.stderr)
    sys.exit(2)

BPF_SOURCE_CODE = open('Nitro.c', 'rb').read().decode()
supp = "#define SELF %d\n#define FULL_FIXED_LEN %d\n#define FULL_FLEX %d\n#define FLEXSIZE %d\n#define TOTAL_MAX_FLEX %d\n#define COMMSIZE %d\n#define GAP %d\n#define SGAP %d\n#define RSIZE %d\n" % (
os.getpid(), args.full_fixed_len, args.full_flex, args.flexsize, args.total_max_flex, args.commsize, args.gap,
args.sgap, args.ring_size * 256)
supp += BPF_SOURCE_CODE
bpf = BPF(text=supp)
bpf['events'].open_ring_buffer(callback)


for _sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
    signal.signal(_sig, lambda *_: (_ for _ in ()).throw(KeyboardInterrupt))


try:
    while 1: bpf.ring_buffer_poll()
except KeyboardInterrupt:
    if args.record_loss:
        v, has_ratio = compute_data_loss()
        append_loss_csv(args.loss_csv, args.benchmark, v, has_ratio)
    os.system("echo 'LOG SYSTEM EXIT'")
    num_cpus = multiprocessing.cpu_count()
    with multiprocessing.Pool(num_cpus) as pool:
        pool.map(execute_command, range(num_cpus))
    time.sleep(1); bpf.ring_buffer_poll(); time.sleep(1); bpf.ring_buffer_poll()
    sys.exit()

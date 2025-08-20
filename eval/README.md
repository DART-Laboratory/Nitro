# Evaluation Benchmarks README

### Please install **Nitro** using the [guidelines here](https://github.com/DART-Laboratory/Nitro/blob/main/README.md) before running the benchmarks below.

This directory includes the benchmarks used in the paper, environment setup, and helper scripts, plus guidance to reproduce the results in the paper and to use Nitro/Nitro-R on additional benchmarks and metrics.

## Install

First, make the `prepare.sh` script executable and run it:

```bash
chmod +x prepare.sh
./prepare.sh
```
The `prepare.sh` script performs the following tasks:

- **Grant execute permissions** to all scripts in the current directory whose names contain `run`.
- **Install dependencies** (`nginx` and `httperf`) using `apt`, enable and start the `nginx` service, and copy the `httperf/contents` directory to the web server root (`/var/www/html`).
- **Download and prepare the Linux kernel source**:
  - Fetch `linux-6.5-rc7.tar.gz` from the official Linux kernel repository.
  - Extract it and rename the directory to `kernel`.
  - Remove the original tarball after extraction.

After these steps, your environment will be ready for running the benchmarks and tests.

## Benchmarks and Metrics

### Stress-test Benchmarks

1. `bmrun`: Script to initiate the execution of an individual benchmark.
2. `bmrunall`: Master script to run all benchmarks collectively.
3. `run_find`: Script to execute the `find` benchmark.
4. `run_httperf`: Script to perform the `httperf` benchmark.
5. `run_kernelbuild`: Script to carry out the kernel compilation benchmark.
6. `run_pm`: Script for running the PostMark benchmark.
7. `run_rdwr`: Script to execute the `rdwr` benchmark.
8. `run_shbm`: Script to run the `shbm` benchmark.
9. `run_tar`: Script for the `tar` benchmark.
10. `lmbench`: Consists of `filec` and `filed` benchmarks, which are part of the lmbench series of OS benchmarks.

#### Important Notes

- Ensure that the directories `./postmark`, `./rdwr`, `./httperf`, and the scripts `run_pm`, `bmrun`, and `bmrunall` are all contained within the same directory.
- Our stress-test benchmarks, with the exception of lmbench, originate from eaudit. The eaudit repository can be accessed at: [eaudit GitHub repository](https://github.com/seclab-stonybrook/eaudit).

### Real-world Benchmarks

1. **FireFox**: Tested using [Speedometer 3.0](https://browserbench.org/Speedometer3.0/). Please install FireFox before testing.
2. **Nginx**: Tested with the `ab` benchmark available at [Apache Benchmark (ab)](https://httpd.apache.org/docs/current/programs/ab.html). Ensure Nginx is installed beforehand.
3. **Redis**: Upon installing Redis, refer to the [Redis benchmarks optimization](https://redis.io/docs/latest/operate/oss_and_stack/management/optimization/benchmarks/) and conduct tests as per the standards mentioned in the paper.
4. **7zip & OpenSSL**: Tests should be conducted using the benchmarks provided by the [Phoronix Test Suite](https://www.phoronix-test-suite.com/).

### Metrics

We have two core metrics in the paper to evaluate different logging systems:

* **Runtime Overhead**

  $$
  O_{\text{runtime}}=\frac{T_{\text{total}}-T_{\text{benchmark}}}{T_{\text{benchmark}}}
  $$

  where $T_{\text{benchmark}}$ is the benchmark execution time without the system, and $T_{\text{total}}$ is the benchmark execution time with the system enabled.

* **Data Loss**

  $$
  P_{\text{loss}}=\frac{D_{\text{discarded}}}{D_{\text{total}}}
  $$

  where $D_{\text{discarded}}$ is the volume of log data dropped during transmission, and $D_{\text{total}}$ is the total volume of log data.


## Running Experiments

### Quick Start

1. **Navigate to the eval directory**

* In our provided VM: `/root/Nitro/eval`
* On your own machine: `/your_path/Nitro/eval`

2. **One-click run**

   From the current directory, run: `./bmrunall your_results_name.csv`
   This script calls `bmrun` and executes all **stress-test** benchmarks sequentially, recording runtime overhead and data loss results.


3. **Results**

* `your_results_name.csv` includes timings for both the **baseline** (system off) and **Nitro / Nitro-R** (system on).

  * If you use **CPU time**, take `bm_usr + bm_sys` (**default in our paper**).
  * If you use **wall-clock time**, use `bm_time`.
  
* **Runtime Overhead**: `your_results_name.csv` reports execution times with the system on and off. Using these values to compute runtime overhead as defined in the Metrics section.

* **Data Loss**: `data_loss.csv` is automatically generated here and reports the data-loss rate for each benchmark with **Nitro/Nitro-R** enabled, as defined above.

4. **Output location**
   All generated CSV files are saved in the current `eval` directory.


## Running Custom Experiments

### Runtime Overhead

1. **Disable** Nitro/Nitro-R. Run each benchmark and record **CPU time (user + sys)** using `time` (same method as above).
2. **Enable** Nitro or Nitro-R (keep all other parameters identical). Re-run the same benchmarks and record **CPU time** again.
3. Compute overhead as defined in the **Metrics** section.

### Data Loss

Nitro/Nitro-R provides **runtime options** to record data loss. At startup, add `--record-loss`, use `--loss-csv` to **specify** the output file, and `--benchmark` to set the benchmark name. Example:

```bash
python3 Nitro.py \
  --full-fixed-len 3000 \
  --full-flex 8000 \
  --flexsize 32 \
  --ring-size 64 \
  --total-max-flex 100 \
  --commsize 64 \
  --gap 1000000000 \
  --sgap 200000000 \
  --output-file ./log.txt \
  --record-loss \
  --loss-csv ./data_loss.csv \
  --benchmark your_benchmark
```

This will **automatically** record the data loss rate during the benchmark and write it to `data_loss.csv`.

### Applicability

* **Benchmarks**: Procedures above could be applied to **any** benchmark (not limited to those reported in the paper).  
* **Metrics**: In addition to the core metrics, users can add custom metrics with minor changes. For example, using psutil to measure the memory usage:

```python
#Nitro.py
import psutil
p = psutil.Process(os.getpid())
rss_mb = p.memory_info().rss / (1024 * 1024)
print(f"[{prefix}] User RSS memory: {rss_mb:.2f} MB")
```

* For **real-world** benchmarks that are not easily scripted (e.g., Firefox Speedometer via a website), follow their official instructions but keep the same workflow:

  * Collect the **baseline** with Nitro/Nitro-R **disabled**.
  * Re-run with Nitro or Nitro-R **enabled**, add `--record-loss` to export the loss rate.
  * Aggregate results per the **Metrics** section.

**Tip:** Keep the environment and inputs for benchmarks identical across the two runs. Only toggle Nitro/Nitro-R and the measurement flags.



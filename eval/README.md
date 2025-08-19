# Evaluation Benchmarks README

### Please install **Nitro** using the [guidelines here](https://github.com/DART-Laboratory/Nitro/blob/main/README.md) before running the benchmarks below.


This directory contains all the benchmarks utilized in our research paper, providing a comprehensive suite for performance evaluation. Below you will find a detailed description of each benchmark included in this suite.

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


## Stress-test Benchmarks

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

### Important Notes

- Ensure that the directories `./postmark`, `./rdwr`, `./httperf`, and the scripts `run_pm`, `bmrun`, and `bmrunall` are all contained within the same directory.
- Our stress-test benchmarks, with the exception of lmbench, originate from eaudit. The eaudit repository can be accessed at: [eaudit GitHub repository](https://github.com/seclab-stonybrook/eaudit).

## Real-world Benchmarks

1. **FireFox**: Tested using [Speedometer 3.0](https://browserbench.org/Speedometer3.0/). Please install FireFox before testing.
2. **Nginx**: Tested with the `ab` benchmark available at [Apache Benchmark (ab)](https://httpd.apache.org/docs/current/programs/ab.html). Ensure Nginx is installed beforehand.
3. **Redis**: Upon installing Redis, refer to the [Redis benchmarks optimization](https://redis.io/docs/latest/operate/oss_and_stack/management/optimization/benchmarks/) and conduct tests as per the standards mentioned in the paper.
4. **7zip & OpenSSL**: Tests should be conducted using the benchmarks provided by the [Phoronix Test Suite](https://www.phoronix-test-suite.com/).

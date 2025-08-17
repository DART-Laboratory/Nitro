sys_map = {0: 'execve', 1: 'open', 2: 'openat', 3: 'creat', 4: 'truncate', 5: 'ftruncate', 6: 'dup', 7: 'dup2',
           8: 'dup3', 9: 'fcntl', 10: 'pipe', 11: 'socketpair', 12: 'pipe2', 13: 'socket', 14: 'accept',
           15: 'accept4', 16: 'connect', 17: 'getpeername', 18: 'read', 19: 'readv', 20: 'recvmsg', 21: 'recvmmsg',
           22: 'pread64', 23: 'preadv', 24: 'preadv2', 25: 'recvfrom', 26: 'write', 27: 'writev', 28: 'sendmsg',
           29: 'sendmmsg', 30: 'pwrite64', 31: 'pwritev', 32: 'pwritev2', 33: 'sendto', 34: 'mprotect', 35: 'mmap',
           36: 'unlink', 37: 'unlinkat', 38: 'mkdir', 39: 'mkdirat', 40: 'rmdir', 41: 'chdir', 42: 'fchdir',
           43: 'mknod', 44: 'mknodat', 45: 'tee', 46: 'splice', 47: 'vmsplice', 48: 'kill', 49: 'tgkill', 50: 'ptrace',
           51: 'chmod', 52: 'fchmod', 53: 'fchmodat', 54: 'setresuid', 55: 'setuid', 56: 'setresgid',
           57: 'setregid', 58: 'setgid', 59: 'setfsgid', 60: 'setfsuid', 61: 'fork', 62: 'vfork', 63: 'clone',
           64: 'clone3', 65: 'exit', 66: 'exit_group', 67: 'execveat'}


def log_decoder(ts, size, flex, fixed, enc, idx, fdx, counter):
    if counter == 0:
        return "\n"

    sample = """LOG_MESSAGE kernel_ts_time: {}, size: {}, syscall_num: {}, crypt_enc: {}
        """
    single_each = """SYSCALL: ({})
        PID : ({})
        """

    each = """SYSCALL: ({})
        PID : ({})
        PATH: ({})
        ARG: ({})
        """

    each_2 = """SYSCALL: ({})
        PID : ({})
        FD: ({})
        """
    each_3 = """SYSCALL: ({})
            PID : ({})
            FDS: ({})
        """

    each_4 = """SYSCALL: ({})
                PID : ({})
                OFD: ({})
        """
    each_5 = """SYSCALL: ({})
                PID : ({})
                USOCKVEC: ({})
        """
    each_6 = """SYSCALL: ({})
                PID : ({})
                FAMILY: ({})
                TYPE: ({})
                PROTOCOL: ({})
        """
    each_7 = """SYSCALL: ({})
                PID : ({})
                U_SOCKADDR: ({})
                U_ADDRLEN: ({})
                FD: ({})
        """
    each_8 = """SYSCALL: ({})
                PID : ({})
                START: ({})
                LEN: ({})
                PROT: ({})
        """
    each_9 = """SYSCALL: ({})
                PID : ({})
                ADDR: ({})
                FD: ({})
                FLAG&PROT: ({})
        """
    each_10 = """SYSCALL: ({})
                PID : ({})
                FDIN: ({})
                FDOUT: ({})
                LEN: ({})
        """
    each_11 = """SYSCALL: ({})
                PID : ({})
                KILLED_PID: ({})
        """
    each_12 = """SYSCALL: ({})
                PID : ({})
                REQUEST: ({})
                P_PID: ({})
        """
    each_13 = """SYSCALL: ({})
                PID : ({})
                RUID: ({})
                EUID: ({})
                SUID: ({})
        """
    each_14 = """SYSCALL: ({})
                PID : ({})
                RGID: ({})
                EGID: ({})
                SGID: ({})
        """
    each_15 = """SYSCALL: ({})
                PID : ({})
                FLAG: ({})
        """
    each_16 = """SYSCALL: ({})
                PID : ({})
                ERROR_CODE: ({})
        """

    pure_log = ""

    pick = 0
    flex = flex[:fdx]
    fixed = fixed[:idx]
    flex = flex.split(b'\xff')

    fixed = split_array(fixed, 0xffffffff)

    fixed_len = len(fixed)

    logging = min(counter, fixed_len)

    for i in range(logging):
        try:
            pid = fixed[i][0]
            sys_name = sys_map.get(fixed[i][1], 0)

            if fixed[i][1] in [9, 18, 19, 20, 21, 22, 23, 24, 26, 27, 28, 29, 30, 31, 32, 42, 47, 52]:
                fd = fixed[i][2]
                pure_log += each_2.format(sys_name, pid, fd)
                continue
            if fixed[i][1] in [6, 10, 12]:
                fds = fixed[i][2]
                pure_log += each_3.format(sys_name, pid, fds)
                continue
            if fixed[i][1] in [7, 8]:
                old = fixed[i][2]
                pure_log += each_4.format(sys_name, pid, old)
                continue
            if fixed[i][1] == 11:
                usockvec = fixed[i][2]
                pure_log += each_5.format(sys_name, pid, usockvec)
                continue
            if fixed[i][1] == 13:
                family = fixed[i][2]
                types = fixed[i][3]
                protocol = fixed[i][4]
                pure_log += each_6.format(sys_name, pid, family, types, protocol)
                continue
            if fixed[i][1] in [14, 15, 16, 17, 25, 33]:
                upeer_sockaddr = fixed[i][2]
                upeer_addrlen = fixed[i][3]
                fd = fixed[i][4]
                pure_log += each_7.format(sys_name, pid, upeer_sockaddr, upeer_addrlen, fd)
                continue
            if fixed[i][1] == 34:
                start = fixed[i][2]
                length = fixed[i][3]
                prot = fixed[i][4]
                pure_log += each_8.format(sys_name, pid, start, length, prot)
                continue
            if fixed[i][1] == 35:
                addr = fixed[i][2]
                fd = fixed[i][3] + 1
                fp = fixed[i][4]
                pure_log += each_9.format(sys_name, pid, addr, fd, fp)
                continue
            if fixed[i][1] in [45, 46]:
                fdin = fixed[i][2]
                fdout = fixed[i][3]
                length = fixed[i][4]
                pure_log += each_10.format(sys_name, pid, fdin, fdout, length)
                continue
            if fixed[i][1] in [48, 49]:
                k_pid = fixed[i][2]
                pure_log += each_11.format(sys_name, pid, k_pid)
                continue
            if fixed[i][1] == 50:
                req = fixed[i][2]
                p_pid = fixed[i][3]
                pure_log += each_12.format(sys_name, pid, req, p_pid)
                continue
            if fixed[i][1] in [54, 55, 60]:
                r = fixed[i][2]
                e = fixed[i][3]
                s = fixed[i][4]
                pure_log += each_13.format(sys_name, pid, r, e, s)
                continue
            if fixed[i][1] in [56, 57, 58, 59]:
                r = fixed[i][2]
                e = fixed[i][3]
                s = fixed[i][4]
                pure_log += each_14.format(sys_name, pid, r, e, s)
                continue
            if fixed[i][1] in [61, 62]:
                pure_log += single_each.format(sys_name, pid)
                continue
            if fixed[i][1] in [63, 64]:
                flag = fixed[i][2]
                pure_log += each_15.format(sys_name, pid, flag)
                continue
            if fixed[i][1] in [65, 66]:
                ec = fixed[i][2]
                pure_log += each_16.format(sys_name, pid, ec)
                continue

            if b'\xfd' not in flex[pick]:
                path = flex[pick].split(b'\xfe')[0]
                pick = min(pick + 1, len(flex)-2)
                pure_log += each.format(sys_name, pid, path, "\n")
                continue

            path = flex[pick].split(b'\xfe')[0]
            left = flex[pick].split(b'\xfe')[1]
            args = left.replace(b'\xfd', b'\n').decode()
            pick = min(pick + 1, len(flex)-2)
            pure_log += each.format(sys_name, pid, path, args).lstrip()


        except Exception as e:
            # Could calculate the format error
            # print(fixed[i])
            # print(i)
            # print(fixed)
            # print(flex)
            # print(counter)
            continue

    size = len(pure_log)
    sample = sample.format(ts, size, counter, hex(enc)).lstrip()
    sample += pure_log

    return sample


def output(unit, path):
    with open(path, 'a') as k:
        k.write(str(unit))
        k.close()


def split_array(arr, value):
    result = []
    sub_array = []
    for num in arr:
        if num == value:
            if sub_array:
                result.append(sub_array)
            sub_array = []
        else:
            sub_array.append(num)
    if sub_array:
        result.append(sub_array)

    if result and all(x == 0 for x in result[-1]):
        result.pop()

    return result

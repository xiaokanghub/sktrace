function stalkerTraceRange(tid, base, size) {
    Stalker.follow(tid, {
        transform: (iterator) => {
            const instruction = iterator.next();
            const startAddress = instruction.address;
            const isModuleCode = startAddress.compare(base) >= 0 && 
                startAddress.compare(base.add(size)) < 0;
            // const isModuleCode = true;
            do {
                iterator.keep();
                if (isModuleCode) {
                    send({
                        type: 'inst',
                        tid: tid,
                        block: startAddress,
                        val: JSON.stringify(instruction)
                    })
                    iterator.putCallout((context) => {
                            send({
                                type: 'ctx',
                                tid: tid,
                                val: JSON.stringify(context)
                            })
                    })
                }
            } while (iterator.next() !== null);
        }
    })
}


function traceAddr(addr) {
    let moduleMap = new ModuleMap();    
    let targetModule = moduleMap.find(addr);
    console.log(JSON.stringify(targetModule))
    //let exports = targetModule.enumerateExports();
    //let symbols = targetModule.enumerateSymbols();
    // send({
    //     type: "module", 
    //     targetModule
    // })
    // send({
    //     type: "sym",
    

    // })
    Interceptor.attach(addr, {
        onEnter: function(args) {
            this.tid = Process.getCurrentThreadId()
            // stalkerTraceRangeC(this.tid, targetModule.base, targetModule.size)
            stalkerTraceRange(this.tid, targetModule.base, targetModule.size)
        },
        onLeave: function(ret) {
            Stalker.unfollow(this.tid);
            Stalker.garbageCollect()
            send({
                type: "fin",
                tid: this.tid
            })
        }
    })
}


function traceSymbol(symbol) {

}

function hook_dlopen(libname, payload) {
    const dlopen_old = Module.findExportByName(null, "dlopen");
    const dlopen_new = Module.findExportByName(null, "android_dlopen_ext");
    const soName = libname;
    if (dlopen_old != null) {
        Interceptor.attach(dlopen_old, {
            onEnter: function (args) {
                var l_soName = args[0].readCString();
                console.log(l_soName);
                if (l_soName.indexOf(soName) !== -1) {
                    this.hook = true;
                }
            },
            onLeave: function (retval) {
                if (this.hook) {
                    console.warn("\nLoaded " + soName);
                    start_trace(libname, payload);
                }
            }
        })
    }

    if (dlopen_new != null) {
        Interceptor.attach(dlopen_new, {
            onEnter: function (args) {
                var l_soName = args[0].readCString();
                console.log(l_soName);
                if (l_soName.indexOf(soName) !== -1) {
                    this.hook = true;
                }
            },
            onLeave: function (retval) {
                if (this.hook) {
                    console.warn("\nLoaded " + soName);
                    start_trace(libname, payload);
                }
            }
        })
    }
}

function start_trace (libname, payload) {
    const targetModule = Process.getModuleByName(libname);
    let targetAddress = null;
    if("symbol" in payload) {
        targetAddress = targetModule.findExportByName(payload.symbol);
    } else if("offset" in payload) {
        targetAddress = targetModule.base.add(ptr(payload.offset));
    }
    console.log("func addr: ", targetAddress);
    traceAddr(targetAddress);

}


(() => {

    console.log(`----- start trace -----`);

    recv("config", (msg) => {
        const payload = msg.payload;
        console.log(JSON.stringify(payload))
        const libname = payload.libname;
        console.log(`libname:${libname}`)
        if(payload.spawn) {
            console.error(`todo: spawn inject not implemented`)
        } else {
            // const modules = Process.enumerateModules();
            //hook_dlopen(libname, payload);
            start_trace(libname, payload);
        }
    })
})()

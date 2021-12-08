
"""
A instruction trace script based on Frida-Stalker.
"""

import argparse
import binascii
import json
import os
import frida
import time

from sktracemgr import TraceMgr

__version__ = "1.0.0"

def _finish(args, device, pid, scripts):
    print('Stopping application (name={}, pid={})...'.format(
        args.target,
        pid
    ), end="")
    try:
        if args.append:
            scripts["append"].unload()
        scripts["script"].unload()
        if args.prepend:
            scripts["prepend"].unload()
        device.kill(pid)
    except frida.InvalidOperationError:
        pass
    finally:
        print("stopped.")


def _custom_script_on_message(message, data):
    print(message, data)


# def _parse_args():
#     parser = argparse.ArgumentParser(usage="sktrace [options] -l libname -i symbol|hexaddr target")
#     parser.add_argument("-m", "--inject-method", choices=["spawn", "attach"],
#                         default="spawn",
#                         help="Specify how frida should inject into the process.")
#     parser.add_argument("-l", "--libname", required=True, 
#                         help="Specify a native library like libnative-lib.so")
#     parser.add_argument("-i", "--interceptor", required=True, 
#                         help="Specity a function (symbol or a hex offset address) to trace.")
#     parser.add_argument("-p", "--prepend", type=argparse.FileType("r"),
#                         help="Prepend a Frida script to run before sktrace does.")
#     parser.add_argument("-a", "--append", type=argparse.FileType("r"),
#                         help="Append a Frida script to run after sktrace has started.")
#     parser.add_argument("-v", "--version", action='version',
#                         version="%(prog)s " + __version__,
#                         help="Show the version.")
#     parser.add_argument("target",
#                         help="The name of the application to trace.")
#     args = parser.parse_args()

#     return args



def main(libname, interceptor, process, host=False, isUsb=False, isSpawn=True):
    script_file = os.path.join(os.path.dirname(__file__), "sktrace.js")
    try:
        script = open(script_file, encoding='utf-8').read()
    except:
        raise Exception("Read script error.")

    trace_mgr = TraceMgr()

    # args = _parse_args()

    config = {
        "type": "config",
        "payload": {}
    }

    config["payload"]["libname"] = libname

    if interceptor.startswith("0x") or interceptor.startswith("0X"):
        config["payload"]["offset"] = int(interceptor, 16)
    else:
        config["payload"]["symbol"] = interceptor
    
    # device = frida.get_usb_device(1)
    # if args.inject_method == "spawn":
    #     raise Exception("working for this ...")
    #     pid = device.spawn([args.target])
    #     config["payload"]["spawn"] = True
    # else:
    #     pid = device.get_process(args.target).pid
    #     config["payload"]["spawn"] = False


    # session = device.attach(pid)
    if isUsb:
        try:
            device = frida.get_usb_device()
        except:
            device = frida.get_remote_device()
    else:
        if host:
            manager = frida.get_device_manager()
            device = manager.add_remote_device(host)
        else:
            device = frida.get_local_device()

    if isSpawn:
        pid = device.spawn([process])
        time.sleep(1)
        session = device.attach(pid)
        time.sleep(1)
        device.resume(pid)
    else:
        print("attach")
        session = device.attach(process)
    scripts = {}

    # if args.prepend:
    #     prepend = session.create_script(args.prepend.read())
    #     prepend.on("message", _custom_script_on_message)
    #     prepend.load()
    #     args.prepend.close()
    #     scripts["prepend"] = prepend

    script = session.create_script(script)
    script.on("message", trace_mgr.on_message)
    script.load()
    scripts["script"] = script

    script.post(config)

    # if args.append:
    #     append = session.create_script(args.append.read())
    #     append.on("message", _custom_script_on_message)
    #     append.load()
    #     args.append.close()
    #     scripts["append"] = append

    # if args.inject_method == "spawn":
    #     device.resume(pid)

    print("Tracing. Press any key to quit...")

    try:
        input()
    except KeyboardInterrupt:
        pass

    # _finish(args, device, pid, scripts)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(usage="sktrace [options] -l libname -i symbol|hexaddr target")
    # parser.add_argument("-m", "--inject-method", choices=["spawn", "attach"],
    #                     default="spawn",
    #                     help="Specify how frida should inject into the process.")
    parser.add_argument("-host", '-H', metavar="<192.168.1.1:27042>", required=False,
                      help="connect to remote frida-server on HOST")
    parser.add_argument("--isUsb", "-U", default=False, action="store_true",
                      help="connect to USB device")
    parser.add_argument("--isSpawn", "-f", default=False, action="store_true",
                      help="if spawned app")
    parser.add_argument("-l", "--libname", required=True, 
                        help="Specify a native library like libnative-lib.so")
    parser.add_argument("-i", "--interceptor", required=True, 
                        help="Specity a function (symbol or a hex offset address) to trace.")
    parser.add_argument("-p", "--prepend", type=argparse.FileType("r"),
                        help="Prepend a Frida script to run before sktrace does.")
    parser.add_argument("-a", "--append", type=argparse.FileType("r"),
                        help="Append a Frida script to run after sktrace has started.")
    parser.add_argument("-v", "--version", action='version',
                        version="%(prog)s " + __version__,
                        help="Show the version.")
    parser.add_argument("target",
                        help="The name of the application to trace.")
    parsed = parser.parse_args()
    main(
        parsed.libname,
        parsed.interceptor,
        int(parsed.target) if parsed.target.isdigit() else parsed.target,
        parsed.host,
        isUsb=parsed.isUsb, 
        isSpawn=parsed.isSpawn,
        
        )

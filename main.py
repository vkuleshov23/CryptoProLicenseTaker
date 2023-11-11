import sys
import argparse
import re
import subprocess
import winreg
import time


KEY_50 = 'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Installer\\UserData\\S-1-5-18\\Products\\08F19F05793DC7340B8C2621D83E5BE5\\InstallProperties'
KEY_39 = 'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Installer\\UserData\\S-1-5-18\\Products\\7AB5E7046046FB044ACD63458B5F481C\\InstallProperties'
KEY_40 = 'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Installer\\UserData\\S-1-5-18\\Products\\68A52D936E5ACF24C9F8FE4A1C830BC8\\InstallProperties'
TEST_KEY = 'SOFTWARE\\ODBC\\ODBCINST.INI\\SQL Server'
KEYS = [KEY_50, KEY_39, KEY_40]
ROUTER_HOST = '*.*.*.*'
MASK_LEN = "24"
CODE = "cp866"
RIGHT_OS_TYPE = "windows"

# RIGHT_OS_TYPE = "linux"
# RIGHT_OS_TYPE = "espressif"

def createParser():
    global ROUTER_HOST, MASK_LEN, RIGHT_OS_TYPE, CODE
    parser = argparse.ArgumentParser()
    parser.add_argument('--host-ip', action='store', dest='router_host')
    parser.add_argument('--mask', action='store', dest='mask_length', default="24")
    parser.add_argument('--os-type', action='store', dest='os_type', default="windows")
    parser.add_argument('--code', action='store', dest='code', default="cp866")
    results = parser.parse_args()
    ROUTER_HOST = results.router_host
    MASK_LEN = results.mask_length
    RIGHT_OS_TYPE = results.os_type
    CODE = results.code
    return results


def nmap_ip_scan(router_host: str, mask_len: str) -> list:
    data = subprocess.run(['nmap', '-sn', router_host + "/" + mask_len], stdout=subprocess.PIPE)
    decode_data = data.stdout.decode(CODE)
    ip_addresses = re.findall(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', decode_data)
    ip_addresses.remove(router_host)
    print("All addresses:")
    print(ip_addresses)
    return ip_addresses


def get_right_ip(ip_addresses: list, right_os: str) -> list:
    right_ip = filter_by_os(ip_addresses, right_os)
    print("Suitable addresses:")
    print(right_ip)
    return right_ip


def filter_by_os(ip_addresses: list, right_os: str) -> list:
    right_ip = []
    for ip in ip_addresses:
        data = subprocess.run(['nmap', '-sS', '-O', ip], stdout=subprocess.PIPE)
        decode_data = data.stdout.decode(CODE).split('\n')
        print(ip, "is OS scan now: ", end='')
        is_right = is_right_os(decode_data, right_os)
        print("+" if is_right else "-")
        if is_right:
            name_exist, name = is_name_exist(decode_data)
            if name_exist:
                right_ip.append((ip, name))
    return right_ip


def is_right_os(decode_data: list, right_os: str) -> bool:
    for line in decode_data:
        if re.match(r'Aggressive OS guesses:', line) or re.match(r'OS details:', line) or re.match(r'OS', line):
            if re.search(right_os, line, re.IGNORECASE):
                return True
    return False


def is_name_exist(decode_data: list):
    for line in decode_data:
        if re.match(r'Nmap scan report for ', line):
            is_found, name = get_host_name(line)
            return is_found, name
    return False, None


def get_host_name(line: str):
    line = line.replace('Nmap scan report for ', '')
    splited_data = line.split(' ')
    if len(splited_data) == 2:
        name = splited_data[0]
        return True, name
    else:
        return False, None


def read_register_key(host_name, key, subkey):
    aReg = winreg.ConnectRegistry(host_name, winreg.HKEY_LOCAL_MACHINE)
    try:
        reg_key = winreg.OpenKey(aReg, key)
        ex = winreg.QueryValueEx(reg_key, subkey)
        print(ex[0])
    except FileNotFoundError:
        return

def main():
    scanned_ip_addresses = nmap_ip_scan(ROUTER_HOST, MASK_LEN)
    ip_adrs = get_right_ip(scanned_ip_addresses, RIGHT_OS_TYPE)
    for ip in ip_adrs:
        for key in KEYS :
            read_register_key(ip[0], key, 'ProductID')


if __name__ == '__main__':
    start_time = time.time()
    print(createParser())
    main()
    end_time = time.time()
    print("The full scan time lasted", round(end_time - start_time), "seconds")
import subprocess
import xml.etree.ElementTree as ET
from EasyMenu3 import easymenu
import psutil
import socket
import ipaddress
from pick import pick
from rich.progress import track
import sys
from datetime import datetime
import csv
from scan_history import build_snapshot, save_snapshot, compare_saved_scans


timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

#Custom Exceptions
class InvalidHostInput(Exception):
    pass
class HostExistsError(Exception):
    pass
class EmptyListError(Exception):
    pass

#app.start()

class Service:
    def __init__(self,port=None,protocol=None,state=None,name=None,product=None,version=None,extrainfo=None):
        self.port = port
        self.protocol = protocol
        self.state = state
        self.name = name
        self.product = product
        self.version = version
        self.extrainfo = extrainfo

class Interface:
    def __init__(self,name,address,netmask,CIDR):
        self.name = name
        self.address = address
        self.netmask = netmask
        self.CIDR= CIDR

class Host:
    def __init__(self,addresses,status,hostname,services):
        self.addresses = addresses
        self.status = status
        self.hostname = hostname
        self.services = services

class Address:
    def __init__(self, address, addr_type, vendor=None):
        self.address = address
        self.addr_type = addr_type
        self.vendor = vendor




### Nmap Command:
### -sT: TCP connect scan
### -sS: TCP SYN scan (requires raw-packet privileges)
### -Pn: Skip host discovery
### -oX -: output XML
### target at the end.


def interface_select():


    interface_list = []
    interfaces = psutil.net_if_addrs()
    for name,addresses in interfaces.items():
        for addr in addresses:
            if addr.family == socket.AF_INET:
                CIDR = ipaddress.ip_interface(f"{addr.address}/{addr.netmask}")
                CIDR = CIDR.network
                interface_obj = Interface(name,addr.address,addr.netmask,CIDR)
                interface_list.append(interface_obj)

    if not interface_list:
        print("No IPv4 interfaces found. Returning to main menu.")
        return None

    options = [f"{item.name}: {item.address}" for item in interface_list]

    option, index = pick(options, title="Select an Interface")

    selected_interface = interface_list[index]

    print(f"Interface {selected_interface.name} selected")
    print(f"Interface: {selected_interface.name}")
    print(f"Address: {selected_interface.address}")
    print(f"Subnet Mask: {selected_interface.netmask}")
    print(f"CIDR Notation: {selected_interface.CIDR}")

    return selected_interface



def host_collection(selected_interface):
    targets=[]
    options=["Automatic Scan","Manual Scan"]
    title = "Please choose an option: "
    option, index = pick(options,title)
    if option.lower() == 'manual scan':
        while True:
            try:
                count_input = input("Enter how many hosts to scan (1-254, or 'exit'): ").strip()
                if count_input.lower() == 'exit':
                    print("Returning to main menu.")
                    return []
                u_range = int(count_input)
                if u_range < 1 or u_range > 254:
                    raise InvalidHostInput

                for c in range(1, u_range + 1):
                    user_input = input(f"Enter IPv4 host #{c} (or 'exit'): ").strip()
                    if user_input.lower() == 'exit':
                        print("Target list cleared. Returning to main menu.")
                        return []
                    valid_ip = ipaddress.ip_address(user_input)
                    if valid_ip.version != 4:
                        raise ValueError("IPv4 addresses only")
                    if str(valid_ip) in targets:
                        raise HostExistsError
                    targets.append(str(valid_ip))

                return targets
            except InvalidHostInput:
                print("Host count must be between 1 and 254.")
            except ValueError:
                targets.clear()
                print("Target list cleared. Enter a valid count and IPv4 addresses only. Try again.")
            except HostExistsError:
                targets.clear()
                print("Target list cleared, duplicate found. Try again.")

    elif option.lower()=='automatic scan':
        try:
            autoscan_host = subprocess.run(["nmap","-sn","-oX","-",str(selected_interface.CIDR)],
                            capture_output=True,
                            text=True,
                            check=True)
        except FileNotFoundError:
            print("Error encountered: Check if nmap is installed correctly on your device")
            print("Cancelling all operations...")
            sys.exit(1)
        except subprocess.CalledProcessError as e:
            print(f"Nmap failed: {e.stderr}")
            sys.exit(1)
        try:
            root = ET.fromstring(autoscan_host.stdout)
        except ET.ParseError:
            print("Error: Invalid/Incomplete XML (C:NMAP)\n Exiting...")
            sys.exit(1)


        
        host_elements = root.findall(".//host")

        for host in track(host_elements, description="Discovering Hosts..."):
            address_elements = host.findall("address")

            for address in address_elements:
                if address.get("addrtype") == "ipv4":
                    ip = address.get("addr")

                    if ip is not None:
                        targets.append(ip)
                        break

        if not targets:
            print("No hosts discovered. Returning to main menu.")
            return []

        selected_hosts = pick(
            targets,
            title="Select IP addresses to keep (Space to select, Enter to confirm):",
            multiselect=True,
            min_selection_count=1,
        )
        return [ip for ip, index in selected_hosts]


def syn_tcp_check():
    scan_type = ""
    options =['TCP Connect scan','TCP SYN scan (requires raw-packet privileges)']
    option, index = pick(options,title="Select scan type: ")
    if index==0:
        scan_type = "tcp"
        return scan_type
    elif index==1:
        scan_type = "stealth"
        return scan_type



def scanning(targets,scan_type):
    try:
        results = []
        options=["Fast scan","Standard Scan","Detailed Service Scan","Back to main menu"]
        option, index = pick(options,title="Choose scan mode:")
        method = "TCP SYN" if scan_type == "stealth" else "TCP connect"
        scan_mode = f"{option} ({method})"
        if index==0 and scan_type=='tcp':
            for x in track(targets, description="Scanning..."):
                result = subprocess.run(["nmap","-sT","-Pn","-F","-n","-oX","-",x],
                                        capture_output=True,
                                        text=True,
                                        check=True)
                results.append(result.stdout)
            return results, scan_mode
        elif index==1 and scan_type=='tcp':
            for x in track(targets, description="Scanning..."):
                result = subprocess.run(["nmap","-sT","-Pn","-oX","-",x],
                                        capture_output=True,
                                        text=True,
                                        check=True)
                results.append(result.stdout)
            return results, scan_mode
        elif index==2 and scan_type=='tcp':
            for x in track(targets,description="Scanning..."):
                result=subprocess.run(["nmap","-sT","-Pn","-sV","-n","-oX","-",x],
                                    capture_output=True,
                                    text=True,
                                    check=True)
                results.append(result.stdout)
            return results, scan_mode
        elif index==0 and scan_type=='stealth':
            for x in track(targets, description="Scanning..."):
                result=subprocess.run(["nmap","-sS","-Pn","-F","-n","-oX","-",x],
                                      capture_output=True,
                                      text=True,
                                      check=True)
                results.append(result.stdout)
            return results,scan_mode
        elif index==1 and scan_type=='stealth':
            for x in track(targets, description="Scanning..."):
                result=subprocess.run(["nmap","-sS","-Pn","-oX","-",x],
                                      capture_output=True,
                                      text=True,
                                      check=True)
                results.append(result.stdout)
            return results,scan_mode
        elif index==2 and scan_type=='stealth':
            for x in track(targets,description="Scanning..."):
                result=subprocess.run(["nmap","-sS","-Pn","-sV","-n","-oX","-",x],
                                      capture_output=True,
                                      text=True,
                                      check=True)
                results.append(result.stdout)
            return results,scan_mode
        elif index==3:
            print("Returning to main menu.")
            return None
    except FileNotFoundError:
        print("Error encountered: Check if nmap is installed correctly on your device")
        print("Cancelling all operations...")
        return sys.exit(1)
    except subprocess.CalledProcessError as e:
        print(f"Nmap failed: {e.stderr}")
        if scan_type == "stealth":
            print("TCP SYN scanning requires raw-packet privileges. Check elevated permissions and, on Windows, your Npcap installation.")
            print("TCP connect scanning is available from the scan-method menu. No fallback scan was run.")
        return None

### Parsing begins here

def element_parsing(results):
    host_result= []
    for x in results:
        try:
            root = ET.fromstring(x)
        except ET.ParseError:
            print("Error: Invalid/Incomplete XML (C:NMAP)\nExiting...") 
            sys.exit(1)

        host_element = root.findall(".//host")
        
        if not host_element:
            print("No host information found...")
            continue # Continues processing with no host info

        host_result.extend(host_element)

    hosts = []
    for host in track(host_result,description="Gathering elements..."):
        services = []
        addresses = []
        status_element = host.find("status")
        if status_element is None:
            print("No status information found...")
            continue
        hostname_element = host.find(".//hostname")
        address_elements = host.findall("address")

        status = status_element.get("state")
        if hostname_element is not None:
            hostname = hostname_element.get("name")
        else:
            hostname = None

        for address in address_elements:
            
            if address.get("addrtype")=="ipv4":
                ipv4 = address.get("addr")
                address_obj = Address(ipv4,address.get("addrtype"),vendor=None)

            elif address.get("addrtype")=="ipv6":
                ipv6=address.get("addr")
                address_obj=Address(ipv6,address.get("addrtype"),vendor=None)

            elif address.get("addrtype")=="mac":

                macaddress=address.get("addr")
                if address.get("vendor") is not None:
                    vendor=address.get("vendor")
                    address_obj=Address(macaddress,address.get("addrtype"),vendor)

                else:
                    vendor=None
                    address_obj=Address(macaddress,address.get("addrtype"),vendor=None)

            addresses.append(address_obj)

        ports = host.findall(".//port")

        for port in track(ports, description="Probing..."):
            port_id = port.get("portid")

            if port_id is None:
                continue

            try:
                port_num = int(port_id)
            except ValueError:
                continue
            state = port.find("state")
            service = port.find("service")

            s_method = service.get("method") if service is not None else None

            if s_method == "probed":
                service_obj = Service(
                    port=port_num,
                    protocol=port.get("protocol"),
                    state=state.get("state") if state is not None else None,
                    name=service.get("name"),
                    product=service.get("product"),
                    version=service.get("version"),
                    extrainfo=service.get("extrainfo"))
            elif s_method == "table":
                service_obj = Service(
                    port=port_num,
                    protocol=port.get("protocol"),
                    state=state.get("state") if state is not None else None,
                    name=service.get("name"),
                    product=None,
                    version=None,
                    extrainfo=None)
            else:
                service_obj = Service(
                    port=port_num,
                    protocol=port.get("protocol"),
                    state=state.get("state") if state is not None else None,
                    name=service.get("name") if service is not None else None,
                    product=None,
                    version=None,
                    extrainfo=None)

            services.append(service_obj)

        host_obj = Host(addresses,status,hostname,services)

        hosts.append(host_obj)
    return hosts




def export_txt(hosts, selected_interface, scan_mode):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"Rastro_Report_{timestamp}.txt"

    try:
        with open(filename, "w", encoding="utf-8") as file:
            file.write("=" * 40 + "\n")
            file.write("RASTRO NETWORK REPORT\n")
            file.write("=" * 40 + "\n\n")

            file.write(f"Scan Mode: {scan_mode}\n")
            file.write(f"Interface: {selected_interface.name}\n")
            file.write(f"Network: {selected_interface.CIDR}\n")
            file.write(f"Hosts Reported: {len(hosts)}\n")

            for i, host in enumerate(hosts, start=1):
                file.write("\n" + "=" * 40 + "\n")
                file.write(f"HOST #{i}\n")
                file.write("=" * 40 + "\n")

                file.write(f"Status: {host.status}\n")
                file.write(f"Hostname: {host.hostname or 'Unknown'}\n")

                for address in host.addresses:
                    file.write(
                        f"{address.addr_type}: {address.address}\n"
                    )

                    if address.vendor:
                        file.write(f"Vendor: {address.vendor}\n")

                file.write("\nSERVICES:\n")

                if not host.services:
                    file.write("No services reported.\n")

                for service in host.services:
                    file.write(
                        f"\nPort: {service.port}/{service.protocol}\n"
                    )
                    file.write(f"State: {service.state or 'Unknown'}\n")
                    file.write(f"Service: {service.name or 'Unknown'}\n")

                    if service.product is not None:
                        file.write(f"Product: {service.product}\n")

                    if service.version is not None:
                        file.write(f"Version: {service.version}\n")

                    if service.extrainfo is not None:
                        file.write(f"Extra Info: {service.extrainfo}\n")

            file.write("\n" + "=" * 40 + "\n")
            file.write("END OF REPORT\n")
            file.write("=" * 40 + "\n")

        print(f"TXT report successfully saved: {filename}")

    except OSError as e:
        print(f"Failed to export TXT report: {e}")


def export_csv(hosts, selected_interface, scan_mode):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"Rastro_Report_{timestamp}.csv"

    try:
        with open(filename, "w", newline="", encoding="utf-8") as file:
            writer = csv.writer(file)

            # CSV column headers
            writer.writerow([
                "Scan Mode",
                "Interface",
                "Network",
                "Host Status",
                "Hostname",
                "Addresses",
                "Port",
                "Protocol",
                "Port State",
                "Service",
                "Product",
                "Version",
                "Extra Info"
            ])

            for host in hosts:
                addresses = ", ".join(
                    f"{addr.addr_type}: {addr.address}"
                    for addr in host.addresses
                )

                host_info = [
                    scan_mode,
                    selected_interface.name,
                    str(selected_interface.CIDR),
                    host.status,
                    host.hostname or "Unknown",
                    addresses
                ]

                if host.services:
                    for service in host.services:
                        writer.writerow(host_info + [
                            service.port,
                            service.protocol,
                            service.state,
                            service.name,
                            service.product,
                            service.version,
                            service.extrainfo
                        ])
                else:
                    # Host exists but has no reported services
                    writer.writerow(host_info + [""] * 7)

        print(f"CSV report successfully saved: {filename}")

    except OSError as e:
        print(f"Failed to export CSV report: {e}")


def display(hosts):


    for host in hosts:
        print("\nHOST REPORT")
        print(f"Status: {host.status}")

        for address in host.addresses:
            print(f"{address.addr_type}: {address.address}")
        print("\nServices:")

        for service in host.services:
            print(f"\n{service.port}/{service.protocol}   {service.state}   {service.name or 'Unknown'}")
            if service.product is not None:
                print(f"Product: {service.product}")
            if service.version is not None:
                print(f"Version: {service.version}")
            if service.extrainfo is not None:
                print(f"Extra Info: {service.extrainfo}")

        print("-" * 50)


def run_scan():
    selected_interface = interface_select()
    if selected_interface is None:
        return

    targets_list = host_collection(selected_interface)
    if not targets_list:
        return

    scan_type = syn_tcp_check()
    scan_result = scanning(targets_list, scan_type)
    if scan_result is None:
        return
    results_list,scan_mode = scan_result

    parse = element_parsing(results_list)

    option, index = pick(
        ["TXT", "CSV", "Skip"],
        title="Export Results?"
    )

    if index == 0:
        export_txt(parse, selected_interface, scan_mode)

    elif index == 1:
        export_csv(parse, selected_interface, scan_mode)

    print(f"\nScan Mode: {scan_mode}")
    display(parse)
    if input("\nSave this scan for future comparison? (y/N): ").strip().lower() == 'y':
        try:
            snapshot = build_snapshot(parse, selected_interface, scan_mode, targets_list)
            path = save_snapshot(snapshot)
            print(f"Scan snapshot saved: {path}")
        except OSError as error:
            print(f"Unable to save snapshot: {error}")
    input("\nPress Enter to return to the main menu...")


def main():
    app = easymenu(
        name="Rastro",
        author="ZeeEm",
        url="https://www.zaidalmousawi.com",
        url_label="My Site",
        make_screen=False,
        catch_errors=False,
        quit_item=True,
    )
    app.add_menu_option("New scan", run_scan, item_key="1")
    app.add_menu_option("Compare saved scans", compare_saved_scans, item_key="2")
    app.start()


if __name__ == "__main__":
    main()

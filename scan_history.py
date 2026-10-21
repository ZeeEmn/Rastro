import ipaddress
import json
from datetime import datetime
from pathlib import Path

SNAPSHOT_DIR = Path(__file__).resolve().parent / 'snapshots'


def build_snapshot(hosts, interface, scan_mode, targets):
    observed = {}
    for host in hosts:
        for address in host.addresses:
            if address.addr_type != 'ipv4':
                continue
            services = {}
            for service in host.services:
                if service.state == 'open':
                    key = f'{service.port}/{service.protocol}'
                    services[key] = {
                        'name': service.name,
                        'product': service.product,
                        'version': service.version,
                    }
            observed[address.address] = {'status': host.status, 'services': services}
    return {
        'schema_version': 1,
        'created_at': datetime.now().astimezone().isoformat(),
        'network': str(interface.CIDR),
        'scan_mode': scan_mode,
        'targets': sorted(set(targets)),
        'hosts': observed,
    }


def save_snapshot(snapshot, directory=None):
    directory = Path(directory) if directory is not None else SNAPSHOT_DIR
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"Rastro_Scan_{datetime.now():%Y%m%d_%H%M%S_%f}.json"
    with path.open('x', encoding='utf-8') as file:
        json.dump(snapshot, file, indent=2)
    return path


def load_snapshot(path):
    with Path(path).open(encoding='utf-8') as file:
        data = json.load(file)
    try:
        if data['schema_version'] != 1:
            raise ValueError('Unsupported snapshot version.')
        
        ipaddress.IPv4Network(data['network'])
        if not isinstance(data['scan_mode'], str) or not isinstance(data['created_at'], str):
            raise ValueError('Invalid scan metadata.')
        if not isinstance(data['targets'], list) or not isinstance(data['hosts'], dict):
            raise ValueError('Invalid target or host data.')
        for target in data['targets']:
            ipaddress.IPv4Address(target)
        for ip, host in data['hosts'].items():
            ipaddress.IPv4Address(ip)
            if ip not in data['targets'] or not isinstance(host['status'], str):
                raise ValueError('Invalid host data.')
            for port, service in host['services'].items():
                number, protocol = port.split('/')
                if not 1 <= int(number) <= 65535 or protocol not in ('tcp', 'udp'):
                    raise ValueError('Invalid service port.')
                for field in ('name', 'product', 'version'):
                    if service[field] is not None and not isinstance(service[field], str):
                        raise ValueError('Invalid service details.')
    except (KeyError, TypeError, AttributeError) as error:
        raise ValueError('Invalid Rastro snapshot.') from error
    return data


def scan_profile_and_method(scan_mode):
    for method in ('TCP connect', 'TCP SYN'):
        suffix = f' ({method})'
        if scan_mode.endswith(suffix):
            return scan_mode.removesuffix(suffix), method
    # Snapshots saved before method selection used TCP connect.
    return scan_mode, 'TCP connect'


def compare_snapshots(before, after):
    #Return observation changes, keeping unscanned IPs separate from absent hosts.
    if before['network'] != after['network']:
        raise ValueError('Choose scans from the same subnet.')
    before_profile, _ = scan_profile_and_method(before['scan_mode'])
    after_profile, _ = scan_profile_and_method(after['scan_mode'])
    if before_profile != after_profile:
        raise ValueError('Choose scans using the same scan profile (Fast, Standard, or Detailed Service).')
    old = {ip: host for ip, host in before['hosts'].items() if host['status'] == 'up'}
    new = {ip: host for ip, host in after['hosts'].items() if host['status'] == 'up'}
    changes = []
    for ip in sorted(new.keys() - old.keys()):
        if ip in before['targets']:
            changes.append(f'Newly observed host: {ip}')
        else:
            changes.append(f'First observation: {ip} (not scanned in baseline)')
    for ip in sorted(old.keys() - new.keys()):
        if ip in after['targets']:
            changes.append(f'Host no longer observed up: {ip}')
        else:
            changes.append(f'Not scanned this time: {ip} (presence unknown)')
    for ip in sorted(old.keys() & new.keys()):
        old_services = old[ip]['services']
        new_services = new[ip]['services']
        for port in sorted(new_services.keys() - old_services.keys()):
            changes.append(f'Newly observed open port: {ip} {port}')
        for port in sorted(old_services.keys() - new_services.keys()):
            changes.append(f'Port no longer reported open: {ip} {port}')
        for port in sorted(old_services.keys() & new_services.keys()):
            previous = old_services[port]
            current = new_services[port]
            if previous['version'] and current['version']:
                if previous['version'] != current['version']:
                    changes.append(f"Detected version changed: {ip} {port}: {previous['version']} -> {current['version']}")
            elif previous['version'] != current['version']:
                changes.append(f'Version detection changed: {ip} {port} (version unavailable in one scan)')
    return changes


def compare_saved_scans():
    files = sorted(SNAPSHOT_DIR.glob('Rastro_Scan_*.json'))
    if len(files) < 2:
        print('Save at least two scan snapshots before comparing.')
        input('Press Enter to return to the main menu...')
        return
    for number, path in enumerate(files, 1):
        print(f'{number}. {path.name}')
    try:
        first = input("Baseline scan number (or 'exit'): ").strip()
        if first.lower() == 'exit':
            return
        second = input("Later scan number (or 'exit'): ").strip()
        if second.lower() == 'exit':
            return
        first, second = int(first), int(second)
        if not (1 <= first <= len(files) and 1 <= second <= len(files)) or first >= second:
            raise ValueError('Choose a baseline followed by a different, later scan.')
        before = load_snapshot(files[first - 1])
        after = load_snapshot(files[second - 1])
        print(f"\nSCAN COMPARISON: {before['created_at']} -> {after['created_at']}")
        print('Changes describe scan observations by IP; they do not prove physical device identity.')
        changes = compare_snapshots(before, after)
        print(f"Scan modes: {before['scan_mode']} -> {after['scan_mode']}")
        _, before_method = scan_profile_and_method(before['scan_mode'])
        _, after_method = scan_profile_and_method(after['scan_mode'])
        if before_method != after_method:
            print('Different TCP methods were used; observed differences may reflect the scan method rather than a network change.')
        for change in changes:
            print(f'- {change}')
        if not changes:
            print('No changes observed within the compared scope.')
    except (OSError, ValueError, UnicodeError) as error:
        print(f'Unable to compare scans: {error}')
    input('\nPress Enter to return to the main menu...')

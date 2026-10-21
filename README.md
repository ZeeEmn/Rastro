# Rastro V0.1.1

Rastro is an interactive Python CLI built around Nmap for IPv4 host discovery and TCP service scanning. It parses Nmap XML, displays results in the terminal, and exports TXT or CSV reports.

## Requirements and setup

- Nmap installed separately, with `nmap` available on PATH. Verify with `nmap --version`.
- Python and pip. The development environment is Windows with Python 3.14.2 and Nmap 7.991 installed. Other environments have not been verified.
- An interactive terminal for the EasyMenu3 and pick menus.

From the repository directory:

```powershell
python -m venv .venv
.venv\Scripts\python -m pip install -r requirements.txt
.venv\Scripts\python main.py
```

The requirements file pins the direct dependency versions installed during verification. It is not a complete transitive dependency lockfile; installation in a fresh environment has not yet been verified.

## Usage

1. Select **New scan**, then an IPv4 interface.
2. Choose automatic discovery or manual target entry.
3. With automatic discovery, use the arrow keys to move, Space to select the IPs to keep, and Enter to confirm. Select at least one IP.
4. With manual entry, enter 1-254 IPv4 addresses. Type `exit` at the count or address prompt to cancel and return to the main menu. Invalid or duplicate input clears the current target list so you can retry.
5. Choose TCP Connect (the default menu selection) or TCP SYN. SYN requires raw-packet privileges; on Windows, check your Npcap installation and whether elevated permissions are required.
6. Choose Fast, Standard, or Detailed Service Scan, or return to the main menu.
7. Choose TXT, CSV, or Skip. Results display for every choice; press Enter afterward to return to the menu.

Reports are saved in the current working directory as `Rastro_Report_<timestamp>.txt` or `.csv`. They are excluded from Git by default.

The selected interface supplies the subnet for automatic discovery and the interface label in reports. Rastro does not bind Nmap traffic to that interface; routing is handled by the operating system and Nmap.

## Scan modes

- **Fast:** Selected TCP scan method of Nmap's fast port set, with host discovery and DNS resolution disabled.
- **Standard:** Selected TCP scan method with host discovery disabled.
- **Detailed Service:** Selected TCP scan method with service/version detection, with host discovery and DNS resolution disabled.

TCP Connect explicitly uses `-sT`; TCP SYN explicitly uses `-sS`. The chosen method appears in the terminal summary, TXT/CSV reports, and saved snapshots. A failed SYN scan displays Nmap's error and returns to the main menu without silently switching to TCP connect. SYN scanning is detectable and does not guarantee faster scans, especially against filtered ports.

## Compare scans

After viewing scan results, answer `y` to save a JSON snapshot. Snapshots are stored in the `snapshots` folder next to the application and excluded from Git.

After saving two scans, choose **Compare saved scans** from the main menu. Enter the number of the baseline scan, then a later scan. Both must use the same subnet and scan profile (Fast, Standard, or Detailed Service). TCP connect and TCP SYN snapshots can be compared with each other. Older snapshots without a method label are treated as TCP connect scans. When methods differ, the comparison displays a note because observed differences may reflect the scan method rather than a network change. Type `exit` at either prompt to cancel.

The comparison reports hosts first observed, hosts no longer observed up, newly observed open ports, ports no longer reported open, and detected service-version changes. Missing version information is reported separately from a version change.

Hosts are matched by IPv4 address, not physical identity; DHCP address changes can affect the results. An IP omitted from a scan is marked **not scanned**, not missing. To track a previously observed host's presence, include its IP explicitly in the later scan using manual target entry. Automatic discovery may omit unreachable hosts before the scan target list is created. Differences in reachability or detection do not by themselves prove a device was removed or a service was upgraded.

## Current limitations

- Scan targets are IPv4 only. This release does not offer IPv6 scanning.
- Automatic discovery uses Nmap `-sn`; discovery results depend on network conditions and available privileges.
- Rastro reports hosts and services; it does not perform vulnerability assessment.
- Missing Nmap, discovery command failures, or malformed XML currently close the application after an error message. Port-scan command failures return to the main menu.
- Automatic host selection requires at least one host; there is no dedicated cancel option in that selection screen.
- Scans have no application-level timeout or saved partial results.
- Report names have one-second timestamp resolution; repeated exports within the same second can overwrite the same format.

## License

MIT. See LICENSE.

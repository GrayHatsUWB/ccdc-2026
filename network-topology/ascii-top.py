#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Nmap ASCII Art Network Map Generator
Converts nmap XML output into visual ASCII art maps
"""

import xml.etree.ElementTree as ET
import sys
import shutil

def parse_nmap_xml(xml_file):
    """Parse nmap XML and extract host/port information"""
    tree = ET.parse(xml_file)
    root = tree.getroot()
    
    hosts = []
    for host in root.findall('host'):
        if host.find('status').get('state') != 'up':
            continue
            
        host_info = {'ip': None, 'hostname': None, 'os': None, 'ports': []}
        
        addr = host.find('address[@addrtype="ipv4"]')
        if addr is not None:
            host_info['ip'] = addr.get('addr')
        
        hostnames = host.find('hostnames')
        if hostnames is not None:
            hostname = hostnames.find('hostname')
            if hostname is not None:
                host_info['hostname'] = hostname.get('name')
        
        # Get OS information
        os_elem = host.find('os')
        if os_elem is not None:
            osmatch = os_elem.find('osmatch')
            if osmatch is not None:
                host_info['os'] = osmatch.get('name')
        
        ports = host.find('ports')
        if ports is not None:
            for port in ports.findall('port'):
                state = port.find('state')
                if state is not None and state.get('state') == 'open':
                    service = port.find('service')
                    port_info = {
                        'port': port.get('portid'),
                        'protocol': port.get('protocol'),
                        'service': service.get('name') if service is not None else 'unknown'
                    }
                    host_info['ports'].append(port_info)
        
        if host_info['ip']:
            hosts.append(host_info)
    
    return hosts

def create_ascii_map(hosts, router_ip=None):
    """Generate router-first ASCII network map with horizontal host wrapping."""
    if not hosts:
        return "No hosts found in scan results"

    def host_detail_lines(host):
        display_name = host['hostname'] if host['hostname'] else host['ip']
        lines = [display_name]

        if host['hostname']:
            lines.append("(" + host['ip'] + ")")
        else:
            lines.append("")

        os_text = "OS: " + host['os'] if host['os'] else "OS: unknown"
        lines.append(os_text)

        web_ports = [p['port'] for p in host['ports'] if p['port'] in ('80', '443')]
        web_text = "Web: " + (", ".join(web_ports) if web_ports else "none")
        lines.append(web_text)

        if host['ports']:
            for port_info in host['ports']:
                lines.append("{}/{} {}".format(
                    port_info['port'],
                    port_info['protocol'],
                    port_info['service']
                ))
        else:
            lines.append("No open ports")
        return lines

    def build_host_card(host, card_width=38):
        inner_width = card_width - 4
        lines = ["+" + "-" * (card_width - 2) + "+"]
        for text in host_detail_lines(host):
            lines.append("| " + text.ljust(inner_width) + " |")
        lines.append("+" + "-" * (card_width - 2) + "+")
        return lines

    router_host = None
    if router_ip:
        for host in hosts:
            if host['ip'] == router_ip:
                router_host = host
                break

    device_hosts = [h for h in hosts if h is not router_host]

    term_width = shutil.get_terminal_size((120, 24)).columns
    min_card_width = 38
    if device_hosts:
        max_detail_len = max(
            max(len(line) for line in host_detail_lines(host))
            for host in device_hosts
        )
        card_width = max(min_card_width, max_detail_len + 4)
    else:
        card_width = min_card_width

    gap = 4
    cols = max(1, (term_width + gap) // (card_width + gap))
    map_width = max(60, cols * card_width + (cols - 1) * gap)

    output = []
    output.append("=" * map_width)
    output.append("NETWORK MAP".center(map_width))
    output.append("=" * map_width)
    output.append("")

    total_ports = sum(len(h['ports']) for h in hosts)
    router_meta = ["Router", "IP: {}".format(router_ip) if router_ip else "IP: unknown"]
    if router_host:
        router_meta.append("OS: {}".format(router_host['os'] if router_host['os'] else "unknown"))
        router_web_ports = [p['port'] for p in router_host['ports'] if p['port'] in ('80', '443')]
        router_meta.append("Web: {}".format(", ".join(router_web_ports) if router_web_ports else "none"))
        if router_host['ports']:
            for port_info in router_host['ports']:
                router_meta.append("{}/{} {}".format(
                    port_info['port'],
                    port_info['protocol'],
                    port_info['service']
                ))
        else:
            router_meta.append("No open ports")
    else:
        router_meta.append("Hosts: {}".format(len(hosts)))
        router_meta.append("Open ports: {}".format(total_ports))

    router_inner = max(22, max(len(line) for line in router_meta) + 2)
    map_width = max(map_width, router_inner + 2)
    output[0] = "=" * map_width
    output[1] = "NETWORK MAP".center(map_width)
    output[2] = "=" * map_width
    router_border = "+" + "-" * router_inner + "+"
    router_box = [router_border]
    for line in router_meta:
        router_box.append("| " + line.center(router_inner - 2) + " |")
    router_box.append(router_border)
    for line in router_box:
        output.append(line.center(map_width))
    output.append("|".center(map_width))
    output.append("v".center(map_width))
    output.append("")

    for i in range(0, len(device_hosts), cols):
        row_hosts = device_hosts[i:i + cols]
        cards = [build_host_card(host, card_width=card_width) for host in row_hosts]
        row_height = max(len(card) for card in cards)

        for card in cards:
            border = "+" + "-" * (card_width - 2) + "+"
            while len(card) < row_height:
                card.insert(-1, "| " + "".ljust(card_width - 4) + " |")
            if not card[-1].startswith("+"):
                card[-1] = border

        row_width = len(row_hosts) * card_width + (len(row_hosts) - 1) * gap
        left_pad = max(0, (map_width - row_width) // 2)

        for line_idx in range(row_height):
            row_line = (" " * gap).join(card[line_idx] for card in cards)
            output.append(" " * left_pad + row_line)

        output.append("")

    return "\n".join(output)

def create_compact_map(hosts):
    """Generate compact side-by-side ASCII map"""
    if not hosts:
        return "No hosts found"
    
    output = []
    output.append("=" * 100)
    output.append(" " * 40 + "NETWORK MAP (COMPACT)")
    output.append("=" * 100)
    output.append("")
    
    cols = 2
    for i in range(0, len(hosts), cols):
        row_hosts = hosts[i:i+cols]
        lines = [[] for _ in range(20)]
        
        for host in row_hosts:
            display_name = host['hostname'] if host['hostname'] else host['ip']
            box_width = 45
            
            host_lines = []
            host_lines.append("+" + "-" * (box_width - 2) + "+")
            host_lines.append("| " + display_name[:box_width-4].ljust(box_width - 4) + " |")
            if host['hostname']:
                host_lines.append("| (" + host['ip'] + ")".ljust(box_width - 4) + " |")
            if host['os']:
                os_text = "OS: " + host['os']
                host_lines.append("| " + os_text[:box_width-4].ljust(box_width - 4) + " |")
            
            # Add web ports if available
            web_ports = []
            for port_info in host['ports']:
                if port_info['port'] == '80':
                    web_ports.append('Website Port 80')
                if port_info['port'] == '443':
                    web_ports.append('Website Port 443')
            
            if web_ports:
                for web_port in web_ports:
                    host_lines.append("| " + web_port[:box_width-4].ljust(box_width - 4) + " |")
            
            host_lines.append("+" + "-" * (box_width - 2) + "+")
            
            for port_info in host['ports'][:10]:
                port_line = "{}/{}: {}".format(
                    port_info['port'], 
                    port_info['protocol'], 
                    port_info['service']
                )
                host_lines.append("| " + port_line[:box_width-4].ljust(box_width - 4) + " |")
            
            if len(host['ports']) > 10:
                more_text = "... +{} more".format(len(host['ports'])-10)
                host_lines.append("| " + more_text.ljust(box_width - 4) + " |")
            
            host_lines.append("+" + "-" * (box_width - 2) + "+")
            
            for j, line in enumerate(host_lines):
                if j < len(lines):
                    lines[j].append(line)
        
        for line_parts in lines:
            if line_parts:
                output.append("  ".join(line_parts))
        
        output.append("")
    
    output.append("=" * 100)
    
    return "\n".join(output)

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 ascii-thing.py <nmap_xml_file> [router_ip] [--compact]")
        print("\nFirst run nmap with XML output and OS detection:")
        print("  sudo nmap -O -oX scan.xml <target>")
        print("\nThen generate the map:")
        print("  python3 ascii-thing.py scan.xml")
        print("  python3 ascii-thing.py scan.xml 192.168.1.1")
        print("  python3 ascii-thing.py scan.xml 192.168.1.1 --compact")
        sys.exit(1)
    
    xml_file = sys.argv[1]
    extra_args = sys.argv[2:]
    compact = '--compact' in extra_args
    positional_args = [arg for arg in extra_args if not arg.startswith('--')]
    router_ip = positional_args[0] if positional_args else None
    
    try:
        hosts = parse_nmap_xml(xml_file)
        
        if compact:
            map_output = create_compact_map(hosts)
        else:
            map_output = create_ascii_map(hosts, router_ip=router_ip)
        
        print(map_output)
        
    except FileNotFoundError:
        print("Error: File '{}' not found".format(xml_file))
        sys.exit(1)
    except ET.ParseError as e:
        print("Error parsing XML: {}".format(e))
        sys.exit(1)
    except Exception as e:
        print("Error: {}".format(e))
        sys.exit(1)

if __name__ == "__main__":
    main()

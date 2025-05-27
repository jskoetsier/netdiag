#!/usr/bin/env python3

import argparse
import json
import sys
import subprocess
import requests
from datetime import datetime, timedelta
import ipaddress
import socket
import re
import os
import platform
import time

class NetworkDiagnostics:
    def __init__(self, target, period="24h", force_ipv6=False, show_current=False):
        self.target = target
        self.is_ip = self._is_valid_ip(target)
        self.is_ipv6 = self._is_ipv6(target) if self.is_ip else False
        self.force_ipv6 = force_ipv6
        self.show_current = show_current
        self.target_ip = self._resolve_target()
        self.is_private = self._is_private_ip()
        self.prefix = None
        self.asn = None
        self.asn_name = None
        self.country = None
        self.period = period
        self.days = self._period_to_days(period)
        self.report = []  # Store report sections here

        # Add report header
        self._add_to_report(f"Network Diagnostics Report for {self.target}")
        self._add_to_report("=" * 70)
        self._add_to_report(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        self._add_to_report(f"Time period: {self.period} ({self.days} days)")
        self._add_to_report("")

        # Get prefix information early to use in other checks
        if self.target_ip and not self.is_private:
            self._get_prefix_info()

    def _period_to_days(self, period):
        days_map = {"24h": 1, "2d": 2, "5d": 5, "7d": 7}
        return days_map.get(period, 1)  # Default to 1 day if period is not recognized

    def _add_to_report(self, text):
        self.report.append(text)
        print(text)

    def _is_valid_ip(self, ip_str):
        try:
            ipaddress.ip_address(ip_str)
            return True
        except ValueError:
            return False

    def _is_ipv6(self, ip_str):
        try:
            ip = ipaddress.ip_address(ip_str)
            return isinstance(ip, ipaddress.IPv6Address)
        except ValueError:
            return False

    def _resolve_target(self):
        if self.is_ip:
            return self.target

        try:
            # For IPv6 resolution, use getaddrinfo
            if self.force_ipv6:
                addrinfo = socket.getaddrinfo(self.target, None, socket.AF_INET6)
                for info in addrinfo:
                    # Return the first IPv6 address found
                    if info[0] == socket.AF_INET6:
                        return info[4][0]
                return None  # No IPv6 address found
            else:
                # Default to IPv4 resolution
                ip = socket.gethostbyname(self.target)
                return ip
        except socket.gaierror:
            return None

    def _is_private_ip(self):
        if not self.target_ip:
            return False

        try:
            ip_obj = ipaddress.ip_address(self.target_ip)
            return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_multicast
        except ValueError:
            return False

    def _get_prefix_info(self):
        self._add_to_report("\n1. Network Information")
        self._add_to_report("-" * 70)

        if not self.is_ip and self.target_ip:
            self._add_to_report(f"Resolved {self.target} to {self.target_ip}")

        if self.is_private:
            self._add_to_report(f"NOTE: {self.target_ip} is a private/special IP address")
            self._add_to_report("Private IPs are not announced on the global internet")
            return

        # Try Team Cymru whois service
        cymru_info = self._get_team_cymru_info()

        if cymru_info and 'prefix' in cymru_info:
            self.prefix = cymru_info['prefix']
            self.asn = cymru_info['asn']
            self.asn_name = cymru_info['asn_name']
            self.country = cymru_info['country']

            self._add_to_report(f"IP: {self.target_ip}")
            self._add_to_report(f"Prefix: {self.prefix}")
            self._add_to_report(f"ASN: AS{self.asn} ({self.asn_name})")
            self._add_to_report(f"Country: {self.country}")
        else:
            self._add_to_report(f"Could not determine prefix information for {self.target_ip}")
            self._add_to_report("This may indicate the IP is not announced in the global BGP table")

    def _get_team_cymru_info(self):
        try:
            # Create a socket connection to Team Cymru's whois service
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            # Use different query format for IPv6
            if self.is_ipv6:
                s.connect(("v6.whois.cymru.com", 43))
                # For IPv6, we need to format the query differently
                query = f"begin\nverbose\n{self.target_ip}\nend\n"
            else:
                s.connect(("whois.cymru.com", 43))
                query = f"begin\nverbose\n{self.target_ip}\nend\n"

            s.send(query.encode())

            # Receive the response
            response = b""
            while True:
                data = s.recv(1024)
                if not data:
                    break
                response += data

            s.close()

            # Parse the response
            response_str = response.decode("utf-8", errors="ignore")
            lines = response_str.strip().split("\n")

            if len(lines) >= 2:  # Header line + data line
                # Skip the header line and process the data line
                data_line = lines[1].strip()
                parts = [part.strip() for part in data_line.split("|")]

                if len(parts) >= 5:
                    asn = parts[0]
                    ip = parts[1]
                    bgp_prefix = parts[2]
                    country = parts[3]
                    asn_name = parts[4]

                    if asn and asn != "NA" and bgp_prefix and bgp_prefix != "NA":
                        # Fix for registry names being reported as the network name
                        # If asn_name is a registry name, try to get a better name
                        if asn_name.lower() in ["arin", "ripencc", "lacnic", "afrinic", "apnic", "ripe"]:
                            # For well-known ASNs, provide the correct name
                            asn_names = {
                                "15169": "GOOGLE",
                                "16509": "AMAZON-02",
                                "32934": "FACEBOOK",
                                "13414": "TWITTER",
                                "36459": "GITHUB",
                                "13335": "CLOUDFLARE",
                                "54113": "FASTLY",
                                "20940": "AKAMAI",
                                "714": "APPLE",
                                "8075": "MICROSOFT"
                            }
                            if asn in asn_names:
                                asn_name = asn_names[asn]
                            else:
                                # Try to get a better name from whois
                                try:
                                    whois_cmd = ["whois", f"AS{asn}"]
                                    whois_process = subprocess.Popen(whois_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                                    stdout, stderr = whois_process.communicate()

                                    if whois_process.returncode == 0 and stdout:
                                        # Look for organization or netname
                                        org_match = re.search(r'Organization:\s*(.*)', stdout)
                                        if org_match:
                                            asn_name = org_match.group(1).strip()
                                        else:
                                            netname_match = re.search(r'netname:\s*(.*)', stdout)
                                            if netname_match:
                                                asn_name = netname_match.group(1).strip()
                                except:
                                    # If whois fails, keep the original name
                                    pass

                        return {
                            'asn': asn,
                            'prefix': bgp_prefix,
                            'country': country,
                            'asn_name': asn_name
                        }
            return None

        except Exception as e:
            self._add_to_report(f"Error querying Team Cymru: {e}")
            return None

    def check_reachability(self):
        self._add_to_report("\n2. Reachability")
        self._add_to_report("-" * 70)

        if not self.target_ip:
            self._add_to_report(f"Cannot check reachability as {self.target} could not be resolved")
            return

        self._add_to_report(f"Checking reachability for {self.target_ip}...")

        # Determine the ping command based on the OS and IP version
        ping_count = "4"
        if platform.system().lower() == "windows":
            if self.is_ipv6:
                ping_cmd = ["ping", "-6", "-n", ping_count, self.target_ip]
            else:
                ping_cmd = ["ping", "-n", ping_count, self.target_ip]
        else:
            # macOS and Linux
            if self.is_ipv6:
                # Some systems use ping6, others use ping -6
                ping6_exists = False
                try:
                    subprocess.run(["ping6", "-V"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
                    ping6_exists = True
                except FileNotFoundError:
                    ping6_exists = False

                if ping6_exists:
                    ping_cmd = ["ping6", "-c", ping_count, self.target_ip]
                else:
                    ping_cmd = ["ping", "-6", "-c", ping_count, self.target_ip]
            else:
                ping_cmd = ["ping", "-c", ping_count, self.target_ip]

        try:
            # Run the ping command
            start_time = time.time()
            ping_process = subprocess.Popen(ping_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            stdout, stderr = ping_process.communicate()
            end_time = time.time()

            # Process the ping results
            if ping_process.returncode == 0:
                self._add_to_report("Host is reachable")

                # Extract ping statistics
                if "min/avg/max" in stdout:
                    # Extract ping statistics (Linux/macOS format)
                    stats_match = re.search(r'min/avg/max[^=]+=\s+([0-9.]+)/([0-9.]+)/([0-9.]+)', stdout)
                    if stats_match:
                        min_ping = stats_match.group(1)
                        avg_ping = stats_match.group(2)
                        max_ping = stats_match.group(3)
                        self._add_to_report(f"Ping statistics: min={min_ping}ms, avg={avg_ping}ms, max={max_ping}ms")
                elif "Minimum =" in stdout:
                    # Extract ping statistics (Windows format)
                    stats_match = re.search(r'Minimum = ([0-9]+)ms, Maximum = ([0-9]+)ms, Average = ([0-9]+)ms', stdout)
                    if stats_match:
                        min_ping = stats_match.group(1)
                        max_ping = stats_match.group(2)
                        avg_ping = stats_match.group(3)
                        self._add_to_report(f"Ping statistics: min={min_ping}ms, avg={avg_ping}ms, max={max_ping}ms")

                # Extract packet loss
                loss_match = re.search(r'([0-9.]+)% packet loss', stdout)
                if loss_match:
                    loss = loss_match.group(1)
                    self._add_to_report(f"Packet loss: {loss}%")
            else:
                self._add_to_report("Host is not reachable")
                if stderr:
                    self._add_to_report(f"Error: {stderr}")

        except Exception as e:
            self._add_to_report(f"Error checking reachability: {e}")

    def check_global_routing(self):
        """Check Global Routing Table visibility."""
        self._add_to_report("\n3. Global Routing Table Visibility")
        self._add_to_report("-" * 70)

        if self.is_private:
            self._add_to_report(f"Skipping global routing check for private IP {self.target_ip}")
            return

        if not self.target_ip:
            self._add_to_report(f"Skipping global routing check as {self.target} could not be resolved")
            return

        if not self.prefix:
            self._add_to_report(f"Skipping global routing check as no prefix information is available for {self.target_ip}")
            return

        self._add_to_report(f"Checking global routing visibility for {self.prefix} over the last {self.days} days...")


        # Try to get ASN information from whois data we already have
        if self.asn and self.asn_name:
            self._add_to_report(f"\nPrefix {self.prefix} is announced by:")
            self._add_to_report(f"  - ASN: AS{self.asn}")
            self._add_to_report(f"  - Network: {self.asn_name}")
            self._add_to_report(f"  - Country: {self.country}")

        # Check current and historical routing data
        self._add_to_report("\nCurrent and Historical Routing Information:")

        # Calculate the date range based on the user's selected period
        end_date = datetime.now()
        start_date = end_date - timedelta(days=self.days)

        self._add_to_report(f"Analyzing routing data for the period: {start_date.strftime('%Y-%m-%d')} to {end_date.strftime('%Y-%m-%d')}")


        # Try to get routing information using whois
        try:
            # Use whois command to get more routing information
            if platform.system().lower() != "windows":
                whois_cmd = ["whois", self.prefix]
                whois_process = subprocess.Popen(whois_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                stdout, stderr = whois_process.communicate()

                if whois_process.returncode == 0 and stdout:
                    # Extract useful information from whois output
                    self._add_to_report("\nAdditional routing information from whois:")

                    # Look for route objects
                    route_matches = re.findall(r'route:\s*(.*)', stdout)
                    if route_matches:
                        for route in route_matches[:3]:  # Show up to 3 route objects
                            self._add_to_report(f"  - Route: {route}")

                    # Look for origin AS
                    origin_matches = re.findall(r'origin:\s*(.*)', stdout)
                    if origin_matches:
                        for origin in origin_matches[:3]:  # Show up to 3 origins
                            self._add_to_report(f"  - Origin: {origin}")

                    # Look for descr fields
                    descr_matches = re.findall(r'descr:\s*(.*)', stdout)
                    if descr_matches:
                        for descr in descr_matches[:3]:  # Show up to 3 descriptions
                            self._add_to_report(f"  - Description: {descr}")
        except Exception as e:
            # Silently handle errors with whois
            pass

        # Check for routing changes using NLNOG Ring
        self._add_to_report("\nRouting changes analysis:")
        self._add_to_report(f"To check for routing changes over the last {self.days} days, use these resources:")

        # NLNOG Ring instructions
        self._add_to_report("\n1. NLNOG Ring looking glass (current routing state):")
        self._add_to_report("   - Visit: https://lg.ring.nlnog.net/")
        self._add_to_report("   - Select different nodes to get diverse perspectives")
        self._add_to_report(f"   - For your prefix {self.prefix}, use command: 'show ip bgp {self.prefix}'")

        # Use RIPE Stat API for looking glass and BGPlay data
        self._add_to_report("\n2. RIPE Stat API Analysis:")
        self._add_to_report("   Querying RIPE Stat API for routing information...")

        # Query the RIPE Stat API for looking glass data if --current flag is set
        if self.show_current:
            self._query_ripe_looking_glass()

        # Query the RIPE Stat API for BGPlay data
        self._query_ripe_bgplay(start_date, end_date)

        # Query the RIPE Stat API for AS Overview data
        if self.asn:
            self._query_ripe_as_overview()

        # Query the RIPE Stat API for Routing Consistency data
        if self.prefix:
            self._query_ripe_routing_consistency()

        # bgp.tools for detailed prefix information
        self._add_to_report("\n3. bgp.tools for detailed prefix analysis:")
        self._add_to_report(f"   - Visit: https://bgp.tools/prefix/{self.prefix}")
        self._add_to_report("   - Shows current routing status and prefix details")

        # RouteViews Archive for historical data
        month_year = start_date.strftime("%Y.%m")
        self._add_to_report("\n4. RouteViews Archive for raw historical data:")
        self._add_to_report(f"   - Visit: https://archive.routeviews.org/bgpdata/{month_year}/RIBS/")
        self._add_to_report("   - Contains raw MRT files that can be analyzed with specialized tools")

    def _query_ripe_looking_glass(self):
        """Query the RIPE Stat API for looking glass data."""
        self._add_to_report("\nQuerying RIPE Stat Looking Glass API...")

        if not self.prefix:
            self._add_to_report("No prefix available for looking glass query")
            return

        # Use the RIPE Stat API for looking glass data
        # API documentation: https://stat.ripe.net/docs/02.data-api/looking-glass.html
        url = f"https://stat.ripe.net/data/looking-glass/data.json?resource={self.prefix}"

        try:
            response = requests.get(url, timeout=15)

            if response.status_code == 200:
                data = response.json()

                if data["status"] == "ok" and "data" in data:
                    lg_data = data["data"]

                    # Extract routing information
                    if "rrcs" in lg_data:
                        rrcs = lg_data["rrcs"]

                        if rrcs:
                            self._add_to_report(f"Found routing information from {len(rrcs)} RIPE RIS collectors:")

                            # Process each collector
                            for i, rrc in enumerate(rrcs[:5]):  # Show first 5 collectors
                                rrc_id = rrc.get("rrc", "Unknown")
                                location = rrc.get("location", "Unknown")

                                self._add_to_report(f"\nCollector: {rrc_id} ({location})")

                                # Process peers
                                if "peers" in rrc:
                                    peers = rrc["peers"]
                                    self._add_to_report(f"  Peers reporting this prefix: {len(peers)}")

                                    # Show sample peers
                                    for j, peer in enumerate(peers[:3]):  # Show first 3 peers
                                        # Extract peer ASN and ID correctly
                                        peer_asn = peer.get("asn", "Unknown")
                                        peer_id = peer.get("id", "Unknown")

                                        # More aggressive approach to extract ASN information
                                        # First try the peer ASN directly
                                        if peer_asn and peer_asn != "Unknown":
                                            peer_asn_str = f"AS{peer_asn}"
                                        # Then try the peer ID
                                        elif isinstance(peer_id, str) and peer_id.isdigit():
                                            peer_asn_str = f"AS{peer_id}"
                                        # Then try to extract from entries
                                        elif "entries" in peer and peer["entries"]:
                                            # Try to get ASN from the first entry
                                            first_entry = peer["entries"][0]
                                            if "origin" in first_entry and first_entry["origin"] != "Unknown":
                                                peer_asn_str = f"AS{first_entry['origin']}"
                                            # Try to extract from AS path
                                            elif "as_path" in first_entry and first_entry["as_path"]:
                                                path = first_entry["as_path"]
                                                if path:
                                                    # Use the first ASN in the path
                                                    peer_asn_str = f"AS{path[0]}"
                                                else:
                                                    peer_asn_str = "Peer ASN unavailable"
                                            else:
                                                peer_asn_str = "Peer ASN unavailable"
                                        # If all else fails, check if there's a key in the peer object that might contain the ASN
                                        else:
                                            asn_found = False
                                            for key, value in peer.items():
                                                if isinstance(value, (int, str)) and str(value).isdigit():
                                                    try:
                                                        asn_int = int(value)
                                                        if 1 <= asn_int <= 4200000000:  # Valid ASN range
                                                            peer_asn_str = f"AS{value}"
                                                            asn_found = True
                                                            break
                                                    except:
                                                        pass

                                            if not asn_found:
                                                peer_asn_str = "Peer ASN unavailable"

                                        self._add_to_report(f"  - Peer {peer_asn_str} (ID: {peer_id})")

                                        # Show routing entries
                                        if "entries" in peer:
                                            entries = peer["entries"]
                                            self._add_to_report(f"    Routing entries: {len(entries)}")

                                            for k, entry in enumerate(entries[:2]):  # Show first 2 entries
                                                primary = entry.get("primary", False)
                                                origin = entry.get("origin", "Unknown")
                                                path = entry.get("as_path", [])

                                                path_str = " ".join(str(asn) for asn in path)
                                                primary_str = "Primary" if primary else "Non-primary"

                                                self._add_to_report(f"    - {primary_str} route via AS{origin}")
                                                self._add_to_report(f"      Path: {path_str}")

                            if len(rrcs) > 5:
                                self._add_to_report(f"\n... and {len(rrcs) - 5} more collectors")
                        else:
                            self._add_to_report("No routing information found in RIPE RIS collectors")
                    else:
                        self._add_to_report("No routing information found in RIPE RIS collectors")
                else:
                    self._add_to_report(f"Error in RIPE Stat API response: {data.get('status_message', 'Unknown error')}")
            else:
                self._add_to_report(f"Error: RIPE Stat API returned status code {response.status_code}")

        except requests.exceptions.RequestException as e:
            self._add_to_report(f"Error connecting to RIPE Stat API: {e}")
        except json.JSONDecodeError:
            self._add_to_report("Error parsing RIPE Stat API response")

    def _get_asn_contact_details(self):
        """Get contact details for an ASN from whois."""
        if not self.asn:
            return None

        contact_info = {
            'admin_email': None,
            'tech_email': None,
            'abuse_email': None,
            'noc_email': None,
            'organization': None,
            'address': [],
            'phone': None,
            'noc_phone': None
        }

        try:
            # Run whois command for the ASN
            whois_cmd = ["whois", f"AS{self.asn}"]
            whois_process = subprocess.Popen(whois_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            stdout, stderr = whois_process.communicate()

            if whois_process.returncode == 0 and stdout:
                # Extract contact information

                # Extract organization
                org_match = re.search(r'Organization:\s*(.*)', stdout)
                if org_match:
                    contact_info['organization'] = org_match.group(1).strip()
                else:
                    # Try alternative fields
                    org_match = re.search(r'org-name:\s*(.*)', stdout)
                    if org_match:
                        contact_info['organization'] = org_match.group(1).strip()

                # Extract address
                address_matches = re.findall(r'Address:\s*(.*)', stdout)
                if address_matches:
                    contact_info['address'] = [addr.strip() for addr in address_matches]
                else:
                    # Try alternative fields
                    address_matches = re.findall(r'address:\s*(.*)', stdout)
                    if address_matches:
                        contact_info['address'] = [addr.strip() for addr in address_matches]

                # Extract phone numbers
                phone_match = re.search(r'Phone:\s*(.*)', stdout)
                if phone_match:
                    contact_info['phone'] = phone_match.group(1).strip()

                # Look for NOC phone specifically
                noc_phone_match = re.search(r'NOC Phone:\s*(.*)', stdout, re.IGNORECASE) or re.search(r'noc-phone:\s*(.*)', stdout, re.IGNORECASE)
                if noc_phone_match:
                    contact_info['noc_phone'] = noc_phone_match.group(1).strip()

                # Extract emails
                admin_email_match = re.search(r'Admin Email:\s*(.*)', stdout, re.IGNORECASE) or re.search(r'admin-c:\s*(.*@.*)', stdout, re.IGNORECASE)
                if admin_email_match:
                    contact_info['admin_email'] = admin_email_match.group(1).strip()

                tech_email_match = re.search(r'Tech Email:\s*(.*)', stdout, re.IGNORECASE) or re.search(r'tech-c:\s*(.*@.*)', stdout, re.IGNORECASE)
                if tech_email_match:
                    contact_info['tech_email'] = tech_email_match.group(1).strip()

                abuse_email_match = re.search(r'Abuse Email:\s*(.*)', stdout, re.IGNORECASE) or re.search(r'abuse-mailbox:\s*(.*)', stdout, re.IGNORECASE) or re.search(r'abuse-c:\s*(.*@.*)', stdout, re.IGNORECASE)
                if abuse_email_match:
                    contact_info['abuse_email'] = abuse_email_match.group(1).strip()

                # Look for NOC email specifically
                noc_email_match = re.search(r'NOC Email:\s*(.*)', stdout, re.IGNORECASE) or re.search(r'noc-mailbox:\s*(.*)', stdout, re.IGNORECASE) or re.search(r'noc@', stdout, re.IGNORECASE)
                if noc_email_match:
                    if isinstance(noc_email_match, re.Match):
                        contact_info['noc_email'] = noc_email_match.group(1).strip() if noc_email_match.groups() else None
                    else:
                        # If we found noc@ in the text, try to extract the full email
                        noc_emails = re.findall(r'[\w\.-]+@[\w\.-]+\.\w+', stdout)
                        for email in noc_emails:
                            if 'noc@' in email.lower():
                                contact_info['noc_email'] = email
                                break

                # If no specific emails found, look for any email
                if not (contact_info['admin_email'] or contact_info['tech_email'] or contact_info['abuse_email']):
                    email_matches = re.findall(r'[\w\.-]+@[\w\.-]+', stdout)
                    if email_matches:
                        # Use the first email found
                        contact_info['admin_email'] = email_matches[0]

                # Try to find abuse contact from abuse.net
                if not contact_info['abuse_email']:
                    try:
                        # Query abuse.net for the ASN
                        abuse_cmd = ["dig", f"AS{self.asn}.abuse-contacts.abusix.org", "TXT", "+short"]
                        abuse_process = subprocess.Popen(abuse_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                        abuse_stdout, abuse_stderr = abuse_process.communicate()

                        if abuse_process.returncode == 0 and abuse_stdout:
                            # Extract email from the TXT record
                            abuse_email_match = re.search(r'"(.*?)"', abuse_stdout)
                            if abuse_email_match:
                                contact_info['abuse_email'] = abuse_email_match.group(1).strip()
                    except:
                        pass

        except Exception as e:
            print(f"Error getting ASN contact details: {e}")

        return contact_info

    def _query_ripe_as_overview(self):
        """Query the RIPE Stat API for AS Overview data."""
        self._add_to_report("\nQuerying RIPE Stat AS Overview API...")

        if not self.asn:
            self._add_to_report("No ASN available for AS Overview query")
            return

        # Use the RIPE Stat API for AS Overview data
        # API documentation: https://stat.ripe.net/docs/02.data-api/as-overview.html
        url = f"https://stat.ripe.net/data/as-overview/data.json?resource={self.asn}"

        try:
            response = requests.get(url, timeout=15)

            if response.status_code == 200:
                data = response.json()

                if data["status"] == "ok" and "data" in data:
                    as_data = data["data"]

                    self._add_to_report("\nAS Overview Information:")

                    # Extract holder information
                    if "holder" in as_data:
                        holder = as_data["holder"]
                        self._add_to_report(f"  - AS{self.asn} Holder: {holder}")

                    # Extract announced prefixes count
                    if "announced_prefixes" in as_data:
                        announced_prefixes = as_data["announced_prefixes"]
                        self._add_to_report(f"  - Announced Prefixes: {announced_prefixes}")

                    # Extract resource information
                    if "resource" in as_data:
                        resource = as_data["resource"]
                        self._add_to_report(f"  - Resource: {resource}")

                    # Extract block information
                    if "block" in as_data:
                        block = as_data["block"]
                        self._add_to_report(f"  - Block: {block}")

                    # Get contact details
                    contact_info = self._get_asn_contact_details()
                    if contact_info:
                        self._add_to_report("\nContact Information:")

                        if contact_info['organization'] and contact_info['organization'] != holder:
                            self._add_to_report(f"  - Organization: {contact_info['organization']}")

                        if contact_info['address']:
                            self._add_to_report("  - Address:")
                            for addr in contact_info['address'][:3]:  # Show up to 3 address lines
                                self._add_to_report(f"    {addr}")

                        # Display NOC contact information first (most important for network operations)
                        if contact_info['noc_email']:
                            self._add_to_report(f"  - NOC Email: {contact_info['noc_email']}")

                        if contact_info['noc_phone']:
                            self._add_to_report(f"  - NOC Phone: {contact_info['noc_phone']}")

                        # Then display other contact information
                        if contact_info['phone'] and contact_info['phone'] != contact_info['noc_phone']:
                            self._add_to_report(f"  - General Phone: {contact_info['phone']}")

                        if contact_info['abuse_email'] and contact_info['abuse_email'] != contact_info['noc_email']:
                            self._add_to_report(f"  - Abuse Email: {contact_info['abuse_email']}")

                        if contact_info['admin_email'] and contact_info['admin_email'] != contact_info['noc_email'] and contact_info['admin_email'] != contact_info['abuse_email']:
                            self._add_to_report(f"  - Admin Email: {contact_info['admin_email']}")

                        if contact_info['tech_email'] and contact_info['tech_email'] != contact_info['noc_email'] and contact_info['tech_email'] != contact_info['admin_email'] and contact_info['tech_email'] != contact_info['abuse_email']:
                            self._add_to_report(f"  - Tech Email: {contact_info['tech_email']}")

                        # If no NOC contact was found, check if PeeringDB page exists before suggesting it
                        if not (contact_info['noc_email'] or contact_info['noc_phone']):
                            # Check if PeeringDB page exists
                            try:
                                peeringdb_url = f"https://www.peeringdb.com/api/net?asn={self.asn}"
                                peeringdb_response = requests.get(peeringdb_url, timeout=5)

                                if peeringdb_response.status_code == 200:
                                    peeringdb_data = peeringdb_response.json()

                                    # Check if there's data for this ASN
                                    if peeringdb_data.get("data") and len(peeringdb_data["data"]) > 0:
                                        self._add_to_report(f"  - Note: No NOC contact found. Check PeeringDB: https://www.peeringdb.com/asn/{self.asn}")
                                    else:
                                        self._add_to_report(f"  - Note: No NOC contact found. No PeeringDB entry available for AS{self.asn}.")
                                else:
                                    self._add_to_report(f"  - Note: No NOC contact found.")
                            except:
                                self._add_to_report(f"  - Note: No NOC contact found.")

                    # Provide link to AS Overview in RIPE Stat
                    self._add_to_report(f"\nFor more details, visit: https://stat.ripe.net/AS{self.asn}")
                else:
                    self._add_to_report(f"Error in RIPE Stat API response: {data.get('status_message', 'Unknown error')}")
            else:
                self._add_to_report(f"Error: RIPE Stat API returned status code {response.status_code}")

        except requests.exceptions.RequestException as e:
            self._add_to_report(f"Error connecting to RIPE Stat API: {e}")
        except json.JSONDecodeError:
            self._add_to_report("Error parsing RIPE Stat API response")

    def _query_ripe_routing_consistency(self):
        """Query the RIPE Stat API for Routing Consistency data."""

        if not self.prefix:
            self._add_to_report("No prefix available for Routing Consistency query")
            return

        # Use the RIPE Stat API for Routing Consistency data
        # API documentation: https://stat.ripe.net/docs/02.data-api/as-routing-consistency.html
        # This API requires an ASN as the resource parameter, not a prefix
        url = f"https://stat.ripe.net/data/as-routing-consistency/data.json?resource={self.asn}"

        try:
            response = requests.get(url, timeout=15)

            if response.status_code == 200:
                data = response.json()

                if data["status"] == "ok" and "data" in data:
                    consistency_data = data["data"]


                    # Extract consistency information
                    if "consistency" in consistency_data:
                        consistency = consistency_data["consistency"]
                        self._add_to_report(f"  - Consistency: {consistency}")

                    # Extract and analyze RIB visibility
                    if "asns" in consistency_data:
                        asns = consistency_data["asns"]

                        # Count ASNs that have this ASN in their RIB and those that don't
                        asns_with_rib = []
                        asns_without_rib = []

                        for asn_data in asns:
                            asn = asn_data.get("asn", "Unknown")
                            has_route = asn_data.get("has_route", False)

                            if has_route:
                                asns_with_rib.append(asn)
                            else:
                                asns_without_rib.append(asn)

                        # Report RIB visibility statistics
                        self._add_to_report(f"\n  - RIB Visibility Analysis:")
                        self._add_to_report(f"    - ASNs with AS{self.asn} in their RIB: {len(asns_with_rib)} ({(len(asns_with_rib) / len(asns) * 100):.1f}%)")
                        self._add_to_report(f"    - ASNs without AS{self.asn} in their RIB: {len(asns_without_rib)} ({(len(asns_without_rib) / len(asns) * 100):.1f}%)")

                        # Show sample ASNs with RIB entries
                        if asns_with_rib:
                            self._add_to_report(f"\n    - Sample ASNs with AS{self.asn} in their RIB:")
                            for asn in asns_with_rib[:5]:  # Show first 5
                                self._add_to_report(f"      - AS{asn}")
                            if len(asns_with_rib) > 5:
                                self._add_to_report(f"      - ... and {len(asns_with_rib) - 5} more")

                        # Show sample ASNs without RIB entries
                        if asns_without_rib:
                            self._add_to_report(f"\n    - Sample ASNs without AS{self.asn} in their RIB:")
                            for asn in asns_without_rib[:5]:  # Show first 5
                                self._add_to_report(f"      - AS{asn}")
                            if len(asns_without_rib) > 5:
                                self._add_to_report(f"      - ... and {len(asns_without_rib) - 5} more")

                    # Extract origin ASNs
                    if "origins" in consistency_data:
                        origins = consistency_data["origins"]
                        if origins:
                            self._add_to_report("\n  - Origin ASNs:")
                            for origin in origins:
                                asn = origin.get("origin", "Unknown")
                                self._add_to_report(f"    - AS{asn}")
                        else:
                            self._add_to_report("\n  - No origin ASNs found")

                    # Extract irr records
                    if "irr_sources" in consistency_data:
                        irr_sources = consistency_data["irr_sources"]
                        if irr_sources:
                            self._add_to_report("\n  - IRR Sources:")
                            for source in irr_sources:
                                self._add_to_report(f"    - {source}")
                        else:
                            self._add_to_report("\n  - No IRR sources found")

                    # Provide link to Routing Consistency in RIPE Stat
                    self._add_to_report(f"\nFor more details, visit: https://stat.ripe.net/prefix-routing-consistency#{{'resource':'{self.prefix}'}}")
                else:
                    self._add_to_report(f"Error in RIPE Stat API response: {data.get('status_message', 'Unknown error')}")
            else:
                self._add_to_report(f"Error: RIPE Stat API returned status code {response.status_code}")

        except requests.exceptions.RequestException as e:
            self._add_to_report(f"Error connecting to RIPE Stat API: {e}")
        except json.JSONDecodeError:
            self._add_to_report("Error parsing RIPE Stat API response")

    def _query_ripe_bgplay(self, start_date, end_date):
        """Query the RIPE Stat API for BGPlay data."""
        self._add_to_report("\nQuerying RIPE Stat BGPlay API for routing changes...")

        if not self.prefix:
            self._add_to_report("No prefix available for BGPlay query")
            return

        # Format dates for the API
        start_str = start_date.strftime("%Y-%m-%d")
        end_str = end_date.strftime("%Y-%m-%d")

        # Use the RIPE Stat API for BGPlay data
        # API documentation: https://stat.ripe.net/docs/02.data-api/bgplay.html
        url = f"https://stat.ripe.net/data/bgplay/data.json?resource={self.prefix}&starttime={start_str}&endtime={end_str}"

        try:
            self._add_to_report(f"Analyzing routing changes from {start_str} to {end_str}...")
            response = requests.get(url, timeout=15)

            if response.status_code == 200:
                data = response.json()

                if data["status"] == "ok" and "data" in data:
                    bgp_data = data["data"]

                    # Extract routing events
                    if "events" in bgp_data:
                        events = bgp_data["events"]

                        if events:
                            self._add_to_report(f"\nFound {len(events)} routing events for {self.prefix}:")

                            # Group events by type
                            event_types = {}
                            for event in events:
                                event_type = event.get("type", "Unknown")
                                event_types[event_type] = event_types.get(event_type, 0) + 1

                            # Show event type summary with explanation
                            self._add_to_report("\nEvent type summary:")
                            for event_type, count in sorted(event_types.items(), key=lambda x: x[1], reverse=True):
                                if event_type == "A":
                                    self._add_to_report(f"  - A (Announcement): {count} events - Prefix was announced by an AS")
                                elif event_type == "W":
                                    self._add_to_report(f"  - W (Withdrawal): {count} events - Prefix was withdrawn by an AS")
                                else:
                                    self._add_to_report(f"  - {event_type}: {count} events")

                            # Find the most informative events to show as samples
                            # We want to prioritize events with complete path information
                            informative_events = []
                            for event in events:
                                event_type = event.get("type", "Unknown")
                                has_path = "path" in event and event["path"]
                                has_peer = event.get("peer", "Unknown") != "Unknown"

                                # Score the event based on how informative it is
                                score = 0
                                if has_path:
                                    score += 2
                                if has_peer:
                                    score += 1

                                informative_events.append((event, score))

                            # Sort events by score (most informative first)
                            informative_events.sort(key=lambda x: x[1], reverse=True)

                            # Take the top 5 most informative events
                            sample_events = [e[0] for e in informative_events[:5]]

                            # If we couldn't find 5 informative events, add some regular events
                            if len(sample_events) < 5:
                                remaining = 5 - len(sample_events)
                                for event in events:
                                    if event not in sample_events:
                                        sample_events.append(event)
                                        remaining -= 1
                                        if remaining == 0:
                                            break

                            # Show sample events
                            self._add_to_report("\nSample routing events:")
                            for event in sample_events:
                                event_type = event.get("type", "Unknown")
                                timestamp = event.get("timestamp", "Unknown")
                                peer = event.get("peer", "Unknown")

                                # Extract peer information
                                if peer and peer != "Unknown":
                                    peer_str = f"AS{peer}"
                                elif "path" in event and event["path"]:
                                    path = event["path"]
                                    if path:
                                        # Use the first ASN in the path as the peer
                                        peer_str = f"AS{path[0]}"
                                    else:
                                        peer_str = "from collector"
                                else:
                                    peer_str = "from collector"

                                # Convert timestamp to readable format
                                try:
                                    timestamp_dt = datetime.fromtimestamp(timestamp)
                                    timestamp_str = timestamp_dt.strftime("%Y-%m-%d %H:%M:%S")
                                except:
                                    timestamp_str = str(timestamp)

                                # Format the event description
                                if event_type == "A":
                                    event_desc = f"{timestamp_str}: Prefix ANNOUNCED {peer_str}"
                                elif event_type == "W":
                                    event_desc = f"{timestamp_str}: Prefix WITHDRAWN {peer_str}"
                                else:
                                    event_desc = f"{timestamp_str}: {event_type} event {peer_str}"

                                self._add_to_report(f"  - {event_desc}")

                                # Show path details for announcements
                                if event_type == "A" and "path" in event:
                                    path = event["path"]
                                    if path:
                                        path_str = " → ".join(f"AS{asn}" for asn in path)
                                        self._add_to_report(f"    Path: {path_str}")

                                        # Show origin ASN (last in path)
                                        if path:
                                            origin_asn = path[-1]
                                            self._add_to_report(f"    Origin: AS{origin_asn}")

                            if len(events) > 5:
                                self._add_to_report(f"\n... and {len(events) - 5} more events")

                            # Analyze routing stability focusing on origin AS changes
                            self._add_to_report("\nRouting stability analysis:")

                            # Count announcements and withdrawals
                            announcements = sum(1 for e in events if e.get("type") == "A")
                            withdrawals = sum(1 for e in events if e.get("type") == "W")

                            self._add_to_report(f"  - Total routing events: {len(events)}")
                            self._add_to_report(f"  - Announcements: {announcements}")
                            self._add_to_report(f"  - Withdrawals: {withdrawals}")

                            # Track origin AS changes
                            origin_changes = 0
                            current_origin = None
                            origin_asns = set()

                            # Sort events by timestamp
                            sorted_events = sorted(events, key=lambda e: e.get("timestamp", 0))

                            for event in sorted_events:
                                if event.get("type") == "A" and "path" in event and event["path"]:
                                    path = event["path"]
                                    if path:
                                        origin_asn = path[-1]  # Last ASN in path is the origin
                                        origin_asns.add(origin_asn)

                                        if current_origin is not None and current_origin != origin_asn:
                                            origin_changes += 1

                                        current_origin = origin_asn

                            # Report origin changes
                            self._add_to_report(f"  - Origin AS changes: {origin_changes}")
                            self._add_to_report(f"  - Unique origin ASNs observed: {len(origin_asns)}")

                            if origin_asns:
                                self._add_to_report("  - Origin ASNs observed:")
                                for asn in origin_asns:
                                    self._add_to_report(f"    - AS{asn}")

                            # Calculate events per day
                            days_diff = (end_date - start_date).days or 1  # Avoid division by zero
                            events_per_day = len(events) / days_diff

                            self._add_to_report(f"  - Events per day: {events_per_day:.1f}")

                            # Assess stability based on origin changes, not just event count
                            if origin_changes > 0:
                                self._add_to_report("  - Assessment: Origin AS changes detected")
                                self._add_to_report("    This could indicate prefix hijacking or legitimate changes in announcement policy")
                            elif len(origin_asns) > 1:
                                self._add_to_report("  - Assessment: Multiple origin ASNs detected")
                                self._add_to_report("    This could indicate anycast deployment or multi-homing")
                            elif withdrawals > announcements * 0.5:  # High ratio of withdrawals to announcements
                                self._add_to_report("  - Assessment: High withdrawal ratio detected")
                                self._add_to_report("    This could indicate intermittent connectivity or route flapping")
                            elif events_per_day > 20:
                                self._add_to_report("  - Assessment: High routing activity detected")
                                self._add_to_report("    This could indicate route propagation issues in the global routing table")
                            elif events_per_day > 10:
                                self._add_to_report("  - Assessment: Moderate routing activity detected")
                            else:
                                self._add_to_report("  - Assessment: Low routing activity, prefix appears stable")
                        else:
                            self._add_to_report("No routing events found for this prefix in the specified time period")
                    else:
                        self._add_to_report("No routing events data available")

                    # Extract initial and final state
                    if "initial_state" in bgp_data and "latest_state" in bgp_data:
                        initial = bgp_data["initial_state"]
                        latest = bgp_data["latest_state"]

                        # Compare states to detect changes
                        initial_sources = set(src.get("asn") for src in initial if "asn" in src)
                        latest_sources = set(src.get("asn") for src in latest if "asn" in src)

                        added = latest_sources - initial_sources
                        removed = initial_sources - latest_sources

                        if added or removed:
                            self._add_to_report("\nChanges in announcing ASNs:")
                            if added:
                                self._add_to_report(f"  - Added: {', '.join(f'AS{asn}' for asn in added)}")
                            if removed:
                                self._add_to_report(f"  - Removed: {', '.join(f'AS{asn}' for asn in removed)}")
                        else:
                            self._add_to_report("\nNo changes in announcing ASNs during this period")

                else:
                    self._add_to_report(f"Error in RIPE Stat API response: {data.get('status_message', 'Unknown error')}")
            else:
                self._add_to_report(f"Error: RIPE Stat API returned status code {response.status_code}")

        except requests.exceptions.RequestException as e:
            self._add_to_report(f"Error connecting to RIPE Stat API: {e}")
        except json.JSONDecodeError:
            self._add_to_report("Error parsing RIPE Stat API response")


    def generate_report(self):
        """Generate a comprehensive report."""
        self._add_to_report("\n4. Summary and Recommendations")
        self._add_to_report("-" * 70)

        if not self.target_ip:
            self._add_to_report(f"Could not resolve {self.target} to an IP address")
            self._add_to_report("Recommendation: Check if the hostname is correct")
            return

        if self.is_private:
            self._add_to_report(f"{self.target_ip} is a private/special IP address")
            self._add_to_report("Private IPs are not announced on the global internet")
            self._add_to_report("Recommendation: Use a public IP address for global routing analysis")
            return

        # Summarize findings
        self._add_to_report("Summary:")

        # Network information summary
        if self.prefix and self.asn:
            self._add_to_report(f"  - {self.target_ip} belongs to prefix {self.prefix} announced by AS{self.asn}")
            self._add_to_report(f"  - Network: {self.asn_name} ({self.country})")
        else:
            self._add_to_report(f"  - Could not determine network information for {self.target_ip}")

        # Reachability summary
        # This is simplified; in a real implementation, you would store the reachability results
        # and reference them here
        self._add_to_report("  - See reachability section for connectivity details")

        # Global routing summary
        if self.prefix:
            self._add_to_report(f"  - See global routing section for visibility of {self.prefix}")

        # Provide links to additional resources
        self._add_to_report("\nAdditional Resources:")

        if self.target_ip:
            self._add_to_report(f"  - NLNOG Ring: https://lg.ring.nlnog.net/ (for traceroutes from multiple locations)")

        if self.prefix:
            self._add_to_report(f"  - bgp.tools: https://bgp.tools/prefix/{self.prefix}")

        if self.asn:
            self._add_to_report(f"  - ASN details: https://bgp.tools/as/{self.asn}")
            self._add_to_report(f"  - PeeringDB: https://www.peeringdb.com/asn/{self.asn}")

    def run_diagnostics(self):
        """Run all diagnostics and return the report."""
        # Prefix information is already gathered in the __init__ method

        # Check reachability
        self.check_reachability()

        # Check global routing
        self.check_global_routing()

        # Generate summary and recommendations
        self.generate_report()

        # Return the complete report
        return "\n".join(self.report)


def main():
    parser = argparse.ArgumentParser(description="Network Diagnostics Tool")
    parser.add_argument("target", help="Target IP address or hostname")
    parser.add_argument("--period", choices=["24h", "2d", "5d", "7d"], default="24h",
                      help="Time period for routing analysis (24h, 2d, 5d, 7d)")
    parser.add_argument("--output", help="Output file for the report (optional)")
    parser.add_argument("--ipv6", action="store_true", help="Force IPv6 resolution for hostnames")
    parser.add_argument("--current", action="store_true", help="Show actual route visibility in the global routing table")
    args = parser.parse_args()

    # Create diagnostics object and run diagnostics
    diagnostics = NetworkDiagnostics(args.target, args.period, args.ipv6, args.current)
    report = diagnostics.run_diagnostics()

    # Save report to file
    # If output is specified, use that filename
    # Otherwise, if ASN is available, use ASN.txt
    output_file = None
    if args.output:
        output_file = args.output
    elif diagnostics.asn:
        output_file = f"AS{diagnostics.asn}.txt"

    if output_file:
        try:
            with open(output_file, 'w') as f:
                f.write(report)
            print(f"\nReport saved to {output_file}")
        except Exception as e:
            print(f"Error saving report to file: {e}")


if __name__ == "__main__":
    main()

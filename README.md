# Network Diagnostics Tool

A comprehensive network diagnostics tool that helps troubleshoot connectivity issues by:

- Getting prefix and ASN information using Team Cymru
- Querying bgp.tools and BGPView APIs for routing information
- Analyzing historical route changes with RIS MRT data
- Providing links to multiple BGP and routing information resources

## Features

### 1. Intelligent Prefix Detection

Automatically identifies the network prefix an IP belongs to:
- Uses Team Cymru whois service as the primary source
- Provides ASN, country, and network name information
- Correlates data from multiple sources for accuracy

### 2. Multiple Data Source Integration

Queries several authoritative BGP data sources:
- Team Cymru whois service for initial prefix and ASN information
- bgp.tools API for detailed routing information and route server visibility
- BGPView API for additional prefix and ASN details
- NLNOG Ring looking glass for distributed network diagnostics
- RIS MRT data for in-depth route change analysis over multiple time periods
- Cross-references information between sources for reliability

### 3. Historical Route Analysis

Provides insights into routing changes and events:
- RIS MRT data analysis for flexible time periods (24h, 2d, 5d, 7d)
- MRT file metadata extraction without requiring external tools
- Links to online services for detailed routing analysis
- Alternative data sources for comprehensive historical analysis

### 4. Comprehensive Resource Links

Generates direct links to detailed reports for further analysis:
- bgp.tools (primary resource)
- BGPView
- Team Cymru IP Info
- IPInfo
- PeeringDB (for ASN information)
- NLNOG Ring looking glass
- Links for IP, ASN, and prefix-specific resources

## Requirements

- Python 3.6+
- Required Python packages:
  - requests
  - ipaddress

## Installation

1. Clone or download this repository
2. Make the shell script executable:
   ```
   chmod +x run_diagnostics.sh
   ```
3. The shell script will automatically install required dependencies and make the Python script executable

## Usage

### Using the Shell Script (Recommended)

The easiest way to run the tool is using the provided shell script:

```
./run_diagnostics.sh TARGET [--period PERIOD]
```

Where:
- `TARGET` is an IP address or hostname you want to diagnose
- `PERIOD` (optional) is the time period for MRT data analysis (24h, 2d, 5d, 7d)

Examples:
```
./run_diagnostics.sh example.com
./run_diagnostics.sh 8.8.8.8 --period 7d
```

The shell script will:
- Check for Python and pip installation
- Install required dependencies
- Make the Python script executable
- Run the network diagnostics tool with your specified target

### Direct Python Usage

You can also run the Python script directly:

```
./network_diagnostics.py TARGET [--period PERIOD]
```

Examples:
```
./network_diagnostics.py 8.8.8.8
./network_diagnostics.py example.com --period 5d
```

## Example Output

```
Network Diagnostics for 8.8.8.8
==================================================

[+] Getting prefix information for 8.8.8.8...
Team Cymru reports IP 8.8.8.8 belongs to:
  - Prefix: 8.8.8.0/24
  - ASN: 15169
  - Country: US
  - ASN Name: GOOGLE - Google LLC

[+] Querying bgp.tools for routing information...
Error: bgp.tools API returned status code 501

[+] Querying BGPView for routing information...
BGPView reports IP 8.8.8.8 belongs to:
  - Prefix: 8.8.8.0/24
  - ASN: 15169
  - Name: GOOGLE
  - Description: Google LLC

[+] Querying NLNOG Ring for routing information...
NLNOG Ring provides a distributed looking glass with nodes around the world.
You can use it to run network diagnostics from multiple locations.

For your prefix 8.8.8.0/24, you can:
1. Visit https://lg.ring.nlnog.net/
2. Select a node from the dropdown (e.g., 'xs4all01' in Netherlands)
3. Choose 'BGP' from the command dropdown
4. Enter 'route 8.8.8.0/24' in the arguments field
5. Click 'Run command' to see BGP route information

[+] Analyzing RIS MRT data for the last 24h (1 days)...
RIPE NCC's Routing Information Service (RIS) collects and stores BGP routing information
in MRT format, which can be used for detailed route change analysis.

Note: Using data from 2023-06-16 to 2023-06-16

[+] MRT Analysis Report for 8.8.8.0/24:
============================================================

Date: 2023-06-16
------------------------------------------------------------

Collector: rrc00
Source: https://data.ris.ripe.net/rrc00/2023.06/rrc00.20230616.0000.gz
File size: 65.42 MB
File is large. Providing metadata only.
To analyze this file, you would need to:
1. Download: wget https://data.ris.ripe.net/rrc00/2023.06/rrc00.20230616.0000.gz
2. Install a tool like bgpdump or mrtparse
3. Process with: bgpdump -M downloaded_file.gz | grep 8.8.8.0/24

Collector: rrc01
Source: https://data.ris.ripe.net/rrc01/2023.06/rrc01.20230616.0000.gz
File size: 42.18 MB
File is large. Providing metadata only.
To analyze this file, you would need to:
1. Download: wget https://data.ris.ripe.net/rrc01/2023.06/rrc01.20230616.0000.gz
2. Install a tool like bgpdump or mrtparse
3. Process with: bgpdump -M downloaded_file.gz | grep 8.8.8.0/24

Alternative data sources for 2023-06-16:
- RouteViews Archive: https://archive.routeviews.org/bgpdata/2023.06/RIBS/
- PCH Route Server Data: https://www.pch.net/resources/Routing_Data/
- CAIDA BGP Data: https://www.caida.org/catalog/datasets/routeviews-prefix2as/

[+] Links to BGP and routing information resources:

IP-specific resources:
  - bgp.tools: https://bgp.tools/ip/8.8.8.8
  - BGPView: https://bgpview.io/ip/8.8.8.8
  - Team Cymru IP Info: https://whois.cymru.com/cgi-bin/whois.cgi?query=8.8.8.8
  - IPInfo: https://ipinfo.io/8.8.8.8
  - NLNOG Ring: https://lg.ring.nlnog.net/

ASN-specific resources for AS15169:
  - bgp.tools: https://bgp.tools/as/15169
  - BGPView: https://bgpview.io/asn/15169
  - PeeringDB: https://www.peeringdb.com/asn/15169

Prefix-specific resources for 8.8.8.0/24:
  - bgp.tools: https://bgp.tools/prefix/8.8.8.0/24
  - BGPView: https://bgpview.io/prefix/8.8.8.0/24
```

## Special Cases Handling

The tool provides informative messages for special cases:

### Private IP Addresses
```
[+] Getting prefix information for 192.168.1.1...
NOTE: 192.168.1.1 is a private/special IP address and won't be visible in public routing tables
Private IPs are not announced on the global internet
```

### Non-routable or Unannounced IPs
```
[+] Getting prefix information for 203.0.113.1...
Could not determine prefix information for 203.0.113.1
This may indicate the IP is not announced in the global BGP table
```

### API Error Handling
```
[+] Querying bgp.tools for routing information...
Error: bgp.tools API returned status code 501
```

## Advanced Usage

For more advanced network diagnostics, consider:

1. Using the bgp.tools links provided for detailed analysis
2. Comparing routing information from different sources
3. Investigating ASN relationships and peering information
4. Using the prefix-specific and ASN-specific links for broader context
5. Leveraging NLNOG Ring for distributed network diagnostics
6. Analyzing historical route changes with RIS MRT data over different time periods
7. Using the provided links to online services for detailed routing analysis

## NLNOG Ring Usage Tips

The NLNOG Ring looking glass (https://lg.ring.nlnog.net/) provides access to over 600 nodes worldwide, allowing you to:

1. **Run BGP commands** to check route visibility:
   - `show ip bgp X.X.X.X/Y` - View BGP information for a specific prefix
   - `show ip bgp regexp _ASNUMBER_` - View routes with a specific ASN in the path

2. **Perform network diagnostics** from multiple locations:
   - Ping - Test basic connectivity and latency
   - Traceroute - Examine the network path to a destination
   - MTR - Combine ping and traceroute for comprehensive path analysis

3. **Compare results** across different regions to identify:
   - Regional routing differences
   - Path asymmetry issues
   - Localized packet loss or latency problems

## RIS MRT Data Analysis

RIS MRT data provides comprehensive historical routing information:

1. **Flexible time period analysis**:
   - 24h - Last 24 hours of routing data
   - 2d - Last 2 days of routing data
   - 5d - Last 5 days of routing data
   - 7d - Last 7 days of routing data
   - Compare changes across different time periods to identify patterns

2. **MRT file metadata**:
   - File size and availability information
   - Basic header information for smaller files
   - Links to online services for detailed analysis
   - Alternative data sources for each date

3. **Online analysis services**:
   - BGPlay: Interactive visualization of routing changes
   - RIPEstat: Comprehensive routing history analysis
   - RouteViews Archive: Historical BGP data
   - PCH Route Server Data: Additional routing information
   - CAIDA BGP Data: Research-grade BGP datasets

4. **For detailed local analysis**:
   - Download links for MRT files
   - Instructions for installing analysis tools
   - Command examples for processing the data
   - Alternative data sources for comprehensive analysis

## License

This tool is provided under the MIT License.

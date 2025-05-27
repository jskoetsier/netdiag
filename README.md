# Network Diagnostics Tool

A comprehensive network diagnostics tool that helps troubleshoot connectivity issues by:

- Getting prefix and ASN information using Team Cymru
- Analyzing current and historical routing information using RIPE Stat APIs
- Checking reachability with detailed ping statistics
- Providing links to multiple BGP and routing information resources
- Supporting both IPv4 and IPv6 addresses

## Features

### 1. Intelligent Prefix Detection

Automatically identifies the network prefix an IP belongs to:
- Uses Team Cymru whois service as the primary source
- Provides ASN, country, and network name information
- Correlates data from multiple sources for accuracy

### 2. Multiple Data Source Integration

Queries several authoritative BGP data sources:
- Team Cymru whois service for initial prefix and ASN information
- RIPE Stat APIs for comprehensive routing information:
  - Looking Glass API for current routing visibility
  - BGPlay API for historical routing changes
  - AS Overview API for ASN details
  - AS Routing Consistency API for RIB visibility analysis
- Whois services for detailed contact information, including NOC contacts
- NLNOG Ring looking glass for distributed network diagnostics
- Cross-references information between sources for reliability

### 3. Historical Route Analysis

Provides insights into routing changes and events:
- RIPE Stat BGPlay API for historical routing changes over flexible time periods (24h, 2d, 5d, 7d)
- Routing stability analysis with event type categorization
- Detection of route flapping and instability
- Identification of changes in announcing ASNs over time

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
./run_diagnostics.sh TARGET [--period PERIOD] [--ipv6] [--current] [--output FILE]
```

Where:
- `TARGET` is an IP address or hostname you want to diagnose
- `--period PERIOD` (optional) is the time period for historical analysis (24h, 2d, 5d, 7d)
- `--ipv6` (optional) forces IPv6 resolution for hostnames
- `--current` (optional) includes RIPE RIS looking glass data in the report
- `--output FILE` (optional) specifies a custom output file (default: AS{number}.txt)

Examples:
```
# Basic usage
./run_diagnostics.sh example.com

# Analyze 7 days of routing history
./run_diagnostics.sh 8.8.8.8 --period 7d

# Include RIPE RIS looking glass data
./run_diagnostics.sh 8.8.8.8 --current

# Force IPv6 resolution
./run_diagnostics.sh google.com --ipv6

# Specify custom output file
./run_diagnostics.sh 8.8.8.8 --output google-report.txt
```

The shell script will:
- Check for Python and pip installation
- Install required dependencies
- Make the Python script executable
- Run the network diagnostics tool with your specified options
- Automatically save the report to AS{number}.txt unless specified otherwise

### Direct Python Usage

You can also run the Python script directly:

```
./network_diagnostics.py TARGET [--period PERIOD] [--ipv6] [--current] [--output FILE]
```

Examples:
```
./network_diagnostics.py 8.8.8.8
./network_diagnostics.py example.com --period 5d --current
./network_diagnostics.py 2001:4860:4860::8888 --ipv6
```

## Example Output

```
Network Diagnostics Report for 8.8.8.8
======================================================================
Generated on: 2023-06-20 15:30:45
Time period: 24h (1 days)

1. Network Information
----------------------------------------------------------------------
IP: 8.8.8.8
Prefix: 8.8.8.0/24
ASN: AS15169 (GOOGLE)
Country: US

2. Reachability
----------------------------------------------------------------------
Checking reachability for 8.8.8.8...
Host is reachable
Ping statistics: min=8.123ms, avg=9.456ms, max=10.789ms
Packet loss: 0%

3. Global Routing Table Visibility
----------------------------------------------------------------------
Checking global routing visibility for 8.8.8.0/24 over the last 1 days...

Prefix 8.8.8.0/24 is announced by:
  - ASN: AS15169
  - Network: GOOGLE
  - Country: US

Current and Historical Routing Information:
Analyzing routing data for the period: 2023-06-19 to 2023-06-20

Routing changes analysis:
To check for routing changes over the last 1 days, use these resources:

1. NLNOG Ring looking glass (current routing state):
   - Visit: https://lg.ring.nlnog.net/
   - Select different nodes to get diverse perspectives
   - For your prefix 8.8.8.0/24, use command: 'show ip bgp 8.8.8.0/24'

2. RIPE Stat API Analysis:
   Querying RIPE Stat API for routing information...

Querying RIPE Stat BGPlay API for routing changes...
Analyzing routing changes from 2023-06-19 to 2023-06-20...

Found 12 routing events for 8.8.8.0/24:

Event type summary:
  - A: 10 events
  - W: 2 events

Sample events:
  - 2023-06-19 08:15:23: A event from AS34224
  - 2023-06-19 12:42:17: A event from AS6939
  - 2023-06-19 15:30:05: W event from AS6939
  - 2023-06-19 18:22:41: A event from AS6939
  - 2023-06-20 02:15:18: A event from AS34224

... and 7 more events

Routing stability analysis:
  - Announcements: 10
  - Withdrawals: 2
  - Events per day: 12.0
  - Assessment: High routing activity detected
    This could indicate route flapping or instability

No changes in announcing ASNs during this period

AS Overview Information:
  - AS15169 Holder: GOOGLE
  - Announced Prefixes: 89
  - Resource: AS15169
  - Block: AS15169 - AS15169

Contact Information:
  - Organization: Google LLC
  - Address:
    1600 Amphitheatre Parkway
    Mountain View
    CA 94043
  - NOC Email: noc@google.com
  - NOC Phone: +1-650-253-0000
  - Abuse Email: abuse@google.com
  - Admin Email: dns-admin@google.com

For more details, visit: https://stat.ripe.net/AS15169

  - RIB Visibility Analysis:
    - ASNs with AS15169 in their RIB: 245 (98.0%)
    - ASNs without AS15169 in their RIB: 5 (2.0%)

    - Sample ASNs with AS15169 in their RIB:
      - AS13030
      - AS25152
      - AS34854
      - AS34927
      - AS34984
      - ... and 240 more

    - Sample ASNs without AS15169 in their RIB:
      - AS12654
      - AS31500
      - AS39120
      - AS48362
      - AS50300

  - Origin ASNs:
    - AS15169

  - IRR Sources:
    - RADB
    - RIPE

For more details, visit: https://stat.ripe.net/prefix-routing-consistency#{'resource':'8.8.8.0/24'}

3. bgp.tools for detailed prefix analysis:
   - Visit: https://bgp.tools/prefix/8.8.8.0/24
   - Shows current routing status and prefix details

4. RouteViews Archive for raw historical data:
   - Visit: https://archive.routeviews.org/bgpdata/2023.06/RIBS/
   - Contains raw MRT files that can be analyzed with specialized tools

4. Summary and Recommendations
----------------------------------------------------------------------
Summary:
  - 8.8.8.8 belongs to prefix 8.8.8.0/24 announced by AS15169
  - Network: GOOGLE (US)
  - See reachability section for connectivity details
  - See global routing section for visibility of 8.8.8.0/24

Additional Resources:
  - NLNOG Ring: https://lg.ring.nlnog.net/ (for traceroutes from multiple locations)
  - bgp.tools: https://bgp.tools/prefix/8.8.8.0/24
  - ASN details: https://bgp.tools/as/15169
  - PeeringDB: https://www.peeringdb.com/asn/15169

Report saved to AS15169.txt
```

## Special Cases Handling

The tool provides informative messages for special cases:

### Private IP Addresses
```
NOTE: 192.168.1.1 is a private/special IP address
Private IPs are not announced on the global internet
```

### Non-routable or Unannounced IPs
```
Could not determine prefix information for 203.0.113.1
This may indicate the IP is not announced in the global BGP table
```

### IPv6 Support
```
Resolved example.com to 2606:2800:220:1:248:1893:25c8:1946
IP: 2606:2800:220:1:248:1893:25c8:1946
Prefix: 2606:2800::/32
ASN: AS15133 (EDGECAST)
Country: US
```

## Advanced Usage

### RIPE RIS Looking Glass Data

Use the `--current` flag to include RIPE RIS looking glass data in the report:

```
./run_diagnostics.sh 8.8.8.8 --current
```

When this flag is set, the tool will:
- Query the RIPE Stat Looking Glass API
- Show which RIPE RIS collectors can see your prefix
- Display how many peers report your prefix at each collector
- List sample AS paths to reach your prefix

Without this flag, the tool will skip the looking glass query to provide a more concise report focused on historical data.

### IPv6 Analysis

For IPv6 addresses or to force IPv6 resolution for hostnames:

```
./run_diagnostics.sh 2001:4860:4860::8888
./run_diagnostics.sh google.com --ipv6
```

The tool will:
- Use the appropriate IPv6 whois services
- Adjust ping commands for IPv6 compatibility
- Provide IPv6-specific routing information

### Network Operator Contact Information

The tool extracts and displays comprehensive contact information for network operators:

```
Contact Information:
  - Organization: Google LLC
  - Address:
    1600 Amphitheatre Parkway
    Mountain View
    CA 94043
  - NOC Email: noc@google.com
  - NOC Phone: +1-650-253-0000
  - Abuse Email: abuse@google.com
  - Admin Email: dns-admin@google.com
```

This information is prioritized to show the most operationally relevant contacts first:
1. NOC (Network Operations Center) contacts - critical for urgent operational issues
2. Abuse contacts - for reporting abuse or security issues
3. Administrative and technical contacts - for general inquiries

If NOC contact information isn't found in whois data, the tool suggests checking PeeringDB for additional contact details.

### RIB Visibility Analysis

The tool provides detailed analysis of which ASNs have your ASN in their routing tables:

```
RIB Visibility Analysis:
- ASNs with AS15169 in their RIB: 245 (98.0%)
- ASNs without AS15169 in their RIB: 5 (2.0%)
```

This helps identify potential routing issues where certain networks might not be able to reach your prefix.

### Automatic Report Saving

Reports are automatically saved to a file named after the ASN:

```
Report saved to AS15169.txt
```

You can specify a custom filename with the `--output` option:

```
./run_diagnostics.sh 8.8.8.8 --output custom-report.txt
```

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

## License

This tool is provided under the MIT License.

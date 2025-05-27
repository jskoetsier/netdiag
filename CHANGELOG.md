# Changelog

All notable changes to the Network Diagnostics Tool will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.4.0] - 2024-05-27

### Added
- NOC contact information extraction from whois data
- PeeringDB suggestion when NOC contacts aren't found
- More aggressive peer ASN extraction for better identification

### Changed
- Improved display of contact information to prioritize NOC contacts
- Enhanced peer identification in BGPlay API output
- Better handling of unknown ASNs in looking glass data

### Fixed
- Fixed "Unknown ASN" issues in looking glass API output
- Fixed "Unknown peer" issues in BGPlay API output
- Improved email extraction from whois data

## [1.0.0] - 2023-06-20

### Added
- Initial release of the Network Diagnostics Tool
- Team Cymru whois service integration for prefix and ASN information
- RIPE Stat API integration (Looking Glass, BGPlay, AS Overview, AS Routing Consistency)
- Reachability testing with ping statistics
- Global routing table visibility analysis
- Historical route change analysis
- IPv4 and IPv6 support
- Automatic report saving with ASN-based filenames
- Comprehensive resource links to bgp.tools, NLNOG Ring, etc.
- Command-line options for customization (--period, --ipv6, --current, --output)

## [1.1.0] - 2023-07-15

### Added
- RIB visibility analysis showing which ASNs have your ASN in their routing tables
- Support for custom output filenames with --output option
- Improved error handling for network connectivity issues

### Changed
- Enhanced Team Cymru ASN name resolution for better network identification
- Improved peer ASN extraction logic in RIPE RIS looking glass data
- Updated documentation with more detailed examples

### Fixed
- Fixed issue with IPv6 address handling in ping commands
- Corrected ASN name display for well-known networks

## [1.2.0] - 2023-08-10

### Added
- Routing stability analysis with event categorization
- Detection of route flapping and instability
- Assessment of routing activity levels (low/moderate/high)
- More detailed whois information extraction

### Changed
- Improved formatting of BGP paths for better readability
- Enhanced error messages for failed API requests
- Updated documentation with advanced usage examples

### Fixed
- Fixed timestamp parsing in BGPlay event data
- Corrected percentage calculations in routing analytics

## [1.3.0] - 2023-09-05

### Added
- Geographic distribution analysis of routing visibility
- Sample AS paths showing shortest, medium, and longest paths
- BGP community analysis in routing data
- Alert for multiple origin ASNs (potential prefix hijacking)

### Changed
- Improved performance for large MRT files
- Enhanced output formatting for better readability
- Updated documentation with troubleshooting tips

### Fixed
- Fixed handling of private and special IP addresses
- Corrected path length calculations in routing analytics

## [2.0.0] - 2023-10-20

### Added
- RIPE Stat API integration for more reliable data sources
- AS Overview API for comprehensive ASN details
- AS Routing Consistency API for RIB visibility analysis
- `--current` flag to include RIPE RIS looking glass data in reports

### Changed
- Replaced MRT file download and analysis with direct API queries
- Improved error handling for API rate limits and timeouts
- Enhanced documentation with detailed API information

### Removed
- Dependency on external MRT file processing tools
- Removed bgpdump requirement for historical analysis

### Fixed
- Fixed issues with ASN resolution in peer information
- Corrected date handling in historical data queries

## [2.1.0] - 2023-11-15

### Added
- Automatic report saving with ASN-based filenames
- Enhanced IPv6 support with specialized whois services
- Cross-platform compatibility improvements

### Changed
- Improved error messages for better troubleshooting
- Enhanced documentation with platform-specific instructions
- Updated requirements.txt with version constraints

### Fixed
- Fixed handling of non-routable or unannounced IPs
- Corrected timestamp display in routing events

## [2.2.0] - 2024-01-10

### Added
- Support for analyzing multiple time periods in a single run
- Enhanced routing stability metrics
- More detailed path analysis in routing reports

### Changed
- Improved performance for large routing tables
- Enhanced error handling for network timeouts
- Updated documentation with advanced analysis techniques

### Fixed
- Fixed handling of special characters in ASN names
- Corrected calculation of routing stability metrics

## [2.3.0] - 2025-05-27

### Added
- Detailed installation guide (INSTALL.md)
- Comprehensive changelog (CHANGELOG.md)
- Docker support for containerized deployment

### Changed
- Improved cross-platform compatibility
- Enhanced documentation with more examples
- Updated requirements for better dependency management

### Fixed
- Fixed issues with proxy handling in API requests
- Corrected formatting in saved report files

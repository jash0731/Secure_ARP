# Changes in version 2.0

## Added

- Automatically refreshed local dashboard with activity and category charts.
- Search, severity/type/mode/source/date filters and event pagination.
- Persistent SQLite storage for events, device observations, labels, trust baselines and approvals.
- Device review, approval replacement, and approval removal.
- Filtered CSV exports and printable HTML reports.
- Optional desktop notifications and sound with cooldown.
- Validated JSON configuration with paths relative to the configuration file.
- Isolated PCAP and PCAPNG analysis using capture timestamps.
- New demonstration scenarios, a synthetic sample capture and updated reports.
- Windows and Unix demo launchers.

## Corrected

- Replay detection rejects duplicate authenticated messages within the freshness window.
- Replay state persists across capture-engine restarts.
- Flood detection no longer hides simultaneous authentication or binding conflicts.
- MAC changes require explicit review after the learning window expires.
- Ethernet padding and VLAN-tagged ARP replies are parsed in the offline pipeline.
- Malformed live replies do not stop the capture monitor.
- Reports escape untrusted text; CSV output neutralizes formula prefixes.
- Local mutation endpoints validate a per-session token and request origin.
- Documentation distinguishes application trust validation from operating-system ARP enforcement.

## Compatibility

- Existing module commands are retained.
- SpoofDetector.process still returns one primary event; process_all returns every finding.
- Authentication now uses a versioned 45-byte nonce-bearing trailer. Original 24-byte trailers are rejected.
- Flood event type changed from GRATUITOUS_ARP_FLOOD to ARP_REPLY_FLOOD.
- Existing old JSON logs are not automatically migrated into the new SQLite history.
- Python 3.10 or newer is required.

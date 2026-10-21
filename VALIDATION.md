# Validation of the updated project

## Executed checks

- 46 automated tests passed with pytest.
- Python modules compiled successfully.
- JavaScript syntax checked with Node.
- The in-memory demonstration completed and generated reports, a chart and a sample capture.
- The sample PCAP was analyzed successfully in standard mode.
- Automated tests also analyzed secure historical captures and PCAPNG.
- Real local HTTP requests exercised the dashboard, JSON state, filtering, export downloads, device approval/removal and demonstration endpoints.

## Security and behavior covered

- Duplicate authenticated replies within the freshness window.
- Replay detection after the capture engine restarts.
- Independent nonces for replies with identical timestamps.
- Sender IP/MAC tampering, missing tags, invalid tags and nonfinite timestamps.
- Replay-cache capacity and expiry behavior.
- Simultaneous flood, authentication-failure and MAC-conflict findings.
- MAC changes after the learning window expires.
- Persistent approvals and changes picked up by an existing engine.
- Rejected observations remaining visible without becoming approved.
- Recorded packet timestamps used for offline rate and authentication checks.
- Ethernet padding, VLAN headers, truncated frames and PCAPNG input.
- Filtered report output, HTML escaping and CSV formula-prefix handling.
- Local request host validation, mutation tokens, origin checks and invalid input handling.
- Demo controls unavailable in the live workspace.
- Existing capture-analysis output protected from accidental overwrite.

## Environment

- Python 3.12
- Scapy 2.7.0
- Rich 15.0.0
- Matplotlib 3.10.8
- pytest 9.1.1

The project targets Python 3.10 and newer. Other supported interpreter versions and Windows/Npcap capture were not executed in this environment.

## Remaining manual checks

- Live network capture requires a machine and interface with capture permissions. No live network packets were captured or transmitted during validation.
- Browser visual rendering and desktop notification/audio behavior need a browser check. A browser binary could not be installed in the build environment, so no successful browser automation pass is claimed.
- The tests exercise the monitor's shared parsing/detection workflow, not operating-system ARP enforcement. Such enforcement is not part of this project.

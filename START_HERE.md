# Run your updated Secure ARP project

Requires Python 3.10 or later.

## 1. Extract the ZIP

Open a terminal inside the extracted folder that contains config.json and the secure_arp folder.

## 2. Open the interactive demonstration

~~~bash
python -m secure_arp --demo
~~~

On Windows, you can also double-click start_demo.bat.

Open http://127.0.0.1:8765 in your browser. Keep the terminal open.

The interactive demo uses Python's standard library, so this command does not need administrator access or third-party packages. It does not send network traffic.

## 3. Try the new features

1. Use **Run demonstration** to generate a comparison between standard and secure modes.
2. Filter Event history by IP, severity, event type, mode, source, or time.
3. Select **CSV** or **Report** to download the filtered results.
4. Open **Devices**, review a mapping, give it a name, and select **Save approval**.
5. Enable notifications or sound if you want alerts for new critical events while the page is open.
6. Open **Settings** to inspect the detection thresholds.

Demo data and approvals are separate from your real monitoring workspace.

## 4. Install the complete project's dependencies

~~~bash
python -m pip install -r requirements.txt
~~~

## 5. Generate demonstration files

~~~bash
python -m secure_arp.demo_harness
~~~

This creates a sample packet capture, HTML and CSV reports, and charts. Pre-generated examples are included in reports/demo and assets.

## 6. Analyze the sample capture

~~~bash
python -m secure_arp.pcap_analyzer reports/demo/sample_arp.pcap
~~~

The command prints the path to a new HTML report. Each analysis uses its own database and does not change your live device approvals.

For actual network monitoring, authentication setup, configuration details, and tests, read README.md.

import xml.etree.ElementTree as ET
import csv
import argparse
import os

def parse_nessus_file(nessus_file, port_filter, severity_filter, plugin_filter, output_file):
    tree = ET.parse(nessus_file)
    root = tree.getroot()

    result_list = []

    # Iterate through each ReportHost block
    for report_host in root.findall(".//ReportHost"):
        host_ip = None
        host_fqdn = None

        # Retrieve IP and FQDN from HostProperties block
        for tag in report_host.findall(".//HostProperties/tag"):
            if tag.get('name') == 'host-ip':
                host_ip = tag.text
            if tag.get('name') == 'host-fqdn':
                host_fqdn = tag.text

        # Iterate through ReportItems to check for ports and filter by severity or plugin
        for report_item in report_host.findall(".//ReportItem"):
            port = report_item.get('port')
            severity = int(report_item.get('severity'))  # Severity as an integer
            plugin_name = report_item.get('pluginName')

            # Check if the severity meets the filter and if the plugin name matches (if provided)
            if severity >= severity_filter and (not plugin_filter or plugin_filter.lower() in plugin_name.lower()):
                # Only filter by port if one is specified
                if not port_filter or port == port_filter:
                    findings_text = plugin_name
                    fqdn_text = host_fqdn if host_fqdn else ""
                    result_list.append([host_ip, fqdn_text, port, findings_text])

    # Determine file format based on extension (default to csv)
    if output_file.endswith(".txt"):
        file_format = "txt"
    elif output_file.endswith(".csv") or not os.path.splitext(output_file)[1]:
        file_format = "csv"
    else:
        file_format = "csv"

    # Save the results to a file in the specified format
    if file_format == 'csv':
        with open(output_file, mode='w', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(["IP", "FQDN", "Port", "Findings"])
            writer.writerows(result_list)
    else:  # Save as txt
        with open(output_file, mode='w') as file:
            for result in result_list:
                file.write(f"{result[0]},{result[1]},{result[2]},{result[3]}\n")

    print(f"Results saved to {output_file}")

# Argument parsing for command-line usage
def main():
    parser = argparse.ArgumentParser(description="Parse Nessus XML file to extract data by port, severity, and plugin name.")
    parser.add_argument('-i', '--input', required=True, help="Path to the Nessus XML file")
    parser.add_argument('-p', '--port', help="Port to filter (e.g., '80'). If not set, processes all ports.")
    parser.add_argument('-s', '--severity', type=int, default=0, help="Severity filter (0=Info, 1=Low, 2=Medium, 3=High, 4=Critical)")
    parser.add_argument('-n', '--plugin', help="Plugin name filter (optional)")
    parser.add_argument('-o', '--output', required=True, help="Output file path (.txt or .csv). Defaults to CSV if no extension.")

    args = parser.parse_args()

    # Run the parser function with provided arguments
    parse_nessus_file(args.input, args.port, args.severity, args.plugin, args.output)

if __name__ == "__main__":
    main()

import xml.etree.ElementTree as ET
import csv
import argparse

def parse_nessus_file(nessus_file, port_filter, severity_filter, output_file, output_format):
    tree = ET.parse(nessus_file)
    root = tree.getroot()

    result_list = []

    # Iterate through each ReportHost block
    for report_host in root.findall(".//ReportHost"):
        host_ip = None
        host_fqdn = None
        findings = []

        # Retrieve IP and FQDN from HostProperties block
        for tag in report_host.findall(".//HostProperties/tag"):
            if tag.get('name') == 'host-ip':
                host_ip = tag.text
            if tag.get('name') == 'host-fqdn':
                host_fqdn = tag.text

        # Iterate through ReportItems to check for the specific port and filter by severity
        for report_item in report_host.findall(".//ReportItem"):
            port = report_item.get('port')
            severity = int(report_item.get('severity'))  # Severity as an integer
            plugin_name = report_item.get('pluginName')

            # Check if the port matches and severity meets the filter
            if port == port_filter and severity >= severity_filter:
                findings.append(plugin_name)

        # Only add the host if there are findings for the port
        if findings:
            fqdn_text = host_fqdn if host_fqdn else ""
            findings_text = "; ".join(findings)
            result_list.append([host_ip, fqdn_text, findings_text])

    # Save the results to a file in the specified format
    if output_format == 'csv':
        with open(output_file, mode='w', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(["IP", "FQDN", "Findings"])
            writer.writerows(result_list)
    else:  # Save as txt
        with open(output_file, mode='w') as file:
            for result in result_list:
                file.write(f"{result[0]},{result[1]},{result[2]}\n")

    print(f"Results saved to {output_file}")

# Argument parsing for command-line usage
def main():
    parser = argparse.ArgumentParser(description="Parse Nessus XML file to extract data by port and severity.")
    parser.add_argument('-i', '--input', required=True, help="Path to the Nessus XML file")
    parser.add_argument('-p', '--port', required=True, help="Port to filter (e.g., '80')")
    parser.add_argument('-s', '--severity', type=int, default=0, help="Severity filter (0=Info, 1=Low, 2=Medium, 3=High, 4=Critical)")
    parser.add_argument('-o', '--output', required=True, help="Output file path")
    parser.add_argument('-f', '--format', choices=['csv', 'txt'], default='csv', help="Output format (csv or txt)")

    args = parser.parse_args()

    # Run the parser function with provided arguments
    parse_nessus_file(args.input, args.port, args.severity, args.output, args.format)

if __name__ == "__main__":
    main()

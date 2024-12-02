#!/bin/bash

import os
from openai import OpenAI

client = OpenAI(api_key='') # Put your API key here

def read_logs(file_paths):
    """
    Reads logs from the given file paths.

    Parameters:
        file_paths (list): List of file paths to read logs from.

    Returns:
        list: A list of log entries.
    """
    logs = []
    for path in file_paths:
        if os.path.exists(path):
            try:
                with open(path, 'r') as file:
                    logs.extend(file.readlines())
            except Exception as e:
                print(f"Error reading {path}: {e}")
        else:
            print(f"Log file not found: {path}")
    return logs

def analyze_log_entry(log_entry):
    """
    Analyzes a single log entry using OpenAI's API.

    Parameters:
        log_entry (str): The log entry to analyze.

    Returns:
        str: Analysis result from OpenAI.
    """
    messages = [
        {
            "role": "system",
            "content": (
                "You are a cybersecurity expert analyzing log entries for malicious or strange activity, "
                "specifically looking for:\n"
                "- DNS requests to the artifex.co.il domain\n"
                "- Connections to S3 buckets with unusual names\n"
                "- Creation of users, especially administrative ones\n"
            )
        },
        {
            "role": "user",
            "content": (
                f"Log Entry:\n{log_entry}\n\n"
                "Does this log entry indicate any of these activities? If yes, please provide details and relevant Sigma signatures."
            )
        }
    ]

    try:
        response = client.chat.completions.create(model="gpt-3.5-turbo",  # Use 'gpt-4' if you have access
        messages=messages,
        max_tokens=150,
        temperature=0,
        n=1,
        stop=None)
        analysis = response.choices[0].message.content.strip()
        return analysis
    except Exception as e:
        print(f"Error analyzing log entry: {e}")
        return None

def main():
    my_path = os.path.dirname(os.path.abspath(__file__))
    project_root_folder = os.path.dirname(my_path)
    logs_path = os.path.join(project_root_folder, "tmp", "logs")

    # List of log file paths
    log_files = [
        os.path.join(logs_path, "zeek", ".rotated.conn"),
        os.path.join(logs_path, "zeek", "dhcp.log"),
        os.path.join(logs_path, "zeek", "http.log"),
        os.path.join(logs_path, "zeek", ".pid"),
        os.path.join(logs_path, "zeek", "analyzer.log"),
        os.path.join(logs_path, "zeek", ".rotated.dhcp"),
        os.path.join(logs_path, "zeek", ".rotated.ocsp"),
        os.path.join(logs_path, "zeek", "quic.log"),
        os.path.join(logs_path, "zeek", "capture_loss.log"),
        os.path.join(logs_path, "zeek", "stderr.log"),
        os.path.join(logs_path, "zeek", ".rotated.ssl"),
        os.path.join(logs_path, "zeek", "stdout.log"),
        os.path.join(logs_path, "zeek", ".env_vars"),
        os.path.join(logs_path, "zeek", ".rotated.conn-summary"),
        os.path.join(logs_path, "zeek", ".status"),
        os.path.join(logs_path, "zeek", "conn.log"),
        os.path.join(logs_path, "zeek", "dns.log"),
        os.path.join(logs_path, "zeek", ".cmdline"),
        os.path.join(logs_path, "zeek", ".rotated.quic"),
        os.path.join(logs_path, "zeek", ".rotated.weird"),
        os.path.join(logs_path, "zeek", "stats.log"),
        os.path.join(logs_path, "zeek", ".rotated.stats"),
        os.path.join(logs_path, "zeek", ".rotated.x509"),
        os.path.join(logs_path, "zeek", ".rotated.files"),
        os.path.join(logs_path, "zeek", ".rotated.http"),
        os.path.join(logs_path, "zeek", "ssl.log"),
        os.path.join(logs_path, "zeek", ".rotated.telemetry"),
        os.path.join(logs_path, "zeek", "ocsp.log"),
        os.path.join(logs_path, "zeek", ".rotated.packet_filter"),
        os.path.join(logs_path, "zeek", "notice.log"),
        os.path.join(logs_path, "zeek", ".startup"),
        os.path.join(logs_path, "zeek", "files.log"),
        os.path.join(logs_path, "zeek", ".rotated.dpd"),
        os.path.join(logs_path, "zeek", ".rotated.notice"),
        os.path.join(logs_path, "zeek", "telemetry.log"),
        os.path.join(logs_path, "zeek", ".rotated.capture_loss"),
        os.path.join(logs_path, "zeek", ".rotated.dns"),
        os.path.join(logs_path, "zeek", ".rotated.ntp"),
        os.path.join(logs_path, "zeek", "weird.log"),
        os.path.join(logs_path, "zeek", ".rotated.analyzer"),
        os.path.join(logs_path, "zeek", ".rotated.reporter"),
        os.path.join(logs_path, "zeek", "dpd.log"),
        os.path.join(logs_path, "zeek", ".rotated.known_services"),
        os.path.join(logs_path, "zeek", ".rotated.loaded_scripts"),
        os.path.join(logs_path, "zeek-2", "http.log"),
        os.path.join(logs_path, "zeek-2", "reporter.log"),
        os.path.join(logs_path, "zeek-2", ".pid"),
        os.path.join(logs_path, "zeek-2", "capture_loss.log"),
        os.path.join(logs_path, "zeek-2", "stderr.log"),
        os.path.join(logs_path, "zeek-2", "stdout.log"),
        os.path.join(logs_path, "zeek-2", ".env_vars"),
        os.path.join(logs_path, "zeek-2", ".status"),
        os.path.join(logs_path, "zeek-2", "conn.log"),
        os.path.join(logs_path, "zeek-2", "dns.log"),
        os.path.join(logs_path, "zeek-2", ".cmdline"),
        os.path.join(logs_path, "zeek-2", "loaded_scripts.log"),
        os.path.join(logs_path, "zeek-2", "ntp.log"),
        os.path.join(logs_path, "zeek-2", "stats.log"),
        os.path.join(logs_path, "zeek-2", "known_services.log"),
        os.path.join(logs_path, "zeek-2", "ssl.log"),
        os.path.join(logs_path, "zeek-2", "notice.log"),
        os.path.join(logs_path, "zeek-2", ".startup"),
        os.path.join(logs_path, "zeek-2", "packet_filter.log"),
        os.path.join(logs_path, "zeek-2", "files.log"),
        os.path.join(logs_path, "zeek-2", "telemetry.log"),
        os.path.join(logs_path, "zeek-2", "weird.log"),

        os.path.join(logs_path, "suricata", "eve.json"),
        os.path.join(logs_path, "suricata", "stats.log"),
        os.path.join(logs_path, "suricata", "fast.log"),
        os.path.join(logs_path, "suricata", "suricata.log"),

        os.path.join(logs_path, "wazuh", "cluster.log"),
        os.path.join(logs_path, "wazuh", "ossec.log"),
        os.path.join(logs_path, "wazuh", "api.log"),

        os.path.join(logs_path, "os", "auth2.log"),
        os.path.join(logs_path, "os", "syslog2"),
        os.path.join(logs_path, "os", "syslog"),
        os.path.join(logs_path, "os", "auth.log"),
        os.path.join(logs_path, "os", "audit.log")
    ]

    # Read logs from all specified files
    logs = read_logs(log_files)

    # Analyze each log entry
    for log_entry in logs:
        analysis = analyze_log_entry(log_entry)
        if analysis and 'yes' in analysis.lower():
            print("Potential malicious activity detected:")
            print(f"Log Entry: {log_entry}")
            print(f"Analysis: {analysis}")
            print("-" * 80)

if __name__ == '__main__':
    main()

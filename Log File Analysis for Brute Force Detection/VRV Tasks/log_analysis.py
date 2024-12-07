import csv
import re
from collections import Counter, defaultdict

# Configuration: Threshold for suspicious activity
FAILED_LOGIN_THRESHOLD = 10

def parse_log_file(file_path):
    """
    Reads the log file and returns its contents line by line.
    """
    try:
        with open(file_path, 'r') as file:
            return file.readlines()
    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found.")
        return []

def count_requests_per_ip(log_lines):
    """
    Counts the number of requests made by each IP address.
    """
    ip_pattern = re.compile(r'^\S+')  # Matches the IP address at the start of each line
    ip_counter = Counter()

    for line in log_lines:
        match = ip_pattern.search(line)
        if match:
            ip_counter[match.group()] += 1

    return ip_counter

def find_most_accessed_endpoint(log_lines):
    """
    Identifies the most frequently accessed endpoint in the log.
    """
    endpoint_pattern = re.compile(r'\"[A-Z]+\s(\S+)\sHTTP')  # Matches endpoints in the log
    endpoint_counter = Counter()

    for line in log_lines:
        match = endpoint_pattern.search(line)
        if match:
            endpoint_counter[match.group(1)] += 1

    most_accessed = endpoint_counter.most_common(1)
    return most_accessed[0] if most_accessed else None

def detect_suspicious_activity(log_lines, threshold=FAILED_LOGIN_THRESHOLD):
    """
    Identifies IPs with failed login attempts exceeding the threshold.
    """
    suspicious_ips = defaultdict(int)
    failed_login_pattern = re.compile(r'401|Invalid credentials')  # Modify as needed

    for line in log_lines:
        if failed_login_pattern.search(line):
            ip = line.split()[0]  # Assuming IP is the first token in the log
            suspicious_ips[ip] += 1

    flagged_ips = {ip: count for ip, count in suspicious_ips.items() if count > threshold}
    return flagged_ips

def save_results_to_csv(results, file_name):
    """
    Saves the results to a CSV file.
    """
    with open(file_name, 'w', newline='') as file:
        writer = csv.writer(file)

        # Write Requests per IP
        writer.writerow(["IP Address", "Request Count"])
        for ip, count in results['requests_per_ip'].items():
            writer.writerow([ip, count])

        writer.writerow([])  # Blank line

        # Write Most Accessed Endpoint
        writer.writerow(["Endpoint", "Access Count"])
        if results['most_accessed_endpoint']:
            writer.writerow(results['most_accessed_endpoint'])

        writer.writerow([])  # Blank line

        # Write Suspicious Activity
        writer.writerow(["IP Address", "Failed Login Count"])
        for ip, count in results['suspicious_activity'].items():
            writer.writerow([ip, count])

def main():
    log_file_path = input("Enter the path to the log file (e.g., sample.log): ").strip()
    log_lines = parse_log_file(log_file_path)

    if not log_lines:
        return

    # Analysis
    requests_per_ip = count_requests_per_ip(log_lines)
    most_accessed_endpoint = find_most_accessed_endpoint(log_lines)
    suspicious_activity = detect_suspicious_activity(log_lines)

    # Display Results
    print("\nRequests per IP Address:")
    for ip, count in requests_per_ip.most_common():
        print(f"{ip:<20} {count}")

    if most_accessed_endpoint:
        print("\nMost Frequently Accessed Endpoint:")
        print(f"{most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)")

    print("\nSuspicious Activity Detected:")
    for ip, count in suspicious_activity.items():
        print(f"{ip:<20} {count}")

    # Save Results to CSV
    results = {
        'requests_per_ip': requests_per_ip,
        'most_accessed_endpoint': most_accessed_endpoint,
        'suspicious_activity': suspicious_activity
    }
    save_results_to_csv(results, 'log_analysis_results.csv')
    print("\nResults saved to log_analysis_results.csv")

if __name__ == "__main__":
    main()

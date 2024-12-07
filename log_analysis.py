import csv
from collections import defaultdict

# Function to parse the log file and perform log analysis
def analyze_log(log_file, output_csv, failed_login_threshold=10):
    ip_request_counts = defaultdict(int)
    endpoint_access_counts = defaultdict(int)
    failed_logins = defaultdict(int)
    
    # Read and process the log file
    with open(log_file, 'r') as file:
        for line in file:
            # Extract IP address
            ip = line.split()[0]
            ip_request_counts[ip] += 1
            
            # Extract endpoint
            if '"' in line:
                try:
                    request_part = line.split('"')[1]
                    endpoint = request_part.split()[1]
                    endpoint_access_counts[endpoint] += 1
                except IndexError:
                    continue
            
            # Detect failed login attempts (status code 401)
            if "401" in line or "Invalid credentials" in line:
                failed_logins[ip] += 1

    # Find the most frequently accessed endpoint
    most_accessed_endpoint = max(endpoint_access_counts, key=endpoint_access_counts.get)
    most_accessed_count = endpoint_access_counts[most_accessed_endpoint]

    # Identify suspicious activity
    suspicious_ips = {ip: count for ip, count in failed_logins.items() if count > failed_login_threshold}

    # Print results
    print("\nRequests per IP Address:")
    print(f"{'IP Address':<20}{'Request Count':<15}")
    for ip, count in sorted(ip_request_counts.items(), key=lambda x: x[1], reverse=True):
        print(f"{ip:<20}{count:<15}")

    print("\nMost Frequently Accessed Endpoint:")
    print(f"{most_accessed_endpoint} (Accessed {most_accessed_count} times)")

    print("\nSuspicious Activity Detected:")
    if suspicious_ips:
        print(f"{'IP Address':<20}{'Failed Login Attempts':<25}")
        for ip, count in suspicious_ips.items():
            print(f"{ip:<20}{count:<25}")
    else:
        print("No suspicious activity detected.")

    # Save results to CSV
    with open(output_csv, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        
        # Write IP requests
        writer.writerow(["Requests per IP"])
        writer.writerow(["IP Address", "Request Count"])
        for ip, count in sorted(ip_request_counts.items(), key=lambda x: x[1], reverse=True):
            writer.writerow([ip, count])

        # Write most accessed endpoint
        writer.writerow([])
        writer.writerow(["Most Accessed Endpoint"])
        writer.writerow(["Endpoint", "Access Count"])
        writer.writerow([most_accessed_endpoint, most_accessed_count])

        # Write suspicious activity
        writer.writerow([])
        writer.writerow(["Suspicious Activity"])
        writer.writerow(["IP Address", "Failed Login Count"])
        for ip, count in suspicious_ips.items():
            writer.writerow([ip, count])


# Main function to run the script
if __name__ == "__main__":
    # Log file and output CSV file names
    log_file = "sample.log"
    output_csv = "log_analysis_results.csv"
    
    # Run the analysis
    analyze_log(log_file, output_csv)

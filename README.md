**Log File Analysis for Brute Force Detection**

**Overview**

This Python script analyzes web server logs to:

1. Count requests per IP address
2. Identify the most accessed endpoint
3. Detect potential brute force login attempts based on failed login thresholds.
   
**Features**
1. IP Request Count: Tracks how many requests each IP has made.
2. Most Accessed Endpoint: Identifies the most visited URL.
3. Brute Force Detection: Flags IPs with excessive failed login attempts.
   
**Requirements**
1. Python 3
2. Log file (e.g., access logs with IP, method, endpoint, status code)
   
**Usage**
1. Update the log file path and threshold.
2. Run the script to analyze and display the results.

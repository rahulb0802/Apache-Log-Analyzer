import re
from collections import defaultdict
from datetime import datetime
import seaborn as sb
import matplotlib.pyplot as plt
import tkinter as tk

# Regular expression to parse Apache log lines
log_pattern = re.compile(r'(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) - - \[(?P<date>[^\]]+)\] "(?P<request>[^"]+)" (?P<status>\d{3}) (?P<size>\d+)')

# Initialize buttons and window for options
root = tk.Tk()
v = tk.StringVar()

# Go through log lines
def parse_log_line(line):
    match = log_pattern.match(line)
    if match:
        return match.groupdict()
    return None


# Used for checking
restricted_pages = ['/admin','/config']
sql_patterns = ["' OR '1'='1", "'--", "UNION SELECT"]

def analyze_log(file):
    # Dicts for each activity
    failed_logins = defaultdict(int)
    restricted_access_att = defaultdict(int)
    unusual_statuses = defaultdict(int)
    request_times = defaultdict(list)
    injection_att = defaultdict(int)
    successful_injection = defaultdict(int)
    unauth_msg = []
    with open(file, 'r') as f:
        for line in f:
            log_entry = parse_log_line(line)
            if log_entry:
                ip = log_entry['ip']
                status = log_entry['status']
                request = log_entry['request']
                date_str = log_entry['date']
                date_obj = datetime.strptime(date_str, '%d/%b/%Y:%H:%M:%S %z')
                request_times[ip].append(date_obj)
                
                # Unusual Status code checking
                if status in ['500', '404']:
                    unusual_statuses[(ip, status)] += 1

                # Failed login attempts
                if status == '401' and "login" in request.lower():
                    failed_logins[ip] += 1
                    
                # SQL injection and successful attempts
                if any(pattern in request for pattern in sql_patterns):
                    injection_att[ip] += 1
                    if status == '200' and 'login' in request.lower():
                        successful_injection[ip] += 1
                        unauth_msg.append(f"IP {ip} gained unauthorized access through SQL injection")
                
                # Attempting access to restricted pages
                for area in restricted_pages:
                    if area in request:
                        restricted_access_att[ip] += 1

    # for (ip, status), count in unusual_statuses.items():
    #     print(f"IP {ip} returned status {status} {count} times")

    # for ip, attempts in failed_logins.items():
    #     if attempts >= 4:
    #         print(f"IP {ip} has made {attempts} failed login attempts")
    
    # for ip, count in injection_att.items():
    #     print(f"SQL Injection attempt detected: IP {ip} attempted {count} times")
        
    # for ip, count in successful_injection.items():
    #     print(f"IP {ip} gained unauthorized access {count} times")

    # for ip, attempts in restricted_access_att.items():
    #     if attempts > 0:
    #         print(f"IP {ip} has tried to access restricted pages {attempts} times")
    
    # for ip, times in request_times.items():
    #     times.sort()
    #     for i in range(1, len(times)):
    #         if (times[i] - times[i-1]).seconds < 10:  
    #             print(f"IP {ip} made {len(times)} requests within a short time")
    #             break
    plot_activity(failed_logins, unusual_statuses, injection_att, successful_injection, restricted_access_att, request_times)

def plot_activity(failed_logins, unusual_statuses, injection_att, successful_injection, restricted_access_att, request_times):
    def submit_option():
        
        # Retrieves data and sets title and labels based on option selected
        selected_option = v.get()
        match selected_option:
            case 'failed logins':
                title = 'Failed Login Attempts by IP'
                y_label = 'Number of Failed Login Attempts'
                plot_data = failed_logins
            case 'unusual statuses':
                title = 'Unusual Status Codes by IP'
                y_label = 'Occurence of Unusual Status Codes'
                plot_data = {f"{ip} - {status}": count for (ip, status), count in unusual_statuses.items()}
            case 'sql injection attempts':
                title = 'SQL Injection Attempts by IP'
                y_label = 'Number of SQL Injection Attempts'
                plot_data = injection_att
            case 'unauthorized access':
                title = 'Unauthorized Accesses by IP (SQL Injection)'
                y_label = 'Number of Unauthorized Accesses'
                plot_data = successful_injection
            case 'restricted page accesses':
                title = 'Accesses to Restricted Pages by IP'
                y_label = 'Number of Accesses to Restricted Pages'
                plot_data = restricted_access_att
            case 'high number of requests':
                title = 'IPs with High Number of Requests (Potential DDoS)'
                y_label = 'Number of Requests'
                plot_data = {ip: len(times) for ip, times in request_times.items() if len(times) >= 3}
            case _:
                return

        # Plotting chart    
        ips = list(plot_data.keys())
        counts = list(plot_data.values())
        plt.figure(figsize=(10,6))
        sb.barplot(x=ips, y=counts)
        plt.xlabel('IP Address')
        plt.ylabel(y_label)
        plt.title(title)
        plt.xticks(rotation=45)
        plt.tight_layout()
        plt.show()

    # Making window and buttons
    print('Open new button window to see activity viewing options')
    tk.Label(root, text="Select activity to view:").pack()
    tk.Radiobutton(root, text="Failed Logins", variable=v, value='failed logins').pack()
    tk.Radiobutton(root, text="Unusual Status Codes", variable=v, value='unusual statuses').pack()
    tk.Radiobutton(root, text="SQL Injection Attempts", variable=v, value='sql injection attempts').pack()
    tk.Radiobutton(root, text="Unauthorized Accesses", variable=v, value='unauthorized access').pack()
    tk.Radiobutton(root, text="Restricted Page Accesses", variable=v, value='restricted page accesses').pack()
    tk.Radiobutton(root, text="Unusually High Number of Requests", variable=v, value='high number of requests').pack()
    tk.Button(root, text="Submit", command=submit_option).pack()

    root.mainloop()

    
logs = 'sample_logs.txt'
analyze_log(logs)

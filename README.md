<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body>
    <h1>Log Analyzer</h1>
    <p>This Python project analyzes Apache log files to identify various activities and anomalies. The script parses log entries to detect failed login attempts, unusual status codes, SQL injection attempts, unauthorized access, and access to restricted pages. It also provides visualization options for the analyzed data using Tkinter, Matplotlib, and Seaborn.</p>
    <h2>Features</h2>
    <ul>
        <li>Parses Apache log lines to extract IP addresses, request details, status codes, and other relevant data.</li>
        <li>Detects and counts failed login attempts, unusual status codes, SQL injection attempts, unauthorized access, and restricted page access.</li>
        <li>Visualizes the analyzed data using Matplotlib and Seaborn for various activities.</li>
        <li>Provides an interactive Tkinter GUI to select and view different types of data visualizations.</li>
    </ul>
    <h2>Tools Used</h2>
    <ul>
        <li><strong>Python:</strong> Language used for scripting.</li>
        <li><strong>Matplotlib:</strong> For generating data visualizations.</li>
        <li><strong>Seaborn:</strong> For advanced data visualization.</li>
        <li><strong>Tkinter:</strong> For creating the GUI interface.</li>
    </ul>
    <h2>Example Log File</h2>
    <p>An example of a log entry format that the analyzer can parse:</p>
    <pre><code>192.168.1.10 - - [01/Sep/2024:12:23:05 +0000] "POST /login?user=admin&password=password123 HTTP/1.1" 200 1024</code></pre>
  <p>Sample logs are included in the project.</p>
</body>
</html>

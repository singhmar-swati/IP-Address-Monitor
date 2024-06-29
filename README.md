# IP Address Monitor
**Description:**

This project monitors network traffic for blacklisted IP addresses, extracts geographical information, and sends notification emails for detected abuses. It generates a detailed report and visualizes IP addresses on Google Maps.

**Features**

1. IP Parsing: Reads and analyzes network traffic from a PCAP file.
2. Geolocation: Retrieves geographical information using GeoLiteCity database.
3. Reporting: Generates detailed reports including timestamps and geographical data.
4. WHOIS Lookup: Extracts email addresses from WHOIS records.
5. Email Notification: Sends email notifications for detected abuses.
6. KML File Creation: Generates a KML file to visualize IP addresses on Google Maps.

   
**Technologies Used**
1. Python
2. PyGeoIP
3. Scapy
4. SimpleKML
5. IPWhoisSMTP

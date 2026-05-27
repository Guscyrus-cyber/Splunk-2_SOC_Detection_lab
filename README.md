
Splunk SIEM Lab – Failed Login Detection & Analysis\
\
Splunk is a data analytics and monitoring platform that collects, indexes, and searches machine-generated logs to help users analyze events and detect issues.\
\
This project demonstrates a hands-on Splunk SIEM lab where log data is generated, ingested, indexed, and analyzed to simulate a real-world security investigation focused on detecting suspicious activity such as repeated failed login attempts. Using Splunk Enterprise on macOS, a custom dataset (test.log) containing failed and successful login events was uploaded into the main index and analyzed through SPL queries, data correlation, and visualizations. The lab showcases the complete SIEM workflow of log generation, ingestion, indexing, detection, and analysis by identifying suspicious login patterns, top attacker IP addresses, and user activity trends. Queries such as failed login detection, top source IP analysis, user correlation, and event categorization were used alongside Splunk visualizations like bar charts and pie charts to transform raw log data into actionable security insights. This project demonstrates practical SOC analyst skills including log ingestion, SPL query writing, threat detection, event correlation, and security event visualization within a simulated real-world investigation environment.\
\
MacBookPro:~ ghasemmirzaei\$ cat test.log

failed login user=admin src_ip=192.168.1.10

error accessing system file

successful login user=root

failed login user=admin src_ip=192.168.1.10

failed login user=admin src_ip=192.168.1.10

failed login user=admin src_ip=192.168.1.10

failed login user=root src_ip=192.168.1.20

failed login user=root src_ip=192.168.1.20

failed login user=guest src_ip=10.0.0.5

failed login user=guest src_ip=10.0.0.5

failed login user=guest src_ip=10.0.0.5

failed login user=guest src_ip=10.0.0.5

successful login user=admin src_ip=192.168.1.10

successful login user=root src_ip=192.168.1.20

error accessing secure file src_ip=172.16.0.3

MacBookPro:~ ghasemmirzaei\$\
\
I also have another file named test_1.log, but for the purpose of this Splunk Enterprise demonstration and the queries being used, the focus is specifically on analyzing data from test.log only.

MacBookPro:~ ghasemmirzaei\$ cat test_1.log

failed login user=admin src_ip=192.168.1.10

failed login user=admin src_ip=192.168.1.10

failed login user=admin src_ip=192.168.1.10

failed login user=root src_ip=192.168.1.20

failed login user=root src_ip=192.168.1.20

failed login user=guest src_ip=10.0.0.5

failed login user=guest src_ip=10.0.0.5

failed login user=guest src_ip=10.0.0.5

failed login user=guest src_ip=10.0.0.5

successful login user=admin src_ip=192.168.1.10

successful login user=root src_ip=192.168.1.20

error accessing secure file src_ip=172.16.0.3

MacBookPro:~ ghasemmirzaei\$\
\
When I run the search index=main, Splunk retrieves and displays all events that were indexed in the main index, which is why I see multiple entries from different times and sources (such as test.log, test_1.log, and full file paths), including grouped log lines and extracted fields like src_ip, user, and host, because Splunk is showing every piece of data it has stored under that index regardless of file name or specific filter.


By running the query index=main source="test.log", I am demonstrating how to retrieve and focus on all events specifically generated from the file test.log within the main index, and the output shows timestamped log entries such as failed logins, successful logins, and error messages grouped together as events, while the left-side “Selected Fields” panel displays key metadata fields like host, source, and sourcetype, which indicate the machine that generated the data (MacBookPro), the file it came from (test.log), and how Splunk categorized the data, and the “Interesting Fields” such as src_ip, user, timestamp, and index show automatically extracted values from the raw logs, confirming that Splunk has parsed the unstructured log data into structured, searchable fields that allow analysis of patterns like repeated failed login attempts from the same IP address.


By running the query index=main source="test.log" "failed login", I am demonstrating how to filter the log data to display only events that contain failed login attempts within the file test.log, and the output shows the relevant timestamped events where multiple failed login activities occurred for different users (such as admin, root, and guest) along with their corresponding src_ip addresses, while still showing metadata fields like host=MacBookPro, source=test.log, and sourcetype=test.log, which confirms that Splunk is narrowing down the dataset to only security-relevant events and allowing me to clearly observe patterns such as repeated failed login attempts from specific IP addresses.


By running the query index=main source="test.log" \| stats count by src_ip \| sort - count, I am demonstrating how to analyze the log data to identify which source IP addresses are generating the most activity in the file test.log, and the reason it returns the IP address 192.168.1.10 at the top is because this IP appears more frequently than any other in the logs (especially in repeated failed login events), so Splunk counts how many times each src_ip occurs and then sorts the results in descending order, making 192.168.1.10 the highest-ranked IP, which indicates it is the most active or potentially suspicious source in this dataset.


By using the query index=main source="test.log" "failed login" \| stats count by src_ip \| sort - count, I am specifically demonstrating how to identify which IP address is responsible for the most failed login attempts only, rather than all activity, and it still returns 192.168.1.10 because this IP address appears the most frequently in the failed login events within the log file, and the difference between this query and the previous one (index=main source="test.log" \| stats count by src_ip \| sort - count) is that the previous query counts all events(including successful logins and errors) while this query filters and counts only failed login events, but both produce the same top IP because 192.168.1.10 dominates the dataset in both overall activity and failed login attempts.


By running the query index=main source="test.log" \| stats count by user \| sort - count, I am demonstrating how to analyze which user accounts generate the most activity in the log file, and it returns admin at the top because this username appears more frequently than others in the events (especially in repeated login attempts), so Splunk counts occurrences of each user and sorts them in descending order, allowing me to identify the most active or potentially targeted account in the dataset.


By using the query index=main source="test.log" \| top src_ip, I am demonstrating how to quickly identify the most frequent source IP addresses in the log file using a built-in Splunk command, and the output shows 192.168.1.10because this IP appears more times than any other in the dataset (especially across multiple login events), so Splunk calculates the frequency of each src_ip and ranks them, making 192.168.1.10 the top result as the most active or potentially suspicious source.


By using the query index=main source="test.log" \| stats values(user) by src_ip, I am demonstrating how to correlate data by showing which user accounts are associated with each source IP address, and it highlights 192.168.1.10because this IP appears frequently in the dataset and is linked to one or more users (such as admin), so Splunk groups events by src_ip and lists all unique user values seen for each IP, allowing me to understand relationships between IP addresses and user activity for investigation purposes.


By using the query index=main source="test.log" \| stats dc(src_ip) as unique_ips, I am demonstrating how to calculate the number of distinct (unique) IP addresses present in the log data, and the output is 1 because Splunk is counting only the unique values of src_ip in the events it processed, and in your current filtered or grouped dataset it is seeing only one distinct IP value (such as 192.168.1.10), which means all the counted events belong to the same source IP rather than multiple different IPs.


By using the query index=main source="test.log" \| timechart count, this demonstrates how event activity is analyzed over time by grouping events into time-based intervals, and the result shows 49 entries ( I used only 11 entries in screenshot ) because Splunk automatically divides the selected time range into multiple time buckets (such as minutes or hours) and counts how many events occur within each interval, so each entry represents one time segment with its corresponding event count, and since the filter source="test.log" is applied, the results correspond only to events from that specific file.


By using the query index=main source="test.log" \| stats count by user src_ip \| sort - count, this demonstrates how to correlate user accounts with their originating IP addresses and measure how frequently each combination occurs, and the result shows admin with IP 192.168.1.10 at the top because that specific user–IP pair appears more often than any other in the dataset, indicating it is the most active or potentially suspicious combination in the log.
\
\
By using the query index=main source="test.log" \| rare src_ip, this demonstrates how to identify the least frequent source IP addresses in the dataset, and it still returns 192.168.1.10 because the current dataset effectively contains only one distinct IP value (or one dominant value after filtering), so even the “rarest” result ends up being the same IP since there are no other IPs with lower frequency to compare against.
\
\
By using the query index=main source="test.log" \| table \_time user src_ip, this demonstrates how to display the raw event-level data with exact timestamps and specific fields, and it shows a precise time such as 21:29:48because \_time represents the actual timestamp of each individual event, whereas the earlier timechart query grouped events into broader time buckets like 21:00:00 or 21:30:00, so those times are not exact event times but rounded interval boundaries, which is why the exact timestamp seen here does not exactly match the summarized time intervals from the previous result.


By using the query index=main source="test.log" \| stats count by sourcetype, this demonstrates how to identify the data classification of the events by showing which sourcetype is associated with the logs, and it returns test.logbecause all events in this dataset were indexed with that same sourcetype, meaning Splunk categorized the entire file under a single data type, so the count reflects that all events belong to that one sourcetype.
\
By using the query index=main source="test.log" \| stats count by host, this demonstrates how to identify which machine generated the log events, and it returns MacBookPro because all events in the dataset were created on that system, so Splunk groups the events by the host field and shows that the entire activity in test.log originated from that single device.\
\
\
By using the query** **index=main source="test.log" \| stats count by time \| sort \_time, this demonstrates how to group and display events based on their** exact timestamp**, and it returns** 2026-04-02 21:29:48 **because multiple log lines share that same precise event time, so Splunk groups those events under that timestamp and counts them, showing when those activities occurred at the exact second level rather than in broader time intervals.


By using the query** **index=main source="test.log" \| stats count by punct, this demonstrates how Splunk analyzes the** punctuation patterns **present in the raw log events, and the output showing combinations like** **---=......-=------represents the sequence and frequency of punctuation characters (such as** **=,** **., and** **-) extracted from each event, which Splunk uses internally to help recognize patterns in unstructured data, so this query is used to understand how similar or different the structure of log lines is, even when the actual text content varies.


By using the query** **index=main source="test.log" \| stats values(src_ip) by user, this demonstrates how to map each user to the IP addresses they have used, and it returns** admin with IP 192.168.1.10 **because that user is associated with that IP in the log events, so Splunk groups all events by** **user** **and lists the unique** **src_ip** **values observed for each user, allowing identification of which IPs are linked to specific accounts.
\
By using the query** **index=main source="test.log" \| eval action=if(searchmatch("failed login"), "failed", if(searchmatch("successful login"), "success", "other")) \| stats count by action, this demonstrates how to** create a new field (**action**) dynamically **based on the content of each event and then categorize and count events by type, and it shows** "failed" **because most of the log entries in** **test.log** **contain the phrase “failed login,” so Splunk labels those events as “failed” and counts them, making it the dominant category in the dataset.


By using the query** **index=main source="test.log" \| eval action=if(searchmatch("failed login"), "failed", if(searchmatch("successful login"), "success", "other")) \| timechart count by action, this demonstrates how to visualize event activity over time by categorizing logs into actions (failed, success, other) and then plotting their counts across time intervals, and it produces** 49 time-based entries **because Splunk automatically divides the selected time range into many small time buckets and counts events in each, but for demonstration and clarity only** 11 of those entries are shown in the screenshot**, while the full dataset still contains all 49 intervals representing the overall activity timeline.
\
By using the query** **index=main source="test.log" \| top user, this demonstrates how to quickly identify the most frequent user values in the dataset along with their counts and percentages, and it shows** admin with count = 1 **because, in the way Splunk is currently interpreting or grouping the events, the user field appears only once per processed event block, so Splunk calculates the frequency and returns admin as the top (and possibly only) user in that context.


By using the query** **index=main source="test.log" \| eval action=if(searchmatch("failed login"), "failed", if(searchmatch("successful login"), "success", "other")) \| stats count by action, this demonstrates how to classify the raw log events into simple categories and summarize them, and the output shows** failed **because most of the events in** **test.log** **contain the phrase** “failed login,” **so Splunk assigns those events to the** failed **action category and counts them, which makes failed the dominant result in the dataset.


By using the query** **index=main source="test.log" \| eval action=if(searchmatch("failed login"), "failed", if(searchmatch("successful login"), "success", "other")) \| stats count by action, this demonstrates how raw log events are first** classified into meaningful categories **(failed, success, other) using the** **eval** **command and then** aggregated into counts **using** **stats, which transforms the unstructured log data into a summarized dataset that can be directly used for visualization, and this is why the query produces a chart, because it outputs structured numerical results (counts per action) that Splunk can easily represent graphically such as in a bar chart or pie chart.


**Key Splunk Concepts**


- Index: Storage location where Splunk stores and organizes ingested data (e.g., main)

- Source: The origin of the data (e.g., test.log file)

- Sourcetype: The format/type of the data that tells Splunk how to parse it

- Indexer: The Splunk component that stores and indexes incoming data

- Search Query (SPL): Commands used to search and analyze data in Splunk

- stats: A transforming command used to aggregate data (e.g., count, avg)

- sort - count: Sorts results in descending order based on count

- top: Displays most frequent values in a field

- timechart: Creates time-based aggregations for visualization

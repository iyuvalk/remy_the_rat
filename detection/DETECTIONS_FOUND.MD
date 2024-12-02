
# Detection for Remy-the-RAT

## Automated OpenAI approach
I tried the attached openai Python code to detect several aspects of remy-the-rat invocations but eventually this yielded mostly useless results as can be seen in the file named `automated-openai-approach-results.txt` in this folder. It seems that the engine mainly looked for any indication of a DNS query.

## Manual OpenAI approach
I sent the following message to ChatGPT 01-preview model along with the logs audit.log, syslog, and auth.log: 
"You are a cybersecurity expert analyzing log entries for malicious or strange activity, specifically looking for:
- DNS requests to the artifex.co.il domain
- Connections to S3 buckets with unusual names
- Creation of users, especially administrative ones
Does this log entry indicate any of these activities? If yes, please provide details and relevant Sigma signatures."
It has successfully detected the creation of the user 'remy-the-root' and the fact it was created with sudo permissions:
```commandline
The provided log snippets cover multiple sources (audit, syslog, auth, etc.) and appear to include system events, user sessions, and service logs. To detect the specific activities of interest, I will systematically check the logs for:

1. **DNS requests to the `artifex.co.il` domain**.
2. **Connections to S3 buckets with unusual names**.
3. **Creation of users, particularly administrative ones**.

### Next Steps
I will:
- Parse each log file for entries matching the specified patterns.
- Look for DNS requests, S3-related keywords, and user account creation activities.
- Provide insights with any matching results.

Let me start by analyzing these patterns.

### Findings from Log Analysis

1. **DNS Requests to `artifex.co.il`**
   - **No matches found**: There were no log entries indicating DNS queries to the `artifex.co.il` domain.

2. **Connections to S3 Buckets**
   - **Matches found**: Several entries from `syslog` include references to asset caching with bucket-like names, but these appear related to Slack's service worker activity (e.g., assets like `https://a.slack-edge.com/...`). These don't seem malicious but could be reviewed further for assurance.

3. **User Creation**
   - **Matches found**: Multiple logs from `audit`, `auth`, and `auth2` indicate the creation of new users:
     - User `remy_the_root` was added as an administrative user with access to the `sudo` group on `2024-12-01`.
     - User `remy_the_rat` was attempted multiple times but only succeeded once on `2024-11-28`, also with administrative access (`sudo` group).

### Recommendations:
- **Investigate User Additions**: Validate whether the creation of `remy_the_root` and `remy_the_rat` users was authorized. Focus on:
  - The associated process (`/usr/sbin/useradd`).
  - User permissions (e.g., `sudo` group membership).

- **Review S3 Connections**: Although the entries for Slack assets seem benign, ensure no anomalies by inspecting related services.

### Suggested Sigma Rules:
- **User Creation**:
  title: New User Creation
  logsource:
    category: process_creation
    product: linux
  detection:
    selection:
      CommandLine|contains:
        - '/usr/sbin/useradd'
        - 'adduser'
    condition: selection
  fields:
    - CommandLine
    - User
  level: medium

- **Suspicious S3 Connections**:
  title: Suspicious S3 Bucket Access
  logsource:
    category: network_connection
    product: linux
  detection:
    selection:
      TargetHostname|contains: 's3.'
    condition: selection
  fields:
    - TargetHostname
    - DestinationIp
  level: high

Would you like a deeper inspection into any specific logs or additional assistance?
```

I sent the same query with Suricata's eve.json logs, this time the results seemed to be more accurate and valuable. Here are the relevant signatures generated:
```yaml
title: DNS Query to artifex.co.il
logsource:
  category: dns
  product: windows
detection:
  selection:
    Question: '*artifex.co.il'
  condition: selection
fields:
  - Question
status: experimental
```

```yaml
title: Detect UUID-like S3 Bucket Names
logsource:
  category: dns
  product: network
detection:
  selection:
    rrname|regex: '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.s3\.amazonaws\.com'
  condition: selection
fields:
  - rrname
status: experimental
```

## Final Thoughts and Conclusion
The key design goals for this RAT were:
- To make it possible to use any domain for storing its root TXT record
- Allow for automated mechanism for choosing the current domain to use based on publicly known data (e.g. current date)
- Make it possible to use any HTTP/S service which accepts PUT and GET requests for storing the commands queue and their results
- Make it possible to use different HTTP/s services for storing the commands queue and the commands outputs
- Make it possible to use a different HTTP/s service for storing the output of each command
- Data transferred to/from the HTTP/s service is being encrypted at the HTTP body level by using PKI (regardless of the TLS encryption) to hide it from TLS inspection services
- Commands to be executed are not hard coded anywhere in the RAT code

Based on all these, I believe that this type of malware cannot be detected by any of the above signatures if the attacker have configured it differently than I did or used it for executing different commands than I did so each usage of this tool can potentially be fingerprinted but not the RAT itself.

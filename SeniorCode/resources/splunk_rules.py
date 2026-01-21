# 1. PHISHING: Browsers clicking HTTP links
QUERY_PHISHING = r"""
search index=* source="xmlwineventlog:microsoft-windows-sysmon/operational" EventCode=1 earliest=-30
(CommandLine="*http://*" OR CommandLine="*https://*")
| eval Browser_Name=mvindex(split(Image, "\\"), -1) 
| eval Parent_App=mvindex(split(ParentImage, "\\"), -1)
| where Browser_Name IN ("chrome.exe", "msedge.exe", "firefox.exe", "brave.exe", "iexplore.exe", "opera.exe")
| rex field=CommandLine "(?<Clicked_Link>https?://\S+)"
| rex field=RuleName "technique_id=(?<Technique_ID>T\d+)"
| table _time, Computer, User, Parent_App, Browser_Name, Clicked_Link, Technique_ID
"""

# 2. CRYPTOJACKING: Detects mining tools (xmrig, etc) or high CPU usage behaviors
# Note: T1496 is "Resource Hijacking"
QUERY_CRYPTO = r"""
search index=main source="*Sysmon*" "<EventID>6</EventID>"
| spath input=_raw
| rex field=_raw "<Data Name='ImageLoaded'>(?<ImageLoaded>[^<]+)</Data>"
| rex field=_raw "<Data Name='Signature'>(?<Signature>[^<]+)</Data>"
| rex field=_raw "<Data Name='Signed'>(?<Signed>[^<]+)</Data>"
| rex field=_raw "<Data Name='Hashes'>(?<All_Hashes>[^<]+)</Data>" 
| rex field=All_Hashes "MD5=(?<MD5>[^,]+)"
| rex field=All_Hashes "SHA256=(?<SHA256>[^,]+)"
| rex field=All_Hashes "IMPHASH=(?<IMPHASH>[^,]+)"
| search MD5="0C0195C48B6B8582FA6F6373032118DA" OR SHA256="11BD2C9F9E2397C9A16E0990E4ED2CF0679498FE0FD418A3DFDAC60B5C160EE5"
| rename "Event.System.Computer" as Computer
| eval Technique_ID="T1068"
| table _time, Computer, ImageLoaded, Signature, Signed, SHA1, MD5, SHA256, IMPHASH, Technique_ID
"""

# 3. DDoS: High volume of network connections (EventCode 3) from one process in short time
# Looks for > 50 connections in 30 seconds from a single process
QUERY_DDOS = r"""
search index=* source="xmlwineventlog:microsoft-windows-sysmon/operational" EventCode=3
| bin _time span=30s
| stats count by _time, Computer, Image, DestinationIp
| where count > 50
| eval Process_Name=mvindex(split(Image, "\\"), -1)
| table _time, Computer, Process_Name, DestinationIp, count
"""

# 4. LICENSE CHECK
QUERY_LICENSE = f"""
search index=_internal source=*license_usage.log type="Usage" earliest=@d
| stats sum(b) AS volumeB max(poolsz) AS poolsz 
| eval limit=coalesce(poolsz, 524288000) 
| eval pctused=round(volumeB/limit*100, 2) 
| table pctused
"""

# 5. BRUTE FORCE CHECK
# Looks for 5+ failed logins (Event 4625) by a single user/IP in the last 30s
QUERY_BRUTEFORCE = r"""
search index=* source="xmlwineventlog:security" EventCode=4625
| stats count by TargetUserName, IpAddress, Computer
| where count >= 5
| eval User=TargetUserName
| table Computer, User, IpAddress, count
"""
## 1. analysis_job_type distribution
| analysis_job_type | Count | Percentage |
| --- | --- | --- |
| only_static_analysis | 258 | 51.600000% |
| full_analysis | 242 | 48.400000% |

## 2. Config JSON and timeout
| analysis_job_type / measure | Total | Count | Percentage | Has timeout | Timeout distribution |
| --- | --- | --- | --- | --- | --- |
| full_analysis | 242 | 242 | 100.000000% | 242 | 120: 80, 180: 78, 60: 84 |
| only_static_analysis | 258 | 258 | 100.000000% | 258 | 120: 85, 180: 85, 60: 88 |
| Dynamic timeout absent (full_analysis) | 242 | 0 | 0.000000% | — | — |

## 3. Submission interface versus timeout
| Analysis ID | Submission ID | submission_interface_name | Parsed timeout | Expected timeout | Agrees |
| --- | --- | --- | --- | --- | --- |
| 266183 | 142769 | 2minutes | 120 | 120 | yes |
| 266181 | 142768 | 1minute | 60 | 60 | yes |
| 266173 | 142764 | 3minutes | 180 | 180 | yes |
| 266171 | 142763 | 2minutes | 120 | 120 | yes |
| 266169 | 142762 | 1minute | 60 | 60 | yes |
| 266161 | 142758 | 3minutes | 180 | 180 | yes |
| 266159 | 142757 | 2minutes | 120 | 120 | yes |
| 266157 | 142756 | 1minute | 60 | 60 | yes |
| 266151 | 142753 | 1minute | 60 | 60 | yes |
| 266149 | 142752 | 3minutes | 180 | 180 | yes |
| 266147 | 142751 | 2minutes | 120 | 120 | yes |
| 266145 | 142750 | 1minute | 60 | 60 | yes |
| 266139 | 142747 | 1minute | 60 | 60 | yes |
| 266137 | 142746 | 3minutes | 180 | 180 | yes |
| 266135 | 142745 | 2minutes | 120 | 120 | yes |
| 266133 | 142744 | 1minute | 60 | 60 | yes |
| 266129 | 142742 | 2minutes | 120 | 120 | yes |
| 266127 | 142741 | 1minute | 60 | 60 | yes |
| 266125 | 142740 | 3minutes | 180 | 180 | yes |
| 266123 | 142739 | 2minutes | 120 | 120 | yes |
| Agreement summary | — | — | — | — | 20/20 (100.000000%) |

## 4. Analysis results and empty verdicts
| analysis_result_code | analysis_result_str / measure | Count |
| --- | --- | --- |
| 1 | Operation completed successfully. | 500 |
| Verdict null/empty | — | 0 |

## 5a. Distinct VTI category and operation pairs
| Category | Operation | Frequency | Minimum score | Maximum score |
| --- | --- | --- | --- | --- |
| Antivirus | Malicious content was detected by heuristic scan | 30 | 4 | 4 |
| Reputation | Malicious file detected via reputation | 30 | 4 | 4 |
| Anti Analysis | Delays execution | 4 | 2 | 2 |
| Discovery | Enumerates running processes | 4 | 1 | 1 |
| Discovery | Possibly does reconnaissance | 4 | 1 | 1 |
| Discovery | Queries system time | 4 | 1 | 1 |
| Discovery | Searches for sensitive application data | 4 | 2 | 2 |
| Discovery | Searches for sensitive browser data | 4 | 2 | 2 |
| Execution | Drops PE file | 4 | 1 | 1 |
| Execution | Executes dropped PE file | 4 | 1 | 1 |
| Hide Tracks | Creates process with hidden window | 4 | 1 | 1 |
| Mutex | Known malicious mutex name is created | 4 | 5 | 5 |
| Obfuscation | Resolves API functions dynamically | 4 | 1 | 1 |
| Persistence | Installs system startup script or application | 4 | 1 | 1 |
| System Modification | Modifies operating system directory | 4 | 1 | 1 |
| YARA | Content matched by YARA rules | 4 | 1 | 1 |
| Discovery | Searches for sensitive password manager data | 3 | 2 | 2 |
| Discovery | Searches for sensitive remote access configuration data | 3 | 2 | 2 |

## 5b. One raw threat_indicator object
| Raw JSON |
| --- |
| {"analysis_ids":[266222],"category":"Antivirus","classifications":[],"id":1,"operation":"Malicious content was detected by heuristic scan","score":4} |

## 6. Analysis timestamps
| Measure | Count | Percentage |
| --- | --- | --- |
| analysis_job_started present | 500 | 100.000000% |
| Comparable created/started pairs | 500 | 100.000000% |
| analysis_created >= analysis_job_started | 500 | 100.000000% |
| Ordering violations | 0 | 0.000000% |

## 7a. VTI taxonomy over 300 analyses
| Category | Operation | Occurrences | full_analysis | only_static_analysis | Score >= 3 | Minimum score | Maximum score |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Antivirus | Malicious content was detected by heuristic scan | 248 | 115 | 133 | 248 | 4 | 4 |
| Reputation | Malicious file detected via reputation | 225 | 97 | 128 | 225 | 4 | 4 |
| Reputation | Malicious host or URL detected via reputation | 53 | 53 | 0 | 53 | 4 | 4 |
| YARA | Malicious content matched by YARA rules | 52 | 52 | 0 | 52 | 5 | 5 |
| Injection | Modifies control flow of another process | 38 | 38 | 0 | 38 | 4 | 4 |
| Injection | Writes into the memory of another process | 38 | 38 | 0 | 38 | 4 | 4 |
| Mutex | Known malicious mutex name is created | 38 | 38 | 0 | 38 | 5 | 5 |
| Injection | Process Hollowing | 26 | 26 | 0 | 26 | 4 | 4 |
| Discovery | Reads installed applications | 24 | 24 | 0 | 24 | 3 | 3 |
| Network Connection | Injected process sets up server that accepts incoming connections | 24 | 24 | 0 | 24 | 4 | 4 |
| Anti Analysis | Modifies native system functions | 19 | 19 | 0 | 19 | 3 | 3 |
| Input Capture | Captures clipboard data | 11 | 11 | 0 | 11 | 3 | 3 |
| Network Connection | Performs DNS request for known DDNS domain | 11 | 11 | 0 | 11 | 3 | 3 |
| Data Collection | Combination of other detections shows multiple input capture behaviors | 9 | 9 | 0 | 9 | 5 | 5 |
| Reputation | Suspicious host or URL detected via reputation | 9 | 9 | 0 | 9 | 3 | 3 |
| Defense Evasion | Obscures a file's origin | 7 | 7 | 0 | 7 | 3 | 3 |
| YARA | Suspicious content matched by YARA rules | 10 | 10 | 0 | 6 | 2 | 3 |
| Anti Analysis | Makes indirect system call to possibly evade hooking based monitoring | 6 | 6 | 0 | 6 | 4 | 4 |
| Browser | Adds a hook to a web browser | 6 | 6 | 0 | 6 | 5 | 5 |
| Injection | Entry point injection | 6 | 6 | 0 | 6 | 4 | 4 |
| Network Connection | Uses HTTP to upload a large amount of data | 6 | 6 | 0 | 6 | 3 | 3 |
| System Modification | Modifies system configuration | 6 | 6 | 0 | 6 | 3 | 3 |
| Network Connection | All network connection attempts failed | 5 | 5 | 0 | 5 | 3 | 3 |
| Injection | Makes indirect system calls to hide process injection | 4 | 4 | 0 | 4 | 5 | 5 |
| Input Capture | Monitors keyboard input | 4 | 4 | 0 | 3 | 1 | 3 |
| Defense Evasion | Bypasses PowerShell execution policy | 3 | 3 | 0 | 3 | 3 | 3 |
| Extracted Configuration | Remcos configuration was extracted | 3 | 3 | 0 | 3 | 5 | 5 |
| Hide Tracks | Creates file(s) in the .NET assembly directory to hide them from Windows Explorer | 3 | 3 | 0 | 3 | 3 | 3 |
| Network Connection | Attempts to connect through HTTP | 3 | 3 | 0 | 3 | 4 | 4 |
| Privilege Escalation | Event Triggered Execution | 3 | 3 | 0 | 3 | 3 | 3 |
| System Modification | Disables a crucial system tool | 3 | 3 | 0 | 3 | 4 | 4 |
| Data Collection | Bypasses browser App-Bound Encryption | 2 | 2 | 0 | 2 | 3 | 3 |
| Extracted Configuration | FormBook configuration was extracted | 2 | 2 | 0 | 2 | 5 | 5 |
| Heuristics | Combination of other detections indicates a phishing website | 1 | 1 | 0 | 1 | 5 | 5 |
| Heuristics | Page contains a Microsoft logon form | 1 | 1 | 0 | 1 | 3 | 3 |
| Input Capture | Monitors user input | 1 | 1 | 0 | 1 | 3 | 3 |
| Machine Learning | Phishing page detected via Machine Learning | 1 | 1 | 0 | 1 | 4 | 4 |
| Discovery | Queries system time | 123 | 123 | 0 | 0 | 1 | 1 |
| Execution | Drops PE file | 111 | 111 | 0 | 0 | 1 | 1 |
| YARA | Content matched by YARA rules | 106 | 76 | 30 | 0 | 1 | 1 |
| Execution | Executes dropped PE file | 101 | 101 | 0 | 0 | 1 | 1 |
| Hide Tracks | Creates process with hidden window | 100 | 100 | 0 | 0 | 1 | 1 |
| Obfuscation | Resolves API functions dynamically | 84 | 84 | 0 | 0 | 1 | 1 |
| Anti Analysis | Delays execution | 74 | 74 | 0 | 0 | 2 | 2 |
| Obfuscation | Creates a page with write and execute permissions | 72 | 72 | 0 | 0 | 1 | 1 |
| Persistence | Installs system startup script or application | 71 | 71 | 0 | 0 | 1 | 1 |
| Discovery | Possibly does reconnaissance | 63 | 63 | 0 | 0 | 1 | 1 |
| Network Connection | Performs DNS request | 63 | 63 | 0 | 0 | 1 | 2 |
| Hide Tracks | Deletes file after execution | 62 | 62 | 0 | 0 | 2 | 2 |
| Network Connection | Connects to remote host | 62 | 62 | 0 | 0 | 1 | 1 |
| Discovery | Enumerates running processes | 55 | 55 | 0 | 0 | 1 | 1 |
| Mutex | Creates mutex | 48 | 48 | 0 | 0 | 1 | 1 |
| Discovery | Query OS Information | 43 | 43 | 0 | 0 | 1 | 1 |
| System Modification | Modifies operating system directory | 41 | 41 | 0 | 0 | 1 | 1 |
| Antivirus | Suspicious content was detected by heuristic scan | 37 | 28 | 9 | 0 | 2 | 2 |
| Discovery | Searches for sensitive browser data | 37 | 37 | 0 | 0 | 2 | 2 |
| Defense Evasion | Loads a dropped DLL | 36 | 36 | 0 | 0 | 1 | 1 |
| Discovery | Searches for sensitive password manager data | 36 | 36 | 0 | 0 | 2 | 2 |
| Discovery | Searches for sensitive remote access configuration data | 36 | 36 | 0 | 0 | 2 | 2 |
| Discovery | Searches for sensitive application data | 35 | 35 | 0 | 0 | 2 | 2 |
| System Modification | Modifies application directory | 30 | 30 | 0 | 0 | 1 | 1 |
| Defense Evasion | Accesses volumes directly | 29 | 29 | 0 | 0 | 1 | 1 |
| Heuristics | Signed executable failed signature validation | 28 | 28 | 0 | 0 | 2 | 2 |
| Obfuscation | Reads from memory of another process | 27 | 27 | 0 | 0 | 1 | 1 |
| Injection | Modifies control flow of a process started from a created or modified executable | 26 | 26 | 0 | 0 | 2 | 2 |
| Heuristics | Uncommon PE properties | 24 | 24 | 0 | 0 | 1 | 1 |
| Hide Tracks | Hides files | 18 | 18 | 0 | 0 | 2 | 2 |
| Obfuscation | Overwrites code | 14 | 14 | 0 | 0 | 1 | 1 |
| Defense Evasion | Timestamp manipulation | 13 | 13 | 0 | 0 | 1 | 1 |
| Crash | A monitored process crashed | 10 | 10 | 0 | 0 | 1 | 1 |
| Network Connection | URL contains a TLD highly associated with phishing | 10 | 10 | 0 | 0 | 1 | 1 |
| Privilege Escalation | Enables process privileges | 10 | 10 | 0 | 0 | 1 | 1 |
| Defense Evasion | Unusual large memory allocation | 9 | 9 | 0 | 0 | 1 | 1 |
| Heuristics | Page contains clickables with luring keywords | 9 | 9 | 0 | 0 | 1 | 1 |
| Heuristics | Page is hosted on a recently registered domain | 9 | 9 | 0 | 0 | 2 | 2 |
| Heuristics | URL contains email address | 9 | 9 | 0 | 0 | 1 | 1 |
| Task Scheduling | Schedules task | 9 | 9 | 0 | 0 | 2 | 2 |
| Anti Analysis | Makes direct system call to possibly evade hooking based monitoring | 8 | 8 | 0 | 0 | 2 | 2 |
| Anti Analysis | Tries to detect application sandbox | 6 | 6 | 0 | 0 | 2 | 2 |
| Discovery | Reads system data | 6 | 6 | 0 | 0 | 1 | 1 |
| Hide Tracks | Writes an unusually large amount of data to the registry | 6 | 6 | 0 | 0 | 1 | 1 |
| Masquerade | Masquerades file extension | 6 | 6 | 0 | 0 | 1 | 1 |
| Network Connection | Allows invalid SSL certificates | 6 | 6 | 0 | 0 | 2 | 2 |
| Anti Analysis | Creates an unusually large number of processes | 5 | 5 | 0 | 0 | 2 | 2 |
| Anti Analysis | Tries to detect a forensic tool | 5 | 5 | 0 | 0 | 2 | 2 |
| Discovery | Collects hardware properties | 5 | 5 | 0 | 0 | 2 | 2 |
| Discovery | Executes WMI query | 5 | 5 | 0 | 0 | 1 | 1 |
| Network Connection | Tries to connect using an uncommon port | 5 | 5 | 0 | 0 | 1 | 1 |
| Anti Analysis | Tries to detect virtual machine | 4 | 4 | 0 | 0 | 2 | 2 |
| Defense Evasion | Reloads native system libraries | 4 | 4 | 0 | 0 | 1 | 1 |
| Hide Tracks | Uses Alternate Data Stream (ADS) file attributes | 4 | 4 | 0 | 0 | 2 | 2 |
| Persistence | Installs system service | 4 | 4 | 0 | 0 | 1 | 1 |
| Defense Evasion | Executes PowerShell without default profile | 3 | 3 | 0 | 0 | 2 | 2 |
| Discovery | Accesses Microsoft Security Software registry keys | 3 | 3 | 0 | 0 | 1 | 1 |
| Discovery | Reads network configuration | 3 | 3 | 0 | 0 | 2 | 2 |
| Discovery | Searches for sensitive mail data | 3 | 3 | 0 | 0 | 2 | 2 |
| Hide Tracks | Executes PowerShell with hidden window | 3 | 3 | 0 | 0 | 2 | 2 |
| Network Connection | Downloads file | 3 | 3 | 0 | 0 | 1 | 2 |
| Anti Analysis | Tries to detect debugger | 2 | 2 | 0 | 0 | 1 | 1 |
| Anti Analysis | Tries to detect kernel debugger | 2 | 2 | 0 | 0 | 2 | 2 |
| Data Collection | Reads sensitive browser data | 2 | 2 | 0 | 0 | 2 | 2 |
| Computer Vision | Branded Logon form detected via Computer Vision | 1 | 1 | 0 | 0 | 2 | 2 |
| Computer Vision | Branding image detected via Computer Vision | 1 | 1 | 0 | 0 | 1 | 1 |
| Heuristics | Image references Microsoft Authenticator | 1 | 1 | 0 | 0 | 2 | 2 |
| Heuristics | Image references login keywords | 1 | 1 | 0 | 0 | 1 | 1 |
| Heuristics | Page presents itself as a logon page | 1 | 1 | 0 | 0 | 1 | 1 |
| Heuristics | Page secured via a Domain Validated SSL certificate | 1 | 1 | 0 | 0 | 1 | 1 |
| Heuristics | URL contains obfuscated email address | 1 | 1 | 0 | 0 | 1 | 1 |
| Input Capture | Reads mouse position | 1 | 1 | 0 | 0 | 1 | 1 |
| Masquerade | Page uses exact branding image of a popular online service | 1 | 1 | 0 | 0 | 1 | 1 |
| Network Connection | Loads a Cloudflare script | 1 | 1 | 0 | 0 | 1 | 1 |
| Network Connection | Possible phishing kit behavior | 1 | 1 | 0 | 0 | 2 | 2 |

## 7b. Distinct VTI categories
| Category |
| --- |
| Anti Analysis |
| Antivirus |
| Browser |
| Computer Vision |
| Crash |
| Data Collection |
| Defense Evasion |
| Discovery |
| Execution |
| Extracted Configuration |
| Heuristics |
| Hide Tracks |
| Injection |
| Input Capture |
| Machine Learning |
| Masquerade |
| Mutex |
| Network Connection |
| Obfuscation |
| Persistence |
| Privilege Escalation |
| Reputation |
| System Modification |
| Task Scheduling |
| YARA |

## 8. Timeout fidelity
| Configured timeout | Count | Minimum seconds | Median seconds | P90 seconds | Maximum seconds |
| --- | --- | --- | --- | --- | --- |
| 60 | 84 | 85.0 | 227.0 | 394.0 | 566.0 |
| 120 | 80 | 95.0 | 298.0 | 452.0 | 740.0 |
| 180 | 78 | 109.0 | 373.0 | 490.0 | 758.0 |

## 9a. Per-sample arm count distribution
| Dynamic run count | Static run count | Samples |
| --- | --- | --- |
| 1 | 0 | 1 |
| 1 | 1 | 1 |
| 3 | 0 | 5 |
| 3 | 3 | 49 |
| 4 | 4 | 1 |
| 6 | 6 | 2 |
| 6 | 28 | 1 |
| 24 | 24 | 1 |
| 32 | 42 | 1 |

## 9b. Samples not having (3, 3)
| Sample ID | Dynamic runs | Static runs | Timeouts present | Timeouts missing |
| --- | --- | --- | --- | --- |
| 141833 | 1 | 1 | 60 | 120, 180 |
| 141839 | 1 | 0 | 180 | 60, 120 |
| 142299 | 6 | 6 | 60, 120, 180 | none |
| 142562 | 3 | 0 | 60, 120, 180 | none |
| 142586 | 3 | 0 | 60, 120, 180 | none |
| 142617 | 6 | 6 | 60, 120, 180 | none |
| 142623 | 4 | 4 | 60, 120, 180 | none |
| 142665 | 3 | 0 | 60, 120, 180 | none |
| 142668 | 3 | 0 | 60, 120, 180 | none |
| 142674 | 3 | 0 | 60, 120, 180 | none |
| 142696 | 24 | 24 | 60, 120, 180 | none |
| 142708 | 32 | 42 | 60, 120, 180 | none |
| 142735 | 6 | 28 | 60, 120 | 180 |


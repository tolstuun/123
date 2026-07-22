## 1. analysis_job_type distribution
| analysis_job_type | Count | Percentage |
| --- | --- | --- |
| full_analysis | 251 | 50.200000% |
| only_static_analysis | 249 | 49.800000% |

## 2. Config JSON and timeout
| analysis_job_type / measure | Total | Count | Percentage | Has timeout | Timeout distribution |
| --- | --- | --- | --- | --- | --- |
| full_analysis | 251 | 251 | 100.000000% | 251 | 120: 85, 180: 82, 60: 84 |
| only_static_analysis | 249 | 249 | 100.000000% | 249 | 120: 83, 180: 83, 60: 83 |
| Dynamic timeout absent (full_analysis) | 251 | 0 | 0.000000% | — | — |

## 3. Submission interface versus timeout
| Analysis ID | Submission ID | submission_interface_name | Parsed timeout | Expected timeout | Agrees |
| --- | --- | --- | --- | --- | --- |
| 265632 | 142486 | 2minutes | 120 | 120 | yes |
| 265630 | 142485 | 1minute | 60 | 60 | yes |
| 265628 | 142484 | 3minutes | 180 | 180 | yes |
| 265627 | 142483 | 2minutes | 120 | 120 | yes |
| 265626 | 142482 | 1minute | 60 | 60 | yes |
| 265625 | 142481 | 3minutes | 180 | 180 | yes |
| 265623 | 142480 | 2minutes | 120 | 120 | yes |
| 265621 | 142479 | 1minute | 60 | 60 | yes |
| 265619 | 142478 | 3minutes | 180 | 180 | yes |
| 265617 | 142477 | 2minutes | 120 | 120 | yes |
| 265615 | 142476 | 1minute | 60 | 60 | yes |
| 265613 | 142475 | 3minutes | 180 | 180 | yes |
| 265611 | 142474 | 2minutes | 120 | 120 | yes |
| 265609 | 142473 | 1minute | 60 | 60 | yes |
| 265607 | 142472 | 3minutes | 180 | 180 | yes |
| 265605 | 142471 | 2minutes | 120 | 120 | yes |
| 265603 | 142470 | 1minute | 60 | 60 | yes |
| 265601 | 142469 | 3minutes | 180 | 180 | yes |
| 265599 | 142468 | 2minutes | 120 | 120 | yes |
| 265597 | 142467 | 1minute | 60 | 60 | yes |
| Agreement summary | — | — | — | — | 20/20 (100.000000%) |

## 4. Analysis results and empty verdicts
| analysis_result_code | analysis_result_str / measure | Count |
| --- | --- | --- |
| 1 | Operation completed successfully. | 500 |
| Verdict null/empty | — | 0 |

## 5a. Distinct VTI category and operation pairs
| Category | Operation | Frequency | Minimum score | Maximum score |
| --- | --- | --- | --- | --- |
| Reputation | Malicious file detected via reputation | 27 | 4 | 4 |
| Antivirus | Malicious content was detected by heuristic scan | 23 | 4 | 4 |
| Obfuscation | Resolves API functions dynamically | 12 | 1 | 1 |
| Obfuscation | The binary file was created with a packer | 12 | 1 | 1 |
| Discovery | Queries system time | 11 | 1 | 1 |
| YARA | Malicious content matched by YARA rules | 10 | 5 | 5 |
| Execution | Drops PE file | 9 | 1 | 1 |
| Hide Tracks | Hides files | 9 | 2 | 2 |
| Obfuscation | Creates a page with write and execute permissions | 9 | 1 | 1 |
| System Modification | Modifies application directory | 9 | 1 | 1 |
| YARA | Content matched by YARA rules | 9 | 1 | 1 |
| Discovery | Enumerates running processes | 5 | 1 | 1 |
| Input Capture | Monitors keyboard input | 5 | 3 | 3 |
| YARA | Suspicious content matched by YARA rules | 4 | 3 | 3 |
| Computer Vision | Branding image detected via Computer Vision | 3 | 1 | 1 |
| Computer Vision | Logon form detected via Computer Vision | 3 | 1 | 1 |
| Data Collection | Combination of other detections shows multiple input capture behaviors | 3 | 5 | 5 |
| Defense Evasion | Tries to detect the presence of antivirus software | 3 | 3 | 3 |
| Discovery | Collects hardware properties | 3 | 2 | 2 |
| Discovery | Queries OS info via WMI | 3 | 2 | 2 |
| Extracted Configuration | XWorm configuration was extracted | 3 | 5 | 5 |
| Heuristics | Page presents itself as a logon page | 3 | 1 | 1 |
| Masquerade | Page contains Microsoft copyright text | 3 | 1 | 1 |
| Mutex | Creates mutex | 3 | 1 | 1 |
| Network Connection | Connects to remote host | 3 | 1 | 1 |
| Network Connection | Tries to connect using an uncommon port | 3 | 1 | 1 |
| Network Connection | URL does not use standard port | 3 | 1 | 1 |
| Privilege Escalation | Enables process privileges | 3 | 1 | 1 |
| Reputation | Suspicious host or URL detected via reputation | 3 | 3 | 3 |
| Anti Analysis | Tries to detect analyzer sandbox | 2 | 2 | 2 |
| Anti Analysis | Tries to detect debugger | 2 | 1 | 1 |
| Anti Analysis | Tries to detect virtual machine | 2 | 2 | 2 |
| Anti Analysis | Tries to evade debugger | 2 | 3 | 3 |
| Discovery | Possibly does reconnaissance | 2 | 1 | 1 |
| Discovery | Searches for sensitive browser data | 2 | 2 | 2 |
| Injection | Injects a file into another process | 2 | 3 | 3 |
| System Modification | Disables a crucial system tool | 2 | 4 | 4 |
| Obfuscation | Obfuscates control flow | 1 | 1 | 1 |

## 5b. One raw threat_indicator object
| Raw JSON |
| --- |
| {"analysis_ids":[265632],"category":"Discovery","classifications":[],"id":6,"operation":"Enumerates running processes","score":1} |

## 6. Analysis timestamps
| Measure | Count | Percentage |
| --- | --- | --- |
| analysis_job_started present | 500 | 100.000000% |
| Comparable created/started pairs | 500 | 100.000000% |
| analysis_created >= analysis_job_started | 500 | 100.000000% |
| Ordering violations | 0 | 0.000000% |


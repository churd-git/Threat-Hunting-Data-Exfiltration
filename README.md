
# Threat Hunt Report: Data Exfiltration 

## Example Scenario:

We are about to initiate an investigation involving a company executive, Bryce Montgomery, at a large tech company. The Risk Department suspects that Mr. Montgomery may be involved in the theft of company intellectual property. The VP of Risk has requested the Security Operations Manager to search for any signs of unusual or unauthorized data access or anything else suspicious. Investigate Bryce Montgomery's computer for any signs of unusual activity or potential data theft.

Important Context:
- Executives' Privileges: Executives, including Bryce Montgomery, have full administrative privileges on their own workstations.
- DLP Exception: While a Data Loss Prevention (DLP) solution is in place, some executives were made exempt from it due to concerns about productivity and inconvenience.

Known Information:
- Username: bmontgomery
- Workstation: corp-ny-it-0334

---

## High-Level Command and Scripting Interpreter: PowerShell related IoC Discovery Plan:
1.

---

## Steps Taken

1. Searched the DeviceFileEvents for suspicious activity from "bmontgomery" with any sensitive company files. Discovered that at "2025-02-05T05:45:12.1857689Z" the employee downloaded 3 sensitive research files "Q1-2025-ResearchAndDevelopment.pdf", "Q2-2025-HumanTrials.pdf", and "Q3-2025-AnimalTrials-SiberianTigers.pdf" on their device "corp-ny-it-0334". Normally the employee would not need the information in these files for their job role, despite having access to them. After downloading the files the employee moved them the the F: drive. The F: drive is a company wide shared folder and would make the files accessable by any device with access to that drive.     

```kql
DeviceFileEvents
| where DeviceName contains "corp-ny-it-0334"
| where InitiatingProcessAccountName contains "bmontgomery"
| where FileName contains "2025-"
```
<img width="1469" alt="Screenshot 2025-03-04 at 5 45 38 AM" src="https://github.com/user-attachments/assets/60ca84d7-634a-46ef-a45c-17c9c930d196" />

2. Investigated any devices or users that accessed the F: drive shortly after "2025-02-05T05:50:34.679531Z" to see if any more activity had taken place with the research files. In DeviceFileEvents between "2025-02-05T06:08:17.8607376Z" and "2025-02-05T06:09:35.6273078Z" the 3 research files were accessed on the device "lobby-fl2-ae5fc" by the account "lobbyuser". They user renamed the files to "bryce-homework-fall-2024.pdf", "Amazon-Order-123456789-Invoice.pdf", and "temp___2bbf98cf.pdf" respectively. The lobby user was attempting to avoid detection by renaming the files. On that same lobby device at "2025-02-05T06:18:59.0882396Z" the program "steghide.exe" was downlaoded. This software is often used to hide documents in image files and is a commonly known obsufication technique.   

```kql
DeviceFileEvents
| where FolderPath contains "f:"
| where DeviceName contains "lobby-fl2-ae5fc"
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, PreviousFileName
```
<img width="1467" alt="Screenshot 2025-03-04 at 6 03 09 AM" src="https://github.com/user-attachments/assets/7f7e0ca0-4e50-4ce7-aa9d-92e192aeb787" />

3. Searched DeviceEvents for any activity with the steghide software. At "2025-02-05T06:22:37.6603913Z" the software was used on the "bryce-homework-fall-2024.pdf" and "Amazon-Order-123456789-Invoice.pdf" files. Using the following commands: "steghide.exe  embed -ef bryce-homework-fall-2024.pdf -cf bryce-and-kid.bmp -p 123456 -sf c:\programdata\bryce-and-kid.bmp" and "steghide.exe  embed -ef amazon-order-123456789-invoice.pdf -cf bryce-fishing.bmp -p 123456 -sf c:\programdata\bryce-fishing.bmp" the files were hidden in the files "bryce-and-kid.bmp" and "bryce-fishing.bmp" respectivly. The steghide software was also deleted from "lobby-fl2-ae5fc" at "2025-02-05T06:36:53.0523679Z" in an attempt to cover their tracks.  

```kql
DeviceEvents
| where DeviceName contains "lobby-fl2-ae5fc"
| where InitiatingProcessFileName contains "steg"
```

<img width="1468" alt="Screenshot 2025-03-04 at 6 31 18 AM" src="https://github.com/user-attachments/assets/775e0117-c7db-4667-8a06-97c33676de81" />
<img width="1467" alt="Screenshot 2025-03-04 at 6 38 49 AM" src="https://github.com/user-attachments/assets/3fd28cc8-fe33-419c-b679-bf0efd131baf" />

4. 

```kql

```
---

## Chronological Events


---

## Summary



---

## Response Taken


---

## Created By:
- **Author Name**: Carlton Hurd
- **Author Contact**: https://www.linkedin.com/in/carlton-hurd-6069a5120/
- **Date**: January 29th, 2025

## Validated By:
- **Reviewer Name**: Carlton Hurd
- **Reviewer Contact**: 
- **Validation Date**: January 29th, 2025 

---

## Additional Notes:
- **None**

---

## Revision History:
| **Version** | **Changes**                   | **Date**         | **Modified By**   |
|-------------|-------------------------------|------------------|-------------------|
| 1.0         | Initial draft                  | `January  29th, 2025`  | `Carlton Hurd`   

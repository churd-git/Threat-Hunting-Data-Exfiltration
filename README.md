![Untitled design](https://github.com/user-attachments/assets/7ab49239-feaa-4986-b4f1-90f313fb911d)
# Threat Hunt Report: Data Exfiltration (T1027.003) 

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
1. Check DeviceFileEvents for any suspicious file activity involving the "corp-ny-it-0334" workstation or "bmontgomery" user account.
2. Check DeviceFileEvents for activity involving the downloaded company files.
3. Search DeviceEvents for activity involving the newly renamed files.
4. Check DeviceEvents for interactions with the newly created steg files.
5. Check DeviceFileEvents for any follow up interaction with the encrypted zip file that was created by a user on the lobby computer.
6. Search DeviceFileEvents to see who/if anyone accesses the zip file that was out into the F: Drive.    

---

## Steps Taken

1. Searched the DeviceFileEvents for suspicious activity from "bmontgomery" with any sensitive company files. Discovered that at "2025-02-05T05:45:12.1857689Z" the employee downloaded 3 sensitive research files "Q1-2025-ResearchAndDevelopment.pdf", "Q2-2025-HumanTrials.pdf", and "Q3-2025-AnimalTrials-SiberianTigers.pdf" on their device "corp-ny-it-0334". Normally the employee would not need the information in these files for their job role, despite having access to them. After downloading the files the employee moved them the the F: drive. The F: drive is a company wide shared folder and would make the files accessible by any device with access to that drive.     

```kql
DeviceFileEvents
| where DeviceName contains "corp-ny-it-0334"
| where InitiatingProcessAccountName contains "bmontgomery"
| where FileName contains "2025-"
```
<img width="1469" alt="Screenshot 2025-03-04 at 5 45 38 AM" src="https://github.com/user-attachments/assets/60ca84d7-634a-46ef-a45c-17c9c930d196" />

2. Investigated any devices or users that accessed the F: drive shortly after "2025-02-05T05:50:34.679531Z" to see if any more activity had taken place with the research files. In DeviceFileEvents between "2025-02-05T06:08:17.8607376Z" and "2025-02-05T06:09:35.6273078Z" the 3 research files were accessed on the device "lobby-fl2-ae5fc" by the account "lobbyuser". The user renamed the files to "bryce-homework-fall-2024.pdf", "Amazon-Order-123456789-Invoice.pdf", and "temp___2bbf98cf.pdf" respectively. The lobby user was attempting to avoid detection by renaming the files. On that same lobby device at "2025-02-05T06:18:59.0882396Z" the program "steghide.exe" was downloaded. This software is often used to hide documents in image files and is a commonly known obfuscation technique.   

```kql
DeviceFileEvents
| where FolderPath contains "f:"
| where DeviceName contains "lobby-fl2-ae5fc"
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, PreviousFileName
```
<img width="1467" alt="Screenshot 2025-03-04 at 6 03 09 AM" src="https://github.com/user-attachments/assets/7f7e0ca0-4e50-4ce7-aa9d-92e192aeb787" />

3. Searched DeviceEvents for any activity with the steghide software. At "2025-02-05T06:22:37.6603913Z" the software was used on the "bryce-homework-fall-2024.pdf" and "Amazon-Order-123456789-Invoice.pdf" files. Using the following commands: "steghide.exe  embed -ef bryce-homework-fall-2024.pdf -cf bryce-and-kid.bmp -p 123456 -sf c:\programdata\bryce-and-kid.bmp" and "steghide.exe  embed -ef amazon-order-123456789-invoice.pdf -cf bryce-fishing.bmp -p 123456 -sf c:\programdata\bryce-fishing.bmp" the files were hidden in the files "bryce-and-kid.bmp" and "bryce-fishing.bmp" respectively. The steghide software was also deleted from "lobby-fl2-ae5fc" at "2025-02-05T06:36:53.0523679Z" in an attempt to cover their tracks.  

```kql
DeviceEvents
| where DeviceName contains "lobby-fl2-ae5fc"
| where InitiatingProcessFileName contains "steg"
```

<img width="1468" alt="Screenshot 2025-03-04 at 6 31 18 AM" src="https://github.com/user-attachments/assets/775e0117-c7db-4667-8a06-97c33676de81" />
<img width="1467" alt="Screenshot 2025-03-04 at 6 38 49 AM" src="https://github.com/user-attachments/assets/3fd28cc8-fe33-419c-b679-bf0efd131baf" />

4. Investigated DeviceEvents for activity with files ending in .bmp. At "2025-02-05T06:34:44.0874954Z" the following command was used in order to create a zip archive with the newly created steg files ""7z.exe"  a -tzip bryce-and-kid.bmp bryce-fishing.bmp suzie-and-bob.bmp -p bryce -mem=AES256". Shortly after this command was used to encrypt and password protect the files "7z  a -tzip -p******" -mem=AES256 secure_files.zip bryce-and-kid.bmp bryce-fishing.bmp suzie-and-bob.bmp". These actions were initiated again on the "lobby-fl2-ae5fc" device and by the user "lobbyuser". The output of the encrypted zip files was called "secure_files.zip".

```kql
DeviceEvents
| where DeviceName contains "lobby-fl2-ae5fc"
| where Timestamp >= datetime(2025-02-05T06:18:59.0882396Z)
| where InitiatingProcessCommandLine contains ".bmp"
| where InitiatingProcessFileName contains "7z.exe"
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName
```
![Screenshot 2025-03-04 at 4 38 05 PM](https://github.com/user-attachments/assets/432852eb-05c7-45fa-9a15-0caaf8cd68a3)

5. Searched the DeviceFileEvent logs to identify if further action was taken on the newly created zip file "secure_files.zip". At "2025-02-05T06:46:19.3571553Z" the file was renamed to "marketing_misc.zip" by the "lobbyuser" and placed into the F: Drive.

```kql
DeviceFileEvents
| where DeviceName contains "lobby-fl2-ae5fc"
| where Timestamp >= datetime(2025-02-05T06:35:58.6268017Z)
| where PreviousFileName contains "secure"
```
![Screenshot 2025-03-04 at 4 59 15 PM](https://github.com/user-attachments/assets/2ac110ee-51c1-4e71-956c-da6e532d445d)

6. Investigated the DeviceFileEvents to identify if "bmontgomery" or "corp-ny-it-0334" interacted with the "marketing_misc.zip" in the F: Drive. The file was taken from the F: Drive at "2025-02-05T08:57:32.2582822Z" by "bmontgomery" and copied to corp-ny-it-0334". Based on the evidence it appears Bryce used his elevated privileges to access and download sensitive company files. In order to avoid suspicion and hide his actions, Bryce moved the files to the F: Drive where he could access those files, rename them, obfuscate them, and compress and encrypt them all on the public lobby computer. After performing his malicious activities he then returned the final zip file with the stolen documents to his own computer where it appears he had planned to exfiltrate it. No evidence suggest he was successful however. Based on the logs he has not yet exfiltrated the data and there is time to stop him before he causes any more harm.

```kql
DeviceFileEvents
| where DeviceName contains "corp-ny-it-0334"
| where InitiatingProcessAccountName contains "bmontgomery"
| where FileName contains "marketing"
```
![Screenshot 2025-03-04 at 5 30 09 PM](https://github.com/user-attachments/assets/b0d860f9-5011-4dbc-9f86-553a2636dbf7)

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
- **Date**: March 4th, 2025

## Validated By:
- **Reviewer Name**: Carlton Hurd
- **Reviewer Contact**: 
- **Validation Date**: March 4th, 2025 

---

## Additional Notes:
- **None**

---

## Revision History:
| **Version** | **Changes**                   | **Date**         | **Modified By**   |
|-------------|-------------------------------|------------------|-------------------|
| 1.0         | Initial draft                  | `March 4th, 2025`  | `Carlton Hurd`   

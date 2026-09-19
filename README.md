
# **Active Directory Attacks Parser**  
A lightweight C# utility that automates the collection of Windows Event Log indicators related to common Active Directory attack techniques. The tool executes embedded PowerShell queries to extract, normalize, and export relevant security telemetry into CSV files for offline analysis.

---

## **Overview**

This tool is designed for defenders, DFIR analysts, and threat hunters who need quick visibility into potential AD attack activity. It parses Windows Event Logs for known indicators of:

- **AS‑REP Roasting**  
- **Kerberoasting**  
- **LDAP Enumeration**  
- **NTDS.dit Dumping**  
- **Golden Ticket activity**  
- **NTLM Relay attempts**

All results are exported to `C:\Temp\` as CSV files for easy review in Excel, Power BI, or your preferred analysis tool.

---

## **Features**

### **1. AS‑REP Roasting Indicators**
Searches for Event ID **4768** where:
- `TicketEncryptionType = 0x17`  
- `PreAuthType = 0`  

Exports to:  
`C:\Temp\AS-REP_Roasting_Indicators.csv`

---

### **2. Kerberoasting Indicators**
Collects Event IDs **4769** and **4768**, extracts all event data fields, and exports them for service ticket analysis.

Exports to:  
`C:\Temp\Kerberoasting_4769_4768_Events.csv`

---

### **3. Users Vulnerable to AS‑REP Roasting**
Queries Active Directory for accounts with:  
`DoesNotRequirePreAuth = TRUE`

Exports to:  
`C:\Temp\Users_Vulnerable_To_AS-Rep_Roasting_Attacks.csv`

> Note: This requires running the tool on a Domain Controller or a system with RSAT + AD module access.

---

### **4. LDAP Enumeration Indicators**
Parses Event ID **4662** and groups results by `SubjectUserName` to identify accounts performing high‑volume directory queries.

Exports to:  
`C:\Temp\LDAP_Enumeration_Indicators.csv`

---

### **5. NTDS Dumping Indicators**
Collects Application log events **216**, **325**, and **327**, which may indicate attempts to access or manipulate NTDS.dit.

Exports to:  
`C:\Temp\NTDS_Dumping_Indicators.csv`

---

### **6. Golden Ticket Indicators**
Parses Event IDs **4769** and **4624**, extracting fields relevant to forged ticket activity:
- `LogonType`
- `TargetUserName`
- `IpAddress`
- `TicketOptions`
- `ServiceName`

Exports to:  
`C:\Temp\Golden_Ticket_Indicators.csv`

---

### **7. NTLM Relay Indicators**
Searches Event ID **4624** for:
- `AuthenticationPackageName = NTLM`
- Non‑empty IP addresses

Exports to:  
`C:\Temp\NTLM_Relay_Indicators.csv`

---

## **How It Works**

The program:

1. Ensures `C:\Temp\` exists (creates it if missing).  
2. Executes multiple embedded PowerShell scripts using `System.Management.Automation`.  
3. Converts each event to XML and extracts all `<EventData>` fields.  
4. Normalizes the data into `PSCustomObject` structures.  
5. Exports each dataset to CSV.  
6. Prints status messages and PowerShell errors to the console.

All PowerShell execution is sandboxed inside `using (PowerShell ps = PowerShell.Create())` blocks.

---

## **Requirements**

- Windows Server or Windows workstation with Security and Application logs available  
- .NET Framework / .NET runtime capable of running the compiled executable  
- PowerShell 5.1+  
- (Optional) RSAT Active Directory module for Part 3  
- Administrative privileges recommended for full log access

---

## **Usage**

1. Compile the project in Visual Studio or via `dotnet build`.  
2. Run the executable as Administrator:  
   ```
   Active-Directory-Attacks-Parser.exe
   ```
3. Review generated CSV files in `C:\Temp\`.

---

## **Output Directory**

All results are saved to:

```
C:\Temp\
```

Files include:

- `AS-REP_Roasting_Indicators.csv`
- `Kerberoasting_4769_4768_Events.csv`
- `Users_Vulnerable_To_AS-Rep_Roasting_Attacks.csv`
- `LDAP_Enumeration_Indicators.csv`
- `NTDS_Dumping_Indicators.csv`
- `Golden_Ticket_Indicators.csv`
- `NTLM_Relay_Indicators.csv`

---

## **Notes**

- This tool **does not perform detection or scoring** — it only extracts relevant telemetry.  
- Human analysis is required to determine whether events represent malicious activity.  
- Use the output as part of broader threat hunting or DFIR workflows.

---

## **License**

MIT License

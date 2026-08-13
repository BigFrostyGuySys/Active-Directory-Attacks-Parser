using System;
using System.Management.Automation;

class Program
{
    static void Main(string[] args)
    {

        //Check for path existence and create if not present
        if (!Directory.Exists("C:\\Temp"))
        {
            Directory.CreateDirectory("C:\\Temp");
        }


        // -------------------------
        // Run PowerShell script to gather potential AS-REP roasting indicators (Event ID 4768, TicketEncryptionType 0x17, PreAuthType 0) and export to CSV
        // -------------------------
        Console.WriteLine("Part 1: Gathering potential AS-REP roasting indicators....");
        using (PowerShell ps = PowerShell.Create())
        {
            string script = @"
                Get-WinEvent -FilterHashtable @{
                    LogName = 'Security'
                    ID      = 4768
                } | ForEach-Object {
                    $xml = [xml]$_.ToXml()
                    $props = [Ordered]@{
                        EventTime = $_.TimeCreated
                        EventID = $_.Id
                    }

                    foreach ($data in $xml.Event.EventData.Data) {
                        $props[$data.Name] = $data.'#text'
                    }
                    [PSCustomObject]$props
                } | Where {$_.TicketEncryptionType -eq '0x17' -and $_.PreAuthType -eq '0'} | Export-ToCsv -Path 'C:\\Temp\\AS-REP_Roasting_Indicators.csv' 
            ";
            ps.AddScript(script);
            var results = ps.Invoke();

            // Handle empty results FIRST
            if (results.Count == 0)
            {
                Console.WriteLine("No AS-REP roasting indicators found.");
            }
            else
                //            {
                //                foreach (var line in results)
                //                    Console.WriteLine(line.ToString());
                //            }

                // Handle actual PowerShell errors SECOND
                if (ps.Streams.Error.Count > 0)
                {
                    Console.WriteLine("PowerShell Error:");
                    foreach (var err in ps.Streams.Error)
                        Console.WriteLine(err.ToString());
                }
        }

        // -------------------------
        // Run PowerShell script to gather potential kerberoasting indicators (Event IDs 4769 and 4768) and export to CSV
        // -------------------------
        Console.WriteLine("Part 2: Gathering potential kerberoasting indicators....");

        using (PowerShell ps = PowerShell.Create())
        {
            string script = @"
                Get-WinEvent -FilterHashtable @{
                    LogName = 'Security'
                    ID      = 4769,4768
                } | ForEach-Object {
                    $xml = [xml]$_.ToXml()
                    $props = [Ordered]@{
                        TimeCreated = $_.TimeCreated
                        EventID = $_.Id
                    }

                    foreach ($data in $xml.Event.EventData.Data) {
                        $props[$data.Name] = $data.'#text'
                    }
                    [PSCustomObject]$props
                } | Export-ToCsv -Path 'C:\\Temp\\Kerberoasting_4769_4768_Events.csv' 
            ";

            ps.AddScript(script);
            var results = ps.Invoke();

            // Handle empty results FIRST
            if (results.Count == 0)
            {
                Console.WriteLine("No 4769 or 4768 events found.");
            }
            else
                //            {
                //                foreach (var line in results)
                //                    Console.WriteLine(line.ToString());
                //            }

                // Handle actual PowerShell errors SECOND
                if (ps.Streams.Error.Count > 0)
                {
                    Console.WriteLine("PowerShell Error:");
                    foreach (var err in ps.Streams.Error)
                        Console.WriteLine(err.ToString());
                }
        }

        // -------------------------
        // Run PowerShell script to gather AD users vulnerable to AS-Rep Roasting attacks....
        // -------------------------
        Console.WriteLine("Part 3: Gathering AD Users vulnerable to AS-Rep Roasting attacks....");
        using (PowerShell ps = PowerShell.Create())
        {
            Console.WriteLine("Checking for users with 'DoesNotRequirePreAuth' set to TRUE...");
            string script = "Get-ADUser -Filter * -Properties DoesNotRequirePreAuth | Where {$_.DoesNotRequirePreAuth -eq $TRUE} | Export-Csv -Path 'C:\\Temp\\Users_Vulnerable_To_AS-Rep_Roasting_Attacks.csv'";
            ps.AddScript(script);

            var results = ps.Invoke();

            // Handle empty results FIRST
            if (results.Count == 0)
            {
                Console.WriteLine("******Unable to check for Preauthentication settings. Please run this application on a Domain Controller\"");
            }
            else
                //            {
                //                foreach (var line in results)
                //                    Console.WriteLine(line.ToString());
                //            }

                // Handle actual PowerShell errors SECOND
                if (ps.Streams.Error.Count > 0)
                {
                    Console.WriteLine("PowerShell Error:");
                    foreach (var err in ps.Streams.Error)
                        Console.WriteLine(err.ToString());
                }
        }
        // -------------------------
        // Run PowerShell script to gather potential LDAP Enumeration indicators (Event ID 4662) and perform a group-by operation.  Export to CSV
        // -------------------------
        Console.WriteLine("Part 4: Gathering potential LDAP Enumeration indicators....");

        using (PowerShell ps = PowerShell.Create())
        {
            string script = @"
                Get-WinEvent -FilterHashtable @{
                    LogName = 'Security'
                    ID      = 4662
                } | ForEach-Object {
                    $xml = [xml]$_.ToXml()
                    $props = [Ordered]@{
                        TimeCreated = $_.TimeCreated
                        EventID = $_.Id
                    }

                    foreach ($data in $xml.Event.EventData.Data) {
                        $props[$data.Name] = $data.'#text'
                    }
                    [PSCustomObject]$props
                }| Group-Object SubjectUserName| Sort-Object Count -Descending| Select-Object Count, Name | Export-ToCsv -Path 'C:\\Temp\\LDAP_Enumeration_Indicators.csv' 
            ";

            ps.AddScript(script);
            var results = ps.Invoke();

            // Handle empty results FIRST
            if (results.Count == 0)
            {
                Console.WriteLine("No LDAP Enumeration events found.");
            }
            else
                //            {
                //                foreach (var line in results)
                //                    Console.WriteLine(line.ToString());
                //            }

                // Handle actual PowerShell errors SECOND
                if (ps.Streams.Error.Count > 0)
                {
                    Console.WriteLine("PowerShell Error:");
                    foreach (var err in ps.Streams.Error)
                        Console.WriteLine(err.ToString());
                }
        }

        // -------------------------
        // Run PowerShell script to gather potential NTDS Dumping indicators -- Export to CSV
        // -------------------------
        Console.WriteLine("Part 5: Gathering potential NTDS Dumping indicators....");

        using (PowerShell ps = PowerShell.Create())
        {
            string script = @"
                Get-WinEvent -FilterHashtable @{
                    LogName = 'Application'
                    ID      = 216,325,327
                } | ForEach-Object {
                    $xml = [xml]$_.ToXml()
                    $props = [Ordered]@{
                        TimeCreated = $_.TimeCreated
                        EventID = $_.Id
                    }

                    foreach ($data in $xml.Event.EventData.Data) {
                        $props[$data.Name] = $data.'#text'
                    }
                    [PSCustomObject]$props
                } Export-ToCsv -Path 'C:\\Temp\\NTDS_Dumping_Indicators.csv' 
            ";

            ps.AddScript(script);
            var results = ps.Invoke();

            // Handle empty results FIRST
            if (results.Count == 0)
            {
                Console.WriteLine("No NTDS Dumping events found, or logs are unavailable.");
            }
            else
                //            {
                //                foreach (var line in results)
                //                    Console.WriteLine(line.ToString());
                //            }

                // Handle actual PowerShell errors SECOND
                if (ps.Streams.Error.Count > 0)
                {
                    Console.WriteLine("PowerShell Error:");
                    foreach (var err in ps.Streams.Error)
                        Console.WriteLine(err.ToString());
                }
        }


        // -------------------------
        // Run PowerShell script to gather potential Golden Ticket indicators -- Export to CSV
        // -------------------------
        Console.WriteLine("Part 6: Gathering potential Golden Ticket indicators....");

        using (PowerShell ps = PowerShell.Create())
        {
            string script = @"
                Get-WinEvent -FilterHashtable @{
                    LogName = 'Security'
                    ID      = 4769, 4624
                } | ForEach-Object {
                    $xml = [xml]$_.ToXml()
                    $props = [Ordered]@{
                        TimeCreated = $_.TimeCreated
                        EventID = $_.Id
                    }

                    foreach ($data in $xml.Event.EventData.Data) {
                        $props[$data.Name] = $data.'#text'
                    }
                    [PSCustomObject]$props
                }| Select-Object TimeCreated, EventID, LogonType, TargetUserName, IpAddress, TicketOptions, ServiceName |  Export-ToCsv -Path 'C:\\Temp\\Golden_Ticket_Indicators.csv' -Append
            ";

            ps.AddScript(script);
            var results = ps.Invoke();

            // Handle empty results FIRST
            if (results.Count == 0)
            {
                Console.WriteLine("No Golden Ticket indicators found, or logs are unavailable.");
            }
            else
                //            {
                //                foreach (var line in results)
                //                    Console.WriteLine(line.ToString());
                //            }

                // Handle actual PowerShell errors SECOND
                if (ps.Streams.Error.Count > 0)
                {
                    Console.WriteLine("PowerShell Error:");
                    foreach (var err in ps.Streams.Error)
                        Console.WriteLine(err.ToString());
                }
        }


        // -------------------------
        // Run PowerShell script to gather potential NTLM Relay indicators -- Export to CSV
        // -------------------------
        Console.WriteLine("Part 7: Gathering potential NTLM Relay indicators....");

        using (PowerShell ps = PowerShell.Create())
        {
            string script = @"
                Get-WinEvent -FilterHashtable @{
                    LogName = 'Security'
                    ID      = 4624
                } | ForEach-Object {
                    $xml = [xml]$_.ToXml()
                    $props = [Ordered]@{
                        TimeCreated = $_.TimeCreated
                        EventID = $_.Id
                    }

                    foreach ($data in $xml.Event.EventData.Data) {
                        $props[$data.Name] = $data.'#text'
                    }
                    [PSCustomObject]$props
                }| Select-Object TimeCreated, TargetUserName, IpAddress, WorkstationName, AuthenticationPackageName | Where-Object { $_.AuthenticationPackageName -eq 'NTLM' -and $_.IpAddress -ne '-' } |  Export-ToCsv -Path 'C:\\Temp\\NTLM_Relay_Indicators.csv' -Append
            ";

            ps.AddScript(script);
            var results = ps.Invoke();

            // Handle empty results FIRST
            if (results.Count == 0)
            {
                Console.WriteLine("No NTLM Relay events found, or logs are unavailable.");
            }
            else
                //            {
                //                foreach (var line in results)
                //                    Console.WriteLine(line.ToString());
                //            }

                // Handle actual PowerShell errors SECOND
                if (ps.Streams.Error.Count > 0)
                {
                    Console.WriteLine("PowerShell Error:");
                    foreach (var err in ps.Streams.Error)
                        Console.WriteLine(err.ToString());
                }
        }
        Console.WriteLine();
        Console.WriteLine();
        Console.WriteLine();
        Console.WriteLine();
        Console.WriteLine();
        Console.WriteLine();
        Console.WriteLine();
        Console.WriteLine();
        Console.WriteLine();
        Console.WriteLine("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~   ");
        Console.WriteLine("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~   ");
        Console.WriteLine("**  Finished parsing.                                                      ");
        Console.WriteLine("**  Results exported to CSV files in C:\\Temp\\ directory.                 ");
        Console.WriteLine("**  Use your favorite CSV viewer to analyze the results.                   ");
        Console.WriteLine("**  Use known threat hunting techniques when identifying potential threats.");
        Console.WriteLine("**  This tool only provides the data, the human must provide the analysis. ");
        Console.WriteLine("**  Leverage the Readme for documentation.                                 ");
        Console.WriteLine("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~  ");
        Console.WriteLine("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~  ");

        Console.ReadLine();
    }
}
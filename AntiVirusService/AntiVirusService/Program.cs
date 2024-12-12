using System;
using System.IO;
using System.ServiceProcess;
using System.Diagnostics;
using System.Threading;
using System.IO.MemoryMappedFiles;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading.Tasks;
using Newtonsoft.Json.Linq;
using System.Text;

public class AntivirusSampleWindowsService : ServiceBase
{
    private const string apiKey = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"; //Get one from virustotal.com
    private const string baseUri = "https://www.virustotal.com/api/v3/";

    private EventWaitHandle _eventWaitHandle; //This event receives the request from the client... at this point I implement an easy to understand code where I don't process multiple requests at the same time... a real AV should handle multiple requests at the same time
    private EventWaitHandle _eventWaitHandle_ResponseToClient; //This event is used to handle the answer from this service to the client
    private MemoryMappedFile _memoryMappedFile; //Shared memory object... used to write information from the client to the service, and viceversa
    private const string MemoryMappedFileName = "Global\\AntivirusSampleServiceMemory"; //Name of the shared memory
    private const int MemoryMappedFileCapacity = 1024*2; //Enough to hold a Unicode path

    /*************************************************************************/
    public AntivirusSampleWindowsService()
    {
        ServiceName = "Antivirus Sample service";
        EventLog.Log = "Application";

        CanStop = true;
        CanPauseAndContinue = true;
        AutoLog = true;

        // Configure security for the event so it grants full access to client app
        EventWaitHandleSecurity eventSecurity = new EventWaitHandleSecurity();
        eventSecurity.AddAccessRule(new EventWaitHandleAccessRule(
            new SecurityIdentifier(WellKnownSidType.NetworkServiceSid, null),
            EventWaitHandleRights.FullControl,
            AccessControlType.Allow));
        eventSecurity.AddAccessRule(new EventWaitHandleAccessRule(
            new SecurityIdentifier(WellKnownSidType.WorldSid, null),
            EventWaitHandleRights.FullControl/* EventWaitHandleRights.Modify | EventWaitHandleRights.Synchronize*/, //Give full control since else it will not work properly
            AccessControlType.Allow));
        // Initialize the events with the same security settings
        bool createdNew;
        _eventWaitHandle = new EventWaitHandle(false, EventResetMode.ManualReset, "Global\\AntivirusSampleServiceEvent", out createdNew, eventSecurity);
        _eventWaitHandle_ResponseToClient = new EventWaitHandle(false, EventResetMode.ManualReset, "Global\\AntivirusSampleServiceEvent_ResponseToClient", out createdNew, eventSecurity);

        // Configure security for the shared memory so it grants read write permissions to client app
        MemoryMappedFileSecurity security = new MemoryMappedFileSecurity();
        security.AddAccessRule(new AccessRule<MemoryMappedFileRights>(
            new SecurityIdentifier(WellKnownSidType.NetworkServiceSid, null),
            MemoryMappedFileRights.FullControl,
            AccessControlType.Allow));
        security.AddAccessRule(new AccessRule<MemoryMappedFileRights>(
            new SecurityIdentifier(WellKnownSidType.WorldSid, null),
            MemoryMappedFileRights.ReadWrite,
            AccessControlType.Allow));
        _memoryMappedFile = MemoryMappedFile.CreateOrOpen(MemoryMappedFileName, MemoryMappedFileCapacity, MemoryMappedFileAccess.ReadWrite, MemoryMappedFileOptions.None, security, HandleInheritability.None);
    }

    /*************************************************************************/
    protected override void OnStart(string[] args)
    {
        EventLog.WriteEntry("Antivirus Sample service started.");
        // Start a background thread to listen for the event signal
        Thread listenerThread = new Thread(ListenForEvent);
        listenerThread.IsBackground = true;
        listenerThread.Start();
    }

    /*************************************************************************/
    protected override void OnStop()
    {
        EventLog.WriteEntry("Antivirus Sample service stopped.");
        // Signal the event to allow the listener thread to complete
        _eventWaitHandle.Set();
        _eventWaitHandle_ResponseToClient.Set();
        _memoryMappedFile?.Dispose();
    }

    /*************************************************************************/
    private async void ListenForEvent()
    {
        EventLog.WriteEntry("Antivirus Sample service: Listening for requests from clients...");
        // Loop and wait for the event to be signaled
        while (true)
        {
            // Wait until the event is signaled
            _eventWaitHandle.WaitOne();

            // Do some action when the event is signaled
            EventLog.WriteEntry("Antivirus Sample service: Request received", EventLogEntryType.Information);

            string szFilePathToAnalyze = ReadFilePathFromSharedMemory();
            bool bIsMalware = false;
            if (!string.IsNullOrEmpty(szFilePathToAnalyze))
            {
                if (System.IO.File.Exists(szFilePathToAnalyze) == false)
                {
                    bIsMalware = false;
                    EventLog.WriteEntry("Antivirus Sample service: This file does not exist: \"" + szFilePathToAnalyze + "\"", EventLogEntryType.Information);
                }
                else
                {
                    EventLog.WriteEntry("Antivirus Sample service: Analyzing \"" + szFilePathToAnalyze + "\"", EventLogEntryType.Information);
                    string analysisId = await UploadFileToVirusTotal(szFilePathToAnalyze);
                    bIsMalware = await CheckFileAnalysis(analysisId, szFilePathToAnalyze);
                    EventLog.WriteEntry("Antivirus Sample service: Result: " + (bIsMalware ? "Is a malware" : "It is safe"));
                }
            } else
            {
                EventLog.WriteEntry("Antivirus Sample service: File Path not specified.", EventLogEntryType.Information);
            }

            //Give the answer to the client...
            using (MemoryMappedViewStream stream = _memoryMappedFile.CreateViewStream())
            {
                using (StreamWriter writer = new StreamWriter(stream))
                {
                    writer.WriteLine(bIsMalware?"MALWARE\0":"SAFE\0");
                    writer.Flush();
                }
            }
            //Awake the client
            _eventWaitHandle_ResponseToClient.Set();

            // Reset the event so it can be triggered again
            _eventWaitHandle.Reset();
        }
    }

    /*************************************************************************/
    private string ReadFilePathFromSharedMemory()
    {
        try
        {
            using (MemoryMappedViewStream stream = _memoryMappedFile.CreateViewStream())
            {
                using (StreamReader reader = new StreamReader(stream))
                {
                    // Read the file path from the shared memory
                    string szToReturn = reader.ReadLine();
                    if( szToReturn.Contains("\0")) szToReturn= szToReturn.Replace("\0", string.Empty);
                    if (szToReturn.Contains("|")) szToReturn = szToReturn.Replace("|", string.Empty);
                    return szToReturn;

                }
            }
        }
        catch (Exception ex)
        {
            EventLog.WriteEntry($"Error reading from shared memory: {ex.Message}", EventLogEntryType.Error);
            return null;
        }
    }

    /*************************************************************************/
    private static async Task<string> UploadFileToVirusTotal(string filePath)
    {
        using (HttpClient client = new HttpClient())
        {
            client.DefaultRequestHeaders.Add("x-apikey", apiKey);

            using (var multipartContent = new MultipartFormDataContent())
            {
                var fileContent = new ByteArrayContent(File.ReadAllBytes(filePath));
                fileContent.Headers.ContentType = MediaTypeHeaderValue.Parse("application/octet-stream");
                multipartContent.Add(fileContent, "file", Path.GetFileName(filePath));

                HttpResponseMessage response = await client.PostAsync(baseUri + "files", multipartContent);

                if (response.IsSuccessStatusCode)
                {
                    string responseBody = await response.Content.ReadAsStringAsync();
                    var jsonResponse = JObject.Parse(responseBody);
                    return jsonResponse["data"]["id"]?.ToString();
                }
                else
                {
                    return null;
                }
            }
        }
    }

    /*************************************************************************/
    private async Task<bool> CheckFileAnalysis(string analysisId, string szFilePathToAnalyze)
    {
        using (HttpClient client = new HttpClient())
        {
            client.DefaultRequestHeaders.Add("x-apikey", apiKey);

            HttpResponseMessage response = await client.GetAsync(baseUri + "analyses/" + analysisId);

            if (response.IsSuccessStatusCode)
            {
                string responseBody = await response.Content.ReadAsStringAsync();
                var jsonResponse = JObject.Parse(responseBody);

                var stats = jsonResponse["data"]["attributes"]["stats"];
                var status = jsonResponse["data"]["attributes"]["status"];
                if ( status!=null )
                {
                    if ( status.ToString().ToUpper()=="QUEUED")
                    {
                        Thread.Sleep(1000);
                        EventLog.WriteEntry("Antivirus Sample service: The analysis was queued. Retrying...");
                        analysisId = await UploadFileToVirusTotal(szFilePathToAnalyze);
                        bool bToRet = await CheckFileAnalysis(analysisId, szFilePathToAnalyze);
                        return bToRet;
                    }
                }
                int malicious = (int)stats["malicious"];
                int harmless = (int)stats["harmless"];

                if (malicious > 0)
                {
                    return true;
                }
                else
                {
                    return false;
                }
            }
            else
            {
                return false;
            }
        }
    }

    /*************************************************************************/
    public static void Main()
    {
        ServiceBase.Run(new AntivirusSampleWindowsService());
    }
}


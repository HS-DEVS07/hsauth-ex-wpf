using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Json;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Threading;

namespace HSAUTH
{
    /// <summary>
    /// Official HS DEVS AUTH C# Client SDK
    /// High-performance, zero-dependency authentication client.
    /// Supports .NET Framework 4.6+, .NET Core 3.1+, .NET 6, 7, 8+.
    /// </summary>
    public class api
    {
        public string name { get; set; }
        public string ownerid { get; set; }
        public string version { get; set; }
        public string secret { get; set; }
        public string apiUrl { get; set; }

        public static string sessionid { get; set; }
        public bool initialized { get; private set; }

        public user_data_structure user_data = new user_data_structure();
        public app_data_structure app_data = new app_data_structure();
        public response_structure response = new response_structure();

        // Real-Time In-App Live Messaging & Killswitch Callback
        public event Action<ActiveMessage> OnMessageReceived;

        private Thread heartbeatThread;
        private bool heartbeatRunning = false;

        /// <summary>
        /// Initialize HS DEVS AUTH Application credentials
        /// </summary>
        public api(string name, string ownerid, string version, string apiUrl = "https://api.hsauth.mujahid.xyz/api/1.3/")
            : this(name, ownerid, "", version, apiUrl)
        {
        }

        /// <summary>
        /// Initialize HS DEVS AUTH Application credentials (with secret)
        /// </summary>
        public api(string name, string ownerid, string secret, string version, string apiUrl = "https://api.hsauth.mujahid.xyz/api/1.3/")
        {
            if (string.IsNullOrEmpty(name) || string.IsNullOrEmpty(ownerid))
            {
                error("Application credentials cannot be empty.");
            }

            this.name = name;
            this.ownerid = ownerid;
            this.secret = secret ?? "";
            this.version = string.IsNullOrEmpty(version) ? "1.0" : version;
            this.apiUrl = apiUrl.TrimEnd('/') + "/";
        }

        #region Structures
        [DataContract]
        public class response_structure
        {
            [DataMember] public bool success { get; set; }
            [DataMember] public string sessionid { get; set; }
            [DataMember] public string message { get; set; }
            [DataMember] public string response { get; set; }
            [DataMember] public string download { get; set; }
            [DataMember] public string contents { get; set; }
            [DataMember] public string ownerid { get; set; }
            [DataMember] public user_data_structure info { get; set; }
            [DataMember] public app_data_structure appinfo { get; set; }
            [DataMember] public ActiveMessage active_message { get; set; }
            [DataMember] public List<users> users { get; set; }
        }

        [DataContract]
        public class ActiveMessage
        {
            [DataMember] public string id { get; set; }
            [DataMember] public string type { get; set; } // modal, banner, killswitch
            [DataMember] public string title { get; set; }
            [DataMember] public string content { get; set; }
        }

        [DataContract]
        public class user_data_structure
        {
            [DataMember] public string username { get; set; }
            [DataMember] public string ip { get; set; }
            [DataMember] public string hwid { get; set; }
            [DataMember] public string createdate { get; set; }
            [DataMember] public string lastlogin { get; set; }
            [DataMember] public List<Data> subscriptions { get; set; } = new List<Data>();
        }

        [DataContract]
        public class Data
        {
            [DataMember] public string subscription { get; set; }
            [DataMember] public string key { get; set; }
            [DataMember] public string expiry { get; set; }
            [DataMember] public string timeleft { get; set; }
        }

        [DataContract]
        public class app_data_structure
        {
            [DataMember] public string numUsers { get; set; }
            [DataMember] public string numOnlineUsers { get; set; }
            [DataMember] public string numKeys { get; set; }
            [DataMember] public string version { get; set; }
            [DataMember] public string customerPanelLink { get; set; }
            [DataMember] public string downloadLink { get; set; }
        }

        [DataContract]
        public class users
        {
            [DataMember] public string credential { get; set; }
        }
        #endregion

        #region Core Authentication Methods

        /// <summary>
        /// Handshakes with HS DEVS AUTH server and initializes secure session
        /// </summary>
        public void init()
        {
            var values = new NameValueCollection
            {
                ["type"] = "init",
                ["ver"] = version,
                ["hash"] = getChecksum(),
                ["name"] = name,
                ["ownerid"] = ownerid
            };

            var raw = req(values);
            if (raw == "HSAUTH_Invalid" || raw.Contains("Invalid app_identifier"))
            {
                error("Application not found. Please verify your Name and OwnerID.");
                return;
            }

            var json = parse_json<response_structure>(raw);
            load_response_struct(json);

            if (json.success)
            {
                sessionid = json.sessionid;
                initialized = true;
                if (json.appinfo != null)
                {
                    app_data = json.appinfo;
                }
            }
            else if (json.message == "invalidver")
            {
                if (!string.IsNullOrEmpty(json.download))
                {
                    try { Process.Start(new ProcessStartInfo(json.download) { UseShellExecute = true }); } catch { }
                }
                error("New version available. Application will now close.");
            }
            else
            {
                error(json.message ?? "Initialization failed.");
            }
        }

        /// <summary>
        /// Login using registered Username and Password
        /// </summary>
        public void login(string username, string pass)
        {
            CheckInit();

            var values = new NameValueCollection
            {
                ["type"] = "login",
                ["username"] = username,
                ["pass"] = pass,
                ["hwid"] = get_hwid(),
                ["sessionid"] = sessionid,
                ["name"] = name,
                ["ownerid"] = ownerid
            };

            var raw = req(values);
            var json = parse_json<response_structure>(raw);
            load_response_struct(json);

            if (json.success)
            {
                if (json.info != null) user_data = json.info;
                if (!string.IsNullOrEmpty(json.sessionid)) sessionid = json.sessionid;
                checkActiveMessage(json.active_message);
            }
        }

        /// <summary>
        /// Register a new account with a License Key
        /// </summary>
        public void register(string username, string pass, string key, string email = "")
        {
            CheckInit();

            var values = new NameValueCollection
            {
                ["type"] = "register",
                ["username"] = username,
                ["pass"] = pass,
                ["key"] = key,
                ["email"] = email,
                ["hwid"] = get_hwid(),
                ["sessionid"] = sessionid,
                ["name"] = name,
                ["ownerid"] = ownerid
            };

            var raw = req(values);
            var json = parse_json<response_structure>(raw);
            load_response_struct(json);

            if (json.success)
            {
                if (json.info != null) user_data = json.info;
                if (!string.IsNullOrEmpty(json.sessionid)) sessionid = json.sessionid;
                checkActiveMessage(json.active_message);
            }
        }

        /// <summary>
        /// Authenticate directly with a License Key (Key-only mode)
        /// </summary>
        public void license(string key)
        {
            CheckInit();

            var values = new NameValueCollection
            {
                ["type"] = "license",
                ["key"] = key,
                ["hwid"] = get_hwid(),
                ["sessionid"] = sessionid,
                ["name"] = name,
                ["ownerid"] = ownerid
            };

            var raw = req(values);
            var json = parse_json<response_structure>(raw);
            load_response_struct(json);

            if (json.success)
            {
                if (json.info != null) user_data = json.info;
                if (!string.IsNullOrEmpty(json.sessionid)) sessionid = json.sessionid;
                checkActiveMessage(json.active_message);
            }
        }

        /// <summary>
        /// Check session status and receive live broadcast messages / killswitches
        /// </summary>
        public void check()
        {
            CheckInit();

            var values = new NameValueCollection
            {
                ["type"] = "check",
                ["sessionid"] = sessionid,
                ["name"] = name,
                ["ownerid"] = ownerid
            };

            var raw = req(values);
            var json = parse_json<response_structure>(raw);
            load_response_struct(json);

            if (json.success)
            {
                checkActiveMessage(json.active_message);
            }
        }

        /// <summary>
        /// Terminate the current session and logout
        /// </summary>
        public void logout()
        {
            CheckInit();
            stop_heartbeat();

            var values = new NameValueCollection
            {
                ["type"] = "logout",
                ["sessionid"] = sessionid,
                ["name"] = name,
                ["ownerid"] = ownerid
            };

            var raw = req(values);
            var json = parse_json<response_structure>(raw);
            load_response_struct(json);
            sessionid = null;
        }

        #endregion

        #region Application Features (Vars, Files, Logs, Webhooks)

        /// <summary>
        /// Get a remote server variable by variable ID or Name
        /// </summary>
        public string var(string varid)
        {
            CheckInit();

            var values = new NameValueCollection
            {
                ["type"] = "var",
                ["varid"] = varid,
                ["sessionid"] = sessionid,
                ["name"] = name,
                ["ownerid"] = ownerid
            };

            var raw = req(values);
            var json = parse_json<response_structure>(raw);
            load_response_struct(json);

            return json.success ? (json.message ?? json.response) : null;
        }

        public string getvar(string varname) => var(varname);

        /// <summary>
        /// Set a variable on the server
        /// </summary>
        public void setvar(string varname, string vardata)
        {
            CheckInit();

            var values = new NameValueCollection
            {
                ["type"] = "setvar",
                ["var"] = varname,
                ["data"] = vardata,
                ["sessionid"] = sessionid,
                ["name"] = name,
                ["ownerid"] = ownerid
            };

            var raw = req(values);
            var json = parse_json<response_structure>(raw);
            load_response_struct(json);
        }

        /// <summary>
        /// Securely download file content or remote URL
        /// </summary>
        public byte[] download(string fileid)
        {
            CheckInit();

            var values = new NameValueCollection
            {
                ["type"] = "file",
                ["fileid"] = fileid,
                ["sessionid"] = sessionid,
                ["name"] = name,
                ["ownerid"] = ownerid
            };

            var raw = req(values);
            var json = parse_json<response_structure>(raw);
            load_response_struct(json);

            if (json.success && !string.IsNullOrEmpty(json.contents))
            {
                // If it's a URL, download content; if raw string, encode
                if (json.contents.StartsWith("http://") || json.contents.StartsWith("https://"))
                {
                    using (WebClient wc = new WebClient())
                    {
                        return wc.DownloadData(json.contents);
                    }
                }
                return Encoding.UTF8.GetBytes(json.contents);
            }
            return null;
        }

        /// <summary>
        /// Send a diagnostic/security log to the developer dashboard
        /// </summary>
        public void log(string message)
        {
            CheckInit();

            var values = new NameValueCollection
            {
                ["type"] = "log",
                ["pcuser"] = Environment.UserName,
                ["message"] = message,
                ["sessionid"] = sessionid,
                ["name"] = name,
                ["ownerid"] = ownerid
            };

            req(values);
        }

        /// <summary>
        /// Ban the current logged in user
        /// </summary>
        public void ban(string reason = null)
        {
            CheckInit();

            var values = new NameValueCollection
            {
                ["type"] = "ban",
                ["reason"] = reason ?? "Banned by client action",
                ["sessionid"] = sessionid,
                ["name"] = name,
                ["ownerid"] = ownerid
            };

            var raw = req(values);
            var json = parse_json<response_structure>(raw);
            load_response_struct(json);
        }

        /// <summary>
        /// Fetch online active session users
        /// </summary>
        public List<users> fetchOnline()
        {
            CheckInit();

            var values = new NameValueCollection
            {
                ["type"] = "fetchOnline",
                ["sessionid"] = sessionid,
                ["name"] = name,
                ["ownerid"] = ownerid
            };

            var raw = req(values);
            var json = parse_json<response_structure>(raw);
            load_response_struct(json);

            return json.success ? (json.users ?? new List<users>()) : new List<users>();
        }

        /// <summary>
        /// Refresh application counters (users, licenses, online)
        /// </summary>
        public void fetchStats()
        {
            CheckInit();

            var values = new NameValueCollection
            {
                ["type"] = "fetchStats",
                ["sessionid"] = sessionid,
                ["name"] = name,
                ["ownerid"] = ownerid
            };

            var raw = req(values);
            var json = parse_json<response_structure>(raw);
            load_response_struct(json);

            if (json.success && json.appinfo != null)
            {
                app_data = json.appinfo;
            }
        }

        /// <summary>
        /// Change the username of the logged-in user
        /// </summary>
        public void changeUsername(string newUsername)
        {
            CheckInit();

            var values = new NameValueCollection
            {
                ["type"] = "changeUsername",
                ["newUsername"] = newUsername,
                ["sessionid"] = sessionid,
                ["name"] = name,
                ["ownerid"] = ownerid
            };

            var raw = req(values);
            var json = parse_json<response_structure>(raw);
            load_response_struct(json);
        }

        #endregion

        #region Background Heartbeat & Live Broadcast Handling

        /// <summary>
        /// Starts background heartbeat loop to pulse session and receive in-app announcements / killswitch
        /// </summary>
        public void start_heartbeat(int intervalSeconds = 30)
        {
            if (heartbeatRunning) return;
            heartbeatRunning = true;

            heartbeatThread = new Thread(() =>
            {
                while (heartbeatRunning)
                {
                    Thread.Sleep(intervalSeconds * 1000);
                    if (!heartbeatRunning) break;
                    try
                    {
                        check();
                    }
                    catch { }
                }
            })
            {
                IsBackground = true
            };
            heartbeatThread.Start();
        }

        /// <summary>
        /// Stops the background heartbeat thread
        /// </summary>
        public void stop_heartbeat()
        {
            heartbeatRunning = false;
            try
            {
                heartbeatThread?.Abort();
            }
            catch { }
        }

        private void checkActiveMessage(ActiveMessage msg)
        {
            if (msg != null && !string.IsNullOrEmpty(msg.title))
            {
                OnMessageReceived?.Invoke(msg);

                // Auto-acknowledge so it won't repeat
                try
                {
                    var values = new NameValueCollection
                    {
                        ["message_id"] = msg.id,
                        ["hwid"] = get_hwid()
                    };
                    using (WebClient wc = new WebClient())
                    {
                        wc.Headers[HttpRequestHeader.ContentType] = "application/x-www-form-urlencoded";
                        wc.UploadValues(apiUrl.Replace("/api/1.3/", "/api/v1/app/messages/ack"), values);
                    }
                }
                catch { }
            }
        }

        #endregion

        #region Utilities & HWID

        public void CheckInit()
        {
            if (!initialized)
            {
                error("You must call HSAuthApp.init() before executing any actions.");
            }
        }

        private void load_response_struct(response_structure data)
        {
            this.response.success = data.success;
            this.response.message = data.message;
            this.response.sessionid = data.sessionid;
            this.response.response = data.response;
            this.response.contents = data.contents;
            this.response.ownerid = data.ownerid;
            this.response.info = data.info;
            this.response.appinfo = data.appinfo;
            this.response.active_message = data.active_message;
        }

        /// <summary>
        /// Cross-platform and resilient Hardware ID detection
        /// </summary>
        public static string get_hwid()
        {
            try
            {
                // 1. Windows Cryptography MachineGuid (Most stable on Windows)
                if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                {
                    try
                    {
                        using (var key = Microsoft.Win32.RegistryKey.OpenBaseKey(Microsoft.Win32.RegistryHive.LocalMachine, Microsoft.Win32.RegistryView.Registry64))
                        using (var subkey = key.OpenSubKey(@"SOFTWARE\Microsoft\Cryptography"))
                        {
                            var guid = subkey?.GetValue("MachineGuid")?.ToString();
                            if (!string.IsNullOrEmpty(guid)) return guid;
                        }
                    }
                    catch { }

                    // 2. Windows User SID
                    try
                    {
                        var sid = WindowsIdentity.GetCurrent().User?.Value;
                        if (!string.IsNullOrEmpty(sid)) return sid;
                    }
                    catch { }
                }

                // 3. Fallback: MachineName + Network Interface MAC + Processor Hash
                StringBuilder sb = new StringBuilder();
                sb.Append(Environment.MachineName);
                sb.Append(Environment.ProcessorCount);
                sb.Append(Environment.OSVersion.VersionString);

                try
                {
                    foreach (NetworkInterface nic in NetworkInterface.GetAllNetworkInterfaces())
                    {
                        if (nic.OperationalStatus == OperationalStatus.Up && nic.NetworkInterfaceType != NetworkInterfaceType.Loopback)
                        {
                            sb.Append(nic.GetPhysicalAddress().ToString());
                            break;
                        }
                    }
                }
                catch { }

                using (SHA256 sha = SHA256.Create())
                {
                    byte[] hash = sha.ComputeHash(Encoding.UTF8.GetBytes(sb.ToString()));
                    StringBuilder hex = new StringBuilder(hash.Length * 2);
                    foreach (byte b in hash) hex.AppendFormat("{0:x2}", b);
                    return hex.ToString().Substring(0, 32);
                }
            }
            catch
            {
                return "HWID-FALLBACK-" + Environment.MachineName;
            }
        }

        private static string getChecksum()
        {
            try
            {
                using (var md5 = MD5.Create())
                using (var stream = File.OpenRead(Process.GetCurrentProcess().MainModule.FileName))
                {
                    byte[] hash = md5.ComputeHash(stream);
                    return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
                }
            }
            catch
            {
                return "unknown_checksum";
            }
        }

        private string req(NameValueCollection post_data)
        {
            try
            {
                using (WebClient client = new WebClient())
                {
                    client.Proxy = null;
                    ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
                    ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };

                    byte[] raw = client.UploadValues(apiUrl, post_data);
                    return Encoding.UTF8.GetString(raw);
                }
            }
            catch (WebException webex)
            {
                var resp = webex.Response as HttpWebResponse;
                if (resp != null && (int)resp.StatusCode == 429)
                {
                    error("Rate limit hit. Please slow down requests.");
                    return "";
                }
                error("Connection failure to HS DEVS AUTH server: " + webex.Message);
                return "";
            }
        }

        private static T parse_json<T>(string json)
        {
            try
            {
                using (var ms = new MemoryStream(Encoding.UTF8.GetBytes(json)))
                {
                    var serializer = new DataContractJsonSerializer(typeof(T));
                    return (T)serializer.ReadObject(ms);
                }
            }
            catch
            {
                return Activator.CreateInstance<T>();
            }
        }

        public static void error(string message)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine("[HS DEVS AUTH ERROR] " + message);
            Console.ResetColor();
        }

        #endregion
    }
}

// HSAuth namespace alias
namespace HSAuth
{
    public class api : HSAUTH.api
    {
        public api(string name, string ownerid, string version, string apiUrl = "https://api.hsauth.mujahid.xyz/api/1.3/")
            : base(name, ownerid, version, apiUrl)
        {
        }

        public api(string name, string ownerid, string secret, string version, string apiUrl = "https://api.hsauth.mujahid.xyz/api/1.3/")
            : base(name, ownerid, secret, version, apiUrl)
        {
        }
    }
}

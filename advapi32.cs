using System;
using System.Runtime.InteropServices;

namespace SharpSecertSet
{
    internal class advapi32
    {
        [StructLayout(LayoutKind.Sequential)]
        public struct LSA_UNICODE_STRING
        {
            public UInt16 Length;
            public UInt16 MaximumLength;
            public IntPtr Buffer;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct LSA_OBJECT_ATTRIBUTES
        {
            public int Length;
            public IntPtr RootDirectory;
            public LSA_UNICODE_STRING ObjectName;
            public uint Attributes;
            public IntPtr SecurityDescriptor;
            public IntPtr SecurityQualityOfService;
        }
        public enum LSA_AccessPolicy : long
        {
            POLICY_VIEW_LOCAL_INFORMATION = 0x00000001L,
            POLICY_VIEW_AUDIT_INFORMATION = 0x00000002L,
            POLICY_GET_PRIVATE_INFORMATION = 0x00000004L,
            POLICY_TRUST_ADMIN = 0x00000008L,
            POLICY_CREATE_ACCOUNT = 0x00000010L,
            POLICY_CREATE_SECRET = 0x00000020L,
            POLICY_CREATE_PRIVILEGE = 0x00000040L,
            POLICY_SET_DEFAULT_QUOTA_LIMITS = 0x00000080L,
            POLICY_SET_AUDIT_REQUIREMENTS = 0x00000100L,
            POLICY_AUDIT_LOG_ADMIN = 0x00000200L,
            POLICY_SERVER_ADMIN = 0x00000400L,
            POLICY_LOOKUP_NAMES = 0x00000800L,
            POLICY_NOTIFICATION = 0x00001000L
        }

        public enum LSA_SecretAccess : long
        {
            SECRET_SET_VALUE = 0x00000001L,
            SECRET_QUERY_VALUE = 0x00000002L
        }

        [DllImport("advapi32.dll")]
        public static extern uint LsaSetSecret(
            [In] IntPtr SecretHandle,
            [In][Optional] ref LSA_UNICODE_STRING CurrentValue,
            [In][Optional] ref LSA_UNICODE_STRING OldValue
        );
        [DllImport("advapi32.dll")]
        public static extern uint LsaOpenSecret(
            [In] IntPtr PolicyHandle,
            [In] ref LSA_UNICODE_STRING SecretName,
            [In] uint DesiredAccess,
            [Out] out IntPtr SecretHandle
        );
        [DllImport("advapi32.dll", SetLastError = true, PreserveSig = true)]
        public static extern uint LsaOpenPolicy(
          ref LSA_UNICODE_STRING SystemName,
          ref LSA_OBJECT_ATTRIBUTES ObjectAttributes,
          uint DesiredAccess,
          out IntPtr PolicyHandle
        );

        [DllImport("advapi32.dll", SetLastError = true, PreserveSig = true)]
        public static extern uint LsaRetrievePrivateData(
          IntPtr PolicyHandle,
          ref LSA_UNICODE_STRING KeyName,
          out IntPtr PrivateData
        );

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern uint LsaQuerySecret(
            IntPtr secretHandle,
            out IntPtr currentValue,
            IntPtr currentValueSetTime,
            IntPtr oldValue,
            IntPtr oldValueSetTime
        );

        [DllImport("advapi32.dll", SetLastError = true, PreserveSig = true)]
        public static extern uint LsaNtStatusToWinError(
          uint status
        );
        [DllImport("advapi32.dll", SetLastError = true, PreserveSig = true)]
        public static extern uint LsaClose(
          IntPtr policyHandle
        );
    }
}

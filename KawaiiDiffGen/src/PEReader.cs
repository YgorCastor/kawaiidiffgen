using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;

namespace KawaiiDiffGen
{
    /*
     * <summary>
     * References: 
     *    -> http://wiki.osdev.org/PE
     *    -> http://www.csn.ul.ie/~caolan/pub/winresdump/winresdump/doc/pefile2.html
     * </summary>
     */
    public class PEReader
    {
        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_DOS_HEADER
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
            public char[] e_magic;
            public UInt16 e_cblp;
            public UInt16 e_cp;
            public UInt16 e_crlc;
            public UInt16 e_cparhdr;
            public UInt16 e_minalloc;
            public UInt16 e_maxalloc;
            public UInt16 e_ss;
            public UInt16 e_sp;
            public UInt16 e_csum;
            public UInt16 e_ip;
            public UInt16 e_cs;
            public UInt16 e_lfarlc;
            public UInt16 e_ovno;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
            public UInt16[] e_res1;
            public UInt16 e_oemid;
            public UInt16 e_oeminfo;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 10)]
            public UInt16[] e_res2;
            public UInt32 e_lfanew;
            private string MagicNumber
            {
                get { return new string(e_magic); }
            }

            public bool ValidMagicNumber
            {
                get { return MagicNumber.Equals("MZ"); }
            }
            
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_DATA_DIRECTORY
        {
            public UInt32 VirtualAddress;
            public UInt32 Size;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_OPTIONAL_HEADER32
        {
            public UInt16 Magic;
            public Byte MajorLinkerVersion;
            public Byte MinorLinkerVersion;
            public UInt32 SizeOfCode;
            public UInt32 SizeOfInitializedData;
            public UInt32 SizeOfUninitializedData;
            public UInt32 AddressOfEntryPoint;
            public UInt32 BaseOfCode;
            public UInt32 BaseOfData;
            public UInt32 ImageBase;
            public UInt32 SectionAlignment;
            public UInt32 FileAlignment;
            public UInt16 MajorOperatingSystemVersion;
            public UInt16 MinorOperatingSystemVersion;
            public UInt16 MajorImageVersion;
            public UInt16 MinorImageVersion;
            public UInt16 MajorSubsystemVersion;
            public UInt16 MinorSubsystemVersion;
            public UInt32 Win32VersionValue;
            public UInt32 SizeOfImage;
            public UInt32 SizeOfHeaders;
            public UInt32 CheckSum;
            public UInt16 Subsystem;
            public UInt16 DllCharacteristics;
            public UInt32 SizeOfStackReserve;
            public UInt32 SizeOfStackCommit;
            public UInt32 SizeOfHeapReserve;
            public UInt32 SizeOfHeapCommit;
            public UInt32 LoaderFlags;
            public UInt32 NumberOfRvaAndSizes;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public IMAGE_DATA_DIRECTORY[] DataDirectory;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_OPTIONAL_HEADER64
        {
            public UInt16 Magic;
            public Byte MajorLinkerVersion;
            public Byte MinorLinkerVersion;
            public UInt32 SizeOfCode;
            public UInt32 SizeOfInitializedData;
            public UInt32 SizeOfUninitializedData;
            public UInt32 AddressOfEntryPoint;
            public UInt32 BaseOfCode;
            public UInt64 ImageBase;
            public UInt32 SectionAlignment;
            public UInt32 FileAlignment;
            public UInt16 MajorOperatingSystemVersion;
            public UInt16 MinorOperatingSystemVersion;
            public UInt16 MajorImageVersion;
            public UInt16 MinorImageVersion;
            public UInt16 MajorSubsystemVersion;
            public UInt16 MinorSubsystemVersion;
            public UInt32 Win32VersionValue;
            public UInt32 SizeOfImage;
            public UInt32 SizeOfHeaders;
            public UInt32 CheckSum;
            public UInt16 Subsystem;
            public UInt16 DllCharacteristics;
            public UInt64 SizeOfStackReserve;
            public UInt64 SizeOfStackCommit;
            public UInt64 SizeOfHeapReserve;
            public UInt64 SizeOfHeapCommit;
            public UInt32 LoaderFlags;
            public UInt32 NumberOfRvaAndSizes;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public IMAGE_DATA_DIRECTORY[] DataDirectory;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_FILE_HEADER
        {
            public UInt16 Machine;
            public UInt16 NumberOfSections;
            public UInt32 TimeDateStamp;
            public UInt32 PointerToSymbolTable;
            public UInt32 NumberOfSymbols;
            public UInt16 SizeOfOptionalHeader;
            public UInt16 Characteristics;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_NT_HEADERS
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
            public char[] Signature;
            public IMAGE_FILE_HEADER FileHeader;
            public IMAGE_OPTIONAL_HEADER32 OptionalHeader32;
            public IMAGE_OPTIONAL_HEADER64 OptionalHeader64;

            private string PESignature
            {
                get { return new string(Signature); }
            }

            public bool ValidSignature
            {
                get { return PESignature == "PE\0\0"; }
            }

        }


        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_SECTION_HEADER
        {
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 8)]
            public string Name;
            public Misc Misc;
            public UInt32 VirtualAddress;
            public UInt32 SizeOfRawData;
            public UInt32 PointerToRawData;
            public UInt32 PointerToRelocations;
            public UInt32 PointerToLinenumbers;
            public UInt16 NumberOfRelocations;
            public UInt16 NumberOfLinenumbers;
            public UInt32 Characteristics;
        }

        [StructLayout(LayoutKind.Explicit)]
        public struct Misc
        {
            [FieldOffset(0)]
            public UInt32 PhysicalAddress;
            [FieldOffset(0)]
            public UInt32 VirtualSize;
        }
        
        private readonly IList<IMAGE_SECTION_HEADER> peSections = new List<IMAGE_SECTION_HEADER>();
        private readonly IMAGE_DOS_HEADER dosHeader;
        private IMAGE_NT_HEADERS winNTHeaders;
        
        private static void Unmanaged2Managed<TUnmanagedStruct>(BinaryReader br , out TUnmanagedStruct uStruct)
        {
            var bytes = br.ReadBytes(Marshal.SizeOf(typeof(TUnmanagedStruct)));
            var gcHandle = GCHandle.Alloc(bytes, GCHandleType.Pinned);
            
            uStruct = (TUnmanagedStruct)Marshal.PtrToStructure(gcHandle.AddrOfPinnedObject(), typeof(TUnmanagedStruct));
            gcHandle.Free();
        }

        public PEReader(BinaryReader br)
        {

            br.BaseStream.Seek(0, SeekOrigin.Begin);

            Unmanaged2Managed(br, out dosHeader);

            if (!dosHeader.ValidMagicNumber)
                throw new InvalidOperationException("Invalid magic number!");

            br.BaseStream.Seek(dosHeader.e_lfanew, SeekOrigin.Begin);

            Unmanaged2Managed(br, out winNTHeaders);

            if (!winNTHeaders.ValidSignature)
                throw new InvalidOperationException("Not a WinNT Signature!");

            if ((winNTHeaders.FileHeader.Characteristics & 0x0100) == 0x0100)
                Load32bitPE(br);
            else
                Load64bitPE(br);


        }

        private void Load32bitPE(BinaryReader br)
        {
            
            IMAGE_SECTION_HEADER section;

            if (winNTHeaders.OptionalHeader32.NumberOfRvaAndSizes != 0x10)
                throw new InvalidOperationException("Invalid data directories!");

            for (var i = 0; i < winNTHeaders.OptionalHeader32.NumberOfRvaAndSizes; i++)
            {
                if (winNTHeaders.OptionalHeader32.DataDirectory[i].Size <= 0) 
                    continue;
                
                Unmanaged2Managed(br, out section);
                peSections.Add(section);
            
            }
        }

        private void Load64bitPE(BinaryReader br)
        {

            IMAGE_SECTION_HEADER section;

            if (winNTHeaders.OptionalHeader64.NumberOfRvaAndSizes != 0x10)
                throw new InvalidOperationException("Invalid data directories!");

            for (var i = 0; i < winNTHeaders.OptionalHeader64.NumberOfRvaAndSizes; i++)
            {
                if (winNTHeaders.OptionalHeader64.DataDirectory[i].Size <= 0) 
                    continue;
                
                Unmanaged2Managed(br, out section);
                peSections.Add(section);
            }
        }

        public IMAGE_OPTIONAL_HEADER32 Get32BitsHeader()
        {
            return winNTHeaders.OptionalHeader32;
        }


    }
}

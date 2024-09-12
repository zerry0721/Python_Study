import struct
from datetime import datetime
# HEX_EDIT_MODE의 출력 방식을 BYTE, WORD, DWORD로 구분하기 위함
def byte_format(tmp,format_type=None):
    raw_data=[]
    value=[]
    if format_type == "w":
        for i in range(0,len(tmp),2): #두개씩 끊어서 tmp의 갯수까지 16개가 될 것. 
            if i+2<=len(tmp): #만약에 i+2가 len(tmp)보다 작거나 같으면
                word = struct.unpack("<H", tmp[i:i+2])[0] #Little-endian 방식, 2바이트씩
                raw_data.append(f'{word:04X}') # 4자리 Hex형식으로 출력
            else:
                raw_data.append(f'{tmp[i]:02X}')
    elif format_type == "dw":  # DWORD 형식
        for i in range(0, len(tmp), 4):
            if i + 4 <= len(tmp):  # 4바이트 단위로 데이터가 있는지 확인
                dword  = struct.unpack("<I", tmp[i:i+4])[0]
                raw_data.append(f'{dword:08X}')
            else:  # 남은 데이터가 1, 2, 3바이트일 때
                raw_data.append(' '.join(f'{tmp[j]:02X}' for j in range(i, len(tmp))))
    else:  #Default, 다른값 입력 해도 이 방식으로 출력함
        raw_data = [f'{byte:02X}' for byte in tmp]
    string=''.join(raw_data).replace(" ","")
    #string으로 raw_data를 한줄로 출력하고 공백을 제거함
    #value에서는 string[i:i+2]
    value = ''.join(
        chr(int(string[i:i+2], 16)) if 32 <= int(string[i:i+2], 16) <= 126 else '.'
        for i in range(0, len(string), 2)
    )
    return ' '.join(raw_data), value

# HEX MODE, start 위치에서
def HEX_EDIT_MODE(data, start=0, size=None):
    if size is None: #size의 default 값을 None으로 설정하였고 별다른 크기를 설정하지 않았다면 size는 data의 전체 크기가 된다.
        size = len(data)  # 출력할 데이터의 전체 크기
    format_type=input("출력할 타입을 지정(w=word,dw=dword, default=byte) >")
    print("pFile     Raw Data                                          Value")
    end = start + size
    for i in range(start, end, 16):#data 안에 있는 데이터를 start 부터 start+size까지 16바이트씩 읽음
        if i+16 >= end: #i+16의 값이 end보다 크다면
            pre = end - i
            if pre > 0:
                # 마지막 블록의 크기를 16바이트가 아닌 남은 데이터 크기로 조정
                tmp = data[i:end]
                raw_data, value = byte_format(tmp, format_type)
                print(f"{i:08X}  {raw_data:<48}  {value}")
        else:
            tmp = data[i:i+16]  #tmp는 data의 i ~ i+16까지 예)i가 0이라면 [4D,5A,90,00,03,00,00,00,04,00,00,00,FF,FF,00,00] 을 가지게 될 것임
            # print("tmp:",tmp)
            raw_data, value = byte_format(tmp, format_type)
            # raw_data=''
            # value=''

            # raw_data = ' '.join(f'{byte:02X}' for byte in tmp)
            # for a in tmp:
            #     if raw_data: #raw_data가 있으면
            #         raw_data += ' '  # 바이트들 사이에 공백 추가
            #     raw_data += f'{a:02X}'
        
            # for a in tmp:
            #     if 32<=a<=126:
            #         value+=chr(a)
            #     else:
            #         value+='.'
            print(f"{i:08X}  {raw_data:<48}  {value}") #i의 값을 16진수로 출력, 앞에는 0 붙게 i는 start부터 start+size 까지임
            #raw_data:<48 정렬


def dos_parser(data):
    dos_header_format = [
        "<H",   # e_magic (2바이트)
        "H",    # e_cblp (파일의 마지막 페이지에 남은 바이트 수)
        "H",    # e_cp (파일 페이지 수)
        "H",    # e_crlc (재배치 테이블 항목 수)
        "H",    # e_cparhdr (헤더 크기)
        "H",    # e_minalloc (최소 메모리 필요량)
        "H",    # e_maxalloc (최대 메모리 필요량)
        "H",    # e_ss (초기 SS 값)
        "H",    # e_sp (초기 SP 값)
        "H",    # e_csum (파일 체크섬)
        "H",    # e_ip (초기 IP 값)
        "H",    # e_cs (초기 CS 값)
        "H",    # e_lfarlc (재배치 테이블 주소)
        "H",    # e_ovno (오버레이 번호)
        "H",   # e_res (예약 필드)
        "H",   # e_res (예약 필드)
        "H",   # e_res (예약 필드)
        "H",   # e_res (예약 필드)
        "H",    # e_oemid (OEM 식별자)
        "H",    # e_oeminfo (OEM 정보)
        "H",  # e_res2 (예약 필드)
        "H",  # e_res2 (예약 필드)
        "H",  # e_res2 (예약 필드)
        "H",  # e_res2 (예약 필드)
        "H",  # e_res2 (예약 필드)
        "H",  # e_res2 (예약 필드)
        "H",  # e_res2 (예약 필드)
        "H",  # e_res2 (예약 필드)
        "H",  # e_res2 (예약 필드)
        "H",  # e_res2 (예약 필드)
        "I",    # e_lfanew (PE 헤더의 오프셋) 4byte
    ]
    dos_descriptions = [
        "Signature",
        "Bytes on Last Page of File",
        "Pages in File",
        "Relocations",
        "Size of Header in Paragraphs",
        "Minimum extra Paragraphs",
        "Maximum extra Paragraphs",
        "Initial (relative) SS",
        "Initial SP",
        "Checksum",
        "Initial IP",
        "Initial (relative) CS",
        "Offset to Relocation Table",
        "Overlay number",
        "Reserved",
        "Reserved",
        "Reserved",
        "Reserved",
        "OEM Identifier",
        "OEM Information",
        "Reserved",
        "Reserved",
        "Reserved",
        "Reserved",
        "Reserved",
        "Reserved",
        "Reserved",
        "Reserved",
        "Reserved",
        "Reserved",
        "Offset to PE header"
    ]
    dos_header = struct.unpack_from("<30HI",data)
    value=["" for i in range(len(dos_header_format))]
    value[0]="IMAGE_DOS_SIGNATURE MZ"
    print_field(dos_header_format,dos_header,dos_descriptions,0,value)
    # offset = 0
    # for i, (field, description) in enumerate(zip(dos_header, dos_descriptions)): #i에는 index 값이 들어감, 
    #     field_size = struct.calcsize(dos_header_format[i]) #현재 dos_header_format[i] 값의 크기를 구함
    #     packed_data = struct.pack(dos_header_format[i], field)[::-1]
    #     data_hex = ''.join(f"{byte:02X}" for byte in packed_data)
    #     value = ""
    #     p_offset = f"{offset:08X}"
    #     print(f"{p_offset:<10} {data_hex:<20}{description:<40}{value:<10}")
    #     offset += field_size
    #     # print(field,description,"의 필드 사이즈를 구합니다.",dos_header_format[i],"size:",field_size)
    return

def nt_parser(data,offset):
    nt_header_format = [
        "<I",  # Signature
        "H",   # Machine
        "H",   # NumberOfSections
        "I",   # TimeDateStamp
        "I",   # PointerToSymbolTable
        "I",   # NumberOfSymbols
        "H",   # SizeOfOptionalHeader
        "H",   # Characteristics
    ]
    nt_header = struct.unpack_from("<IHHIIHH", data, offset)
    nt_descriptions = [
        "Signature",
        "Machine",
        "Number of Sections",
        "Time Date Stamp",
        "Pointer to Symbol Table",
        "Number of Symbols",
        "Size of Optional Header",
        "Characteristics"
    ]
    return nt_header, nt_descriptions
    
def nt_sig_parser(data,offset):
    nt_header_format = [
        "<I",  # Signature
    ]
    nt_header = struct.unpack_from("<I", data, offset)
    nt_descriptions = [
        "Signature",
    ]
    print_field(nt_header_format,nt_header,nt_descriptions, offset,["IMAGE_NT_SIGNATURE PE"])
    return nt_header, nt_descriptions

def nt_headers_sizer(data, e_lfanew):
    optional_header_offset = e_lfanew + 4 + 20  # Signature(4) + IMAGE_FILE_HEADER(20)
    magic = struct.unpack_from("<H", data, optional_header_offset)[0]
    # NumberofSymbols_offset = e_lfanew + 4 + 20  # Signature(4) + IMAGE_FILE_HEADER(20)
    # NumberofSymbol = struct.unpack_from("<H", data, NumberofSymbols_offset)[0]
    # print(NumberofSymbol)
    
    if magic == 0x10B:  # PE32
        nt_headers_size = 248  # 4(Signature) + 20(IMAGE_FILE_HEADER) + 224(IMAGE_OPTIONAL_HEADER)
    elif magic == 0x20B:  # PE32+
        nt_headers_size = 264  # 4(Signature) + 20(IMAGE_FILE_HEADER) + 240(IMAGE_OPTIONAL_HEADER)
    else:
        raise ValueError("Invalid PE file: Unknown Optional Header format.")
    
    return nt_headers_size

def nt_file_parser(data,offset,stdout=1):
    nt_file_format = [
        "H",   # Machine
        "H",   # NumberOfSections
        "I",   # TimeDateStamp
        "I",   # PointerToSymbolTable
        "I",   # NumberOfSymbols
        "H",   # SizeOfOptionalHeader
        "H",   # Characteristics
    ]
    nt_header = struct.unpack_from("<HHIIIHH", data, offset)
    nt_descriptions = [
        "Machine",
        "Number of Sections",
        "Time Date Stamp",
        "Pointer to Symbol Table",
        "Number of Symbols",
        "Size of Optional Header",
        "Characteristics"
    ]
    value=["" for i in range(len(nt_file_format))]
    #https://learn.microsoft.com/ko-kr/windows/win32/sysinfo/image-file-machine-constants
    #머신 넘버에 따른 value 값 지정
    mac=nt_header[0]
    if mac == 0x0: # Unknown
        value[0] = "IMAGE_FILE_MACHINE_UNKNOWN"
    elif mac == 0x0001: # WOW64 게스트가 아닌 호스트와 상호 작용
        value[0] = "IMAGE_FILE_MACHINE_TARGET_HOST"
    elif mac == 0x014c: # Intel 386
        value[0] = "IMAGE_FILE_MACHINE_I386"
    elif mac == 0x0162: # MIPS 리틀 엔디안, 0x160 빅 엔디안
        value[0] = "IMAGE_FILE_MACHINE_R3000"
    elif mac == 0x0166: # MIPS little-endian
        value[0] = "IMAGE_FILE_MACHINE_R4000"
    elif mac == 0x0168: # MIPS little-endian
        value[0] = "IMAGE_FILE_MACHINE_R10000"
    elif mac == 0x0169: # MIPS little-endian WCE v2
        value[0] = "IMAGE_FILE_MACHINE_WCEMIPSV2"
    elif mac == 0x0184: # Alpha_AXP
        value[0] = "IMAGE_FILE_MACHINE_ALPHA"
    elif mac == 0x01a2: # SH3 little-endian
        value[0] = "IMAGE_FILE_MACHINE_SH3"
    elif mac == 0x01a3: # SH3DSP
        value[0] = "IMAGE_FILE_MACHINE_SH3DSP"
    elif mac == 0x01a4: # SH3E little-endian
        value[0] = "IMAGE_FILE_MACHINE_SH3E"
    elif mac == 0x01a6: # SH4 little-endian
        value[0] = "IMAGE_FILE_MACHINE_SH4"
    elif mac == 0x01a8: # SH5
        value[0] = "IMAGE_FILE_MACHINE_SH5"
    elif mac == 0x01c0: # ARM Little-Endian
        value[0] = "IMAGE_FILE_MACHINE_ARM"
    elif mac == 0x01c2: # ARM Thumb/Thumb-2 Little-Endian
        value[0] = "IMAGE_FILE_MACHINE_THUMB"
    elif mac == 0x01c4: # ARM Thumb-2 Little-Endian
        value[0] = "IMAGE_FILE_MACHINE_ARMNT"
    elif mac == 0x01d3: # TAM33BD
        value[0] = "IMAGE_FILE_MACHINE_AM33"
    elif mac == 0x01f0: # IBM PowerPC Little-Endian
        value[0] = "IMAGE_FILE_MACHINE_POWERPC"
    elif mac == 0x01f1: # POWERPCFP
        value[0] = "IMAGE_FILE_MACHINE_POWERPCFP"
    elif mac == 0x0200: # Intel 64
        value[0] = "IMAGE_FILE_MACHINE_IA64"
    elif mac == 0x0266: # MIPS
        value[0] = "IMAGE_FILE_MACHINE_MIPS16"
    elif mac == 0x0284: # ALPHA64
        value[0] = "IMAGE_FILE_MACHINE_ALPHA64"
    elif mac == 0x0366: # MIPS
        value[0] = "IMAGE_FILE_MACHINE_MIPSFPU"
    elif mac == 0x0466: # MIPS
        value[0] = "IMAGE_FILE_MACHINE_MIPSFPU16"
    elif mac == 0x0520: # 인 피니언
        value[0] = "IMAGE_FILE_MACHINE_TRICORE"
    elif mac == 0x0CEF: # CEF
        value[0] = "IMAGE_FILE_MACHINE_CEF"
    elif mac == 0x0EBC: # EFI 바이트 코드
        value[0] = "IMAGE_FILE_MACHINE_EBC"
    elif mac == 0x8664: # AMD64(K8)
        value[0] = "IMAGE_FILE_MACHINE_AMD64"
    elif mac == 0x9041: # M32R little-endian
        value[0] = "IMAGE_FILE_MACHINE_M32R"
    elif mac == 0xAA64: # ARM64 Little-Endian
        value[0] = "IMAGE_FILE_MACHINE_ARM64"
    elif mac == 0xC0EE: # CEE
        value[0] = "IMAGE_FILE_MACHINE_CEE"
    else:
        value[0] = "Unknown Machine Type"
    
    pre_time=datetime.utcfromtimestamp(nt_header[2])
    value[2]=pre_time.strftime('%Y/%m/%d %H:%M:%S UTC')

    #https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_file_header
    #Characteristics value 값 출력 위해서 만듬
    charact=f'{nt_header[-1]:04X}'
    # print("charact:",type(charact),charact)
    if stdout==1:
        print_field(nt_file_format,nt_header,nt_descriptions, offset,value)
        if charact[3] in ("1", "3", "5", "7", "9", "B", "D", "F"):
            print(f'{"":<10}{"":<20}{"0001":<40}{"IMAGE_FILE_RELOCS_STRIPPED":<10}')
        if charact[3] in ("2","3","6","7","A","B","E","F"):
            print(f'{"":<10}{"":<20}{"0002":<40}{"IMAGE_FILE_EXECUTABLE_IMAGE":<10}')
        if charact[3] in ("4","6","7","C","D","E","F"):
            print(f'{"":<10}{"":<20}{"0004":<40}{"IMAGE_FILE_LINE_NUMS_STRIPPED":<10}')
        if charact[3] in ("8","9","A","B","C","D","E","F"):
            print(f'{"":<10}{"":<20}{"0008":<40}{"IMAGE_FILE_LOCAL_SYMS_STRIPPED":<10}')
        #10의 자리 숫자
        if charact[2] in ("1","3","9","B"):
            print(f'{"":<10}{"":<20}{"0010":<40}{"IMAGE_FILE_AGGRESIVE_WS_TRIM":<10}')
        if charact[2] in ("2","3","A","B"):
            print(f'{"":<10}{"":<20}{"0020":<40}{"IMAGE_FILE_LARGE_ADDRESS_AWARE":<10}')
        if charact[2] in ("8","9","A","B"):
            print(f'{"":<10}{"":<20}{"0080":<40}{"IMAGE_FILE_BYTES_REVERSED_LO":<10}')
        #100의 자리 숫자
        if charact[1] in ("1", "3", "5", "7", "9", "B", "D", "F"):
            print(f'{"":<10}{"":<20}{"0100":<40}{"IMAGE_FILE_32BIT_MACHINE":<10}')
        if charact[1] in ("2","3","6","7","A","B","E","F"):
            print(f'{"":<10}{"":<20}{"0200":<40}{"IMAGE_FILE_DEBUG_STRIPPED":<10}')
        if charact[1] in ("4","6","7","C","D","E","F"):
            print(f'{"":<10}{"":<20}{"0400":<40}{"IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP":<10}')
        if charact[1] in ("8","9","A","B","C","D","E","F"):
            print(f'{"":<10}{"":<20}{"0800":<40}{"IMAGE_FILE_NET_RUN_FROM_SWAP":<10}')
        #1000의 자리 숫자
        if charact[0] in ("1", "3", "5", "7", "9", "B", "D", "F"):
            print(f'{"":<10}{"":<20}{"1000":<40}{"IMAGE_FILE_SYSTEM":<10}')
        if charact[0] in ("2","3","6","7","A","B","E","F"):
            print(f'{"":<10}{"":<20}{"2000":<40}{"IMAGE_FILE_DLL":<10}')
        if charact[0] in ("4","6","7","C","D","E","F"):
            print(f'{"":<10}{"":<20}{"4000":<40}{"IMAGE_FILE_UP_SYSTEM_ONLY":<10}')
        if charact[0] in ("8","9","A","B","C","D","E","F"):
            print(f'{"":<10}{"":<20}{"8000":<40}{"IMAGE_FILE_BYTES_REVERSED_HI":<10}')

    else:pass
    return nt_header

def nt_optional_header(data,offset,stdout=1):
    optional_header_format = [
        "H",   # Magic
        "B",   # MajorLinkerVersion
        "B",   # MinorLinkerVersion
        "I",   # SizeOfCode
        "I",   # SizeOfInitializedData
        "I",   # SizeOfUninitializedData
        "I",   # AddressOfEntryPoint
        "I",   # BaseOfCode
        "I",   # BaseOfData
        "I",   # ImageBase
        "I",   # SectionAlignment
        "I",   # FileAlignment
        "H",   # MajorOperatingSystemVersion
        "H",   # MinorOperatingSystemVersion
        "H",   # MajorImageVersion
        "H",   # MinorImageVersion
        "H",   # MajorSubsystemVersion
        "H",   # MinorSubsystemVersion
        "I",   # Win32VersionValue
        "I",   # SizeOfImage
        "I",   # SizeOfHeaders
        "I",   # CheckSum
        "H",   # Subsystem
        "H",   # DllCharacteristics
        "I",   # SizeOfStackReserve
        "I",   # SizeOfStackCommit
        "I",   # SizeOfHeapReserve
        "I",   # SizeOfHeapCommit
        "I",   # LoaderFlags
        "I",   # NumberOfDataDirectory
        "I","I",
        "I","I",
        "I","I",
        "I","I",
        "I","I",
        "I","I",
        "I","I",
        "I","I",
        "I","I",
        "I","I",
        "I","I",
        "I","I",
        "I","I",
        "I","I",
        "I","I",
        "I","I"
    ]
    optional_header = struct.unpack_from("<" + "".join(optional_header_format), data, offset)
    descriptions = [
        "Magic",
        "Major Linker Version",
        "Minor Linker Version",
        "Size Of Code",
        "Size Of Initialized Data",
        "Size Of Uninitialized Data",
        "Address Of Entry Point",
        "Base Of Code",
        "Base Of Data",
        "Image Base",
        "Section Alignment",
        "File Alignment",
        "Major Operating System Version",
        "Minor Operating System Version",
        "Major Image Version",
        "Minor Image Version",
        "Major Subsystem Version",
        "Minor Subsystem Version",
        "Win32 Version Value",
        "Size Of Image",
        "Size Of Headers",
        "CheckSum",
        "Subsystem",
        "Dll Characteristics",
        "Size Of Stack Reserve",
        "Size Of Stack Commit",
        "Size Of Heap Reserve",
        "Size Of Heap Commit",
        "Loader Flags",
        "Number Of Data Directory",
        "RVA", "SIZE",
        "RVA", "SIZE",
        "RVA", "SIZE",
        "RVA", "SIZE",
        "RVA", "SIZE",
        "RVA", "SIZE",
        "RVA", "SIZE",
        "RVA", "SIZE",
        "RVA", "SIZE",
        "RVA", "SIZE",
        "RVA", "SIZE",
        "RVA", "SIZE",
        "RVA", "SIZE",
        "RVA", "SIZE",
        "RVA", "SIZE",
        "RVA", "SIZE"
    ]
    
    value=["" for i in range(len(optional_header_format))]
    
    # https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_optional_header32

    magic = optional_header[0]
    if magic == 0x10b:
        value[0] = "IMAGE_NT_OPTIONAL_HDR32_MAGIC"
    elif magic == 0x20b:
        value[0] = "IMAGE_NT_OPTIONAL_HDR64_MAGIC"
    elif magic == 0x107:
        value[0] == "IMAGE_ROM_OPTIONAL_HDR_MAGIC"
    else:
        value[0] = "Unknown Magic"
    value[30] = "EXPORT Table"
    value[32] = "IMPORT Table"
    value[34] = "RESOURCE Table"
    value[36] = "EXCEPTION Table"
    value[38] = "CERTIFICATE Table"
    value[40] = "BASE RELOCATION Table"
    value[42] = "DEBUG Table"
    value[44] = "Architecture Specific Data"
    value[46] = "GLOBAL POINTER Table"
    value[48] = "TLS Table"
    value[50] = "LOAD CONFIGURATION Table"
    value[52] = "BOUND IMPORT Table"
    value[54] = "IMPORT Adress Table"
    value[56] = "DELAY IMPORT Descriptors"
    value[58] = "CLI Header"
    if stdout == 1:
        print("pFile      Data                Description                             Value")
        for i, (field, description) in enumerate(zip(optional_header, descriptions)): #i에는 index 값이 들어감, 
            field_size = struct.calcsize(optional_header_format[i]) #현재 dos_header_format[i] 값의 크기를 구함
            packed_data = struct.pack(optional_header_format[i], field)[::-1]
            data_hex = ''.join(f"{byte:02X}" for byte in packed_data)
            p_offset = f"{offset:08X}"
            offset += field_size
            if i==22:
                opt=optional_header[i]    
                if opt==1:
                    value[i] = "IMAGE_SUBSYSTEM_NATIVE"
                elif opt==2:
                    value[i] = "IMAGE_SUBSYSTEM_WINDOWS_GUI"
                elif opt==3:
                    value[i] = "IMAGE_SUBSYSTEM_WINDOWS_CUI"
                elif opt==5:
                    value[i] = "IMAGE_SUBSYSTEM_OS2_CUI"
                elif opt==7:
                    value[i] = "IMAGE_SUBSYSTEM_POSIX_CUI"
                elif opt==9:
                    value[i] = "IMAGE_SUBSYSTEM_WINDOWS_CE_GUI"
                elif opt==10:
                    value[i] = "IMAGE_SUBSYSTEM_EFI_APPLICATION"
                elif opt==11:
                    value[i] = "IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER"
                elif opt==12:
                    value[i] = "IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER"
                elif opt==13:
                    value[i] = "IMAGE_SUBSYSTEM_EFI_ROM"
                elif opt==14:
                    value[i] = "IMAGE_SUBSYSTEM_XBOX"
                elif opt==16:
                    value[i] = "IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION"
                else:
                    value[i] = "IMAGE_SUBSYSTEM_UNKNOWN"
                tmp_value=value[i] #value는 리스트 형식으로 받습니다.
                print(f"{p_offset:<10} {data_hex:<20}{description:<40}{tmp_value:<10}")
            elif i==23:
                print(f"{p_offset:<10} {data_hex:<20}{description:<40}{tmp_value:<10}")
                opt=data_hex
                if opt[3] in ("1", "3", "5", "7", "9", "B", "D", "F"):
                    print(f'{"":<10}{"":<20}{"0001":<40}{"Reserved.":<10}')
                if opt[3] in ("2","3","6","7","A","B","E","F"):
                    print(f'{"":<10}{"":<20}{"0002":<40}{"Reserved.":<10}')
                if opt[3] in ("4","6","7","C","D","E","F"):
                    print(f'{"":<10}{"":<20}{"0004":<40}{"Reserved.":<10}')
                if opt[3] in ("8","9","A","B","C","D","E","F"):
                    print(f'{"":<10}{"":<20}{"0008":<40}{"Reserved.":<10}')
                #10의 자리 숫자
                if opt[2] in ("4","6","7","C","D","E","F"):
                    print(f'{"":<10}{"":<20}{"0040":<40}{"IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE":<10}')
                if opt[2] in ("8","9","A","B"):
                    print(f'{"":<10}{"":<20}{"0080":<40}{"IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY":<10}')
                #100의 자리 숫자
                if opt[1] in ("1", "3", "5", "7", "9", "B", "D", "F"):
                    print(f'{"":<10}{"":<20}{"0100":<40}{"IMAGE_DLLCHARACTERISTICS_NX_COMPAT":<10}')
                if opt[1] in ("2","3","6","7","A","B","E","F"):
                    print(f'{"":<10}{"":<20}{"0200":<40}{"IMAGE_DLLCHARACTERISTICS_NO_ISOLATION":<10}')
                if opt[1] in ("4","6","7","C","D","E","F"):
                    print(f'{"":<10}{"":<20}{"0400":<40}{"IMAGE_DLLCHARACTERISTICS_NO_SEH":<10}')
                if opt[1] in ("8","9","A","B","C","D","E","F"):
                    print(f'{"":<10}{"":<20}{"0800":<40}{"IMAGE_DLLCHARACTERISTICS_NO_BIND":<10}')
                #1000의 자리 숫자
                if opt[0] in ("1", "3", "5", "7", "9", "B", "D", "F"):
                    print(f'{"":<10}{"":<20}{"1000":<40}{"Reserved.":<10}')
                if opt[0] in ("2","3","6","7","A","B","E","F"):
                    print(f'{"":<10}{"":<20}{"2000":<40}{"IMAGE_DLLCHARACTERISTICS_WDM_DRIVER":<10}')
                if opt[0] in ("4","6","7","C","D","E","F"):
                    print(f'{"":<10}{"":<20}{"4000":<40}{"Reserved.":<10}')
                if opt[0] in ("8","9","A","B","C","D","E","F"):
                    print(f'{"":<10}{"":<20}{"8000":<40}{"IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE":<10}')
            else:
                tmp_value=value[i] #value는 리스트 형식으로 받습니다.
                print(f"{p_offset:<10} {data_hex:<20}{description:<40}{tmp_value:<10}")
            # print(field,description,"의 필드 사이즈를 구합니다.",dos_header_format[i],"size:",field_size)
    return optional_header


def print_field(format,h,h_description,offset=0,value=[]):
    print("pFile      Data                Description                             Value")
    for i, (field, description) in enumerate(zip(h, h_description)): #i에는 index 값이 들어감, 
        field_size = struct.calcsize(format[i]) #현재 dos_header_format[i] 값의 크기를 구함
        packed_data = struct.pack(format[i], field)[::-1]
        data_hex = ''.join(f"{byte:02X}" for byte in packed_data)
        p_offset = f"{offset:08X}"
        tmp_value=value[i] #value는 리스트 형식으로 받습니다.
        print(f"{p_offset:<10} {data_hex:<20}{description:<40}{tmp_value:<10}")
        offset += field_size
        # print(field,description,"의 필드 사이즈를 구합니다.",dos_header_format[i],"size:",field_size)

def image_section_name(data):
    section_offset=e_lfanew+nt_file_parser(data,e_lfanew+4,0)[5]+20+4 #section 해더의 시작위치
    section_count=nt_file_parser(data,e_lfanew+4,0)[1]#section의 갯수
    section_name_list=[]
    for i in range(section_count):
        current_offset = section_offset + (i * 40) #각 섹션 헤더는 40바이트로 고정이다.
        section_name_bytes = data[current_offset:current_offset + 8] #섹션 해더에서 상단의 8바이트 읽기
        section_name = section_name_bytes.split(b'\x00', 1)[0].decode()
        section_name_list.append(section_name)
    return section_name_list,section_offset

def section_hader_parser(data,offset,num,stdout=1):
    section_header_format = [
        "4s",  # Name (8 bytes)
        "4s",
        "I",   # Virtual Size (4 bytes)
        "I",   # Virtual Address (RVA) (4 bytes)
        "I",   # Size Of Raw Data (4 bytes)
        "I",   # Pointer To Raw Data (4 bytes)
        "I",   # Pointer To Relocations (4 bytes)
        "I",   # Pointer To Line Numbers (4 bytes)
        "H",   # Number Of Relocations (2 bytes)
        "H",   # Number Of Line Numbers (2 bytes)
        "I"    # Characteristics (4 bytes)
    ]
    section_header = struct.unpack_from(">" + "".join(section_header_format), data, offset+(num*40))
    descriptions = [
        "Name",
        "",
        "Virtual Size",
        "RVA",
        "Size Of Raw Data",
        "Pointer to Raw Data",
        "Pointer to Relocations",
        "Pointer to Line Numbers",
        "Number of Relocations",
        "Number of Line Numbers",
        "Characteristics",
    ]
    value=["" for i in range(len(section_header_format))]
    value[0]=section_header_name[num]
    if stdout == 1:
        print("pFile      Data                Description                             Value")
        for i, (field, description) in enumerate(zip(section_header, descriptions)): #i에는 index 값이 들어감, 
            field_size = struct.calcsize(section_header_format[i]) #현재 dos_header_format[i] 값의 크기를 구함
            packed_data = struct.pack(section_header_format[i], field)
            data_hex = ''.join(f"{byte:02X}" for byte in packed_data)
            p_offset = f"{offset:08X}"
            offset += field_size
            if i in (0,1):
                data_hex = ' '.join(data_hex[i:i+2] for i in range(0, len(data_hex), 2))
                print
            if i==10:
                print(f"{p_offset:<10} {data_hex:<20}{description:<40}{tmp_value:<10}")
                opt=data_hex
                if opt[7]==0:
                    print(f'{"":<10}{"":<20}{"00000001":<40}{"Reserved.":<10}')
                if opt[7] in ("1", "3", "5", "7", "9", "B", "D", "F"):
                    print(f'{"":<10}{"":<20}{"00000001":<40}{"Reserved.":<10}')
                if opt[7] in ("2","3","6","7","A","B","E","F"):
                    print(f'{"":<10}{"":<20}{"00000002":<40}{"Reserved.":<10}')
                if opt[7] in ("4","6","7","C","D","E","F"):
                    print(f'{"":<10}{"":<20}{"00000004":<40}{"Reserved.":<10}')
                if opt[7] in ("8","9","A","B","C","D","E","F"):
                    print(f'{"":<10}{"":<20}{"00000008":<40}{"IMAGE_SCN_TYPE_NO_PAD":<10}')
                #10의 자리 숫자
                if opt[6] in ("1", "3", "5", "7", "9", "B", "D", "F"):
                    print(f'{"":<10}{"":<20}{"00000010":<40}{"Reserved.":<10}')
                if opt[6] in ("2","3","6","7","A","B","E","F"):
                    print(f'{"":<10}{"":<20}{"00000020":<40}{"IMAGE_SCN_CNT_CODE":<10}')
                if opt[6] in ("4","6","7","C","D","E","F"):
                    print(f'{"":<10}{"":<20}{"00000040":<40}{"IMAGE_SCN_CNT_INITIALIZED_DATA":<10}')
                if opt[6] in ("8","9","A","B"):
                    print(f'{"":<10}{"":<20}{"00000080":<40}{"IMAGE_SCN_CNT_UNINITIALIZED_DATA":<10}')
                #100의 자리 숫자
                if opt[5] in ("1", "3", "5", "7", "9", "B", "D", "F"):
                    print(f'{"":<10}{"":<20}{"00000100":<40}{"IMAGE_SCN_LNK_OTHER":<10}')
                if opt[5] in ("2","3","6","7","A","B","E","F"):
                    print(f'{"":<10}{"":<20}{"00000200":<40}{"IMAGE_SCN_LNK_INFO":<10}')
                if opt[5] in ("4","6","7","C","D","E","F"):
                    print(f'{"":<10}{"":<20}{"00000400":<40}{"Reserved.":<10}')
                if opt[5] in ("8","9","A","B","C","D","E","F"):
                    print(f'{"":<10}{"":<20}{"00000800":<40}{"IMAGE_SCN_LNK_REMOVE":<10}')
                #1000의 자리 숫자
                if opt[4] in ("1", "3", "5", "7", "9", "B", "D", "F"):
                    print(f'{"":<10}{"":<20}{"00001000":<40}{"IMAGE_SCN_LNK_COMDAT":<10}')
                if opt[4] in ("2","3","6","7","A","B","E","F"):
                    print(f'{"":<10}{"":<20}{"00002000":<40}{"Reserved.":<10}')
                if opt[4] in ("4","6","7","C","D","E","F"):
                    print(f'{"":<10}{"":<20}{"00004000":<40}{"IMAGE_SCN_NO_DEFER_SPEC_EXC":<10}')
                if opt[4] in ("8","9","A","B","C","D","E","F"):
                    print(f'{"":<10}{"":<20}{"00008000":<40}{"IMAGE_SCN_GPREL":<10}')
                #만의 자리 숫자
                if opt[3] in ("1", "3", "5", "7", "9", "B", "D", "F"):
                    print(f'{"":<10}{"":<20}{"00010000":<40}{"Reserved.":<10}')
                if opt[3] in ("2","3","6","7","A","B","E","F"):
                    print(f'{"":<10}{"":<20}{"00020000":<40}{"IMAGE_SCN_MEM_PURGEABLE":<10}')
                if opt[3] in ("4","6","7","C","D","E","F"):
                    print(f'{"":<10}{"":<20}{"00040000":<40}{"IMAGE_SCN_MEM_LOCKED":<10}')
                if opt[3] in ("8","9","A","B","C","D","E","F"):
                    print(f'{"":<10}{"":<20}{"00080000":<40}{"IMAGE_SCN_MEM_PRELOAD":<10}')
                #십만의 자리 숫자
                if opt[2] == "1":
                    print(f'{"":<10}{"":<20}{"00100000":<40}{"IMAGE_SCN_ALIGN_1BYTES":<10}')
                if opt[2] == "2":
                    print(f'{"":<10}{"":<20}{"00100000":<40}{"IMAGE_SCN_ALIGN_2BYTES":<10}')
                if opt[2] == "3":
                    print(f'{"":<10}{"":<20}{"00100000":<40}{"IMAGE_SCN_ALIGN_4BYTES":<10}')
                if opt[2] == "4":
                    print(f'{"":<10}{"":<20}{"00100000":<40}{"IMAGE_SCN_ALIGN_8BYTES":<10}')
                if opt[2] == "5":
                    print(f'{"":<10}{"":<20}{"00100000":<40}{"IMAGE_SCN_ALIGN_16BYTES":<10}')
                if opt[2] == "6":
                    print(f'{"":<10}{"":<20}{"00100000":<40}{"IMAGE_SCN_ALIGN_32BYTES":<10}')
                if opt[2] == "7":
                    print(f'{"":<10}{"":<20}{"00100000":<40}{"IMAGE_SCN_ALIGN_64BYTES":<10}')
                if opt[2] == "8":
                    print(f'{"":<10}{"":<20}{"00100000":<40}{"IMAGE_SCN_ALIGN_128BYTES":<10}')
                if opt[2] == "9":
                    print(f'{"":<10}{"":<20}{"00100000":<40}{"IMAGE_SCN_ALIGN_256BYTES":<10}')
                if opt[2] == "A":
                    print(f'{"":<10}{"":<20}{"00100000":<40}{"IMAGE_SCN_ALIGN_512BYTES":<10}')
                if opt[2] == "B":
                    print(f'{"":<10}{"":<20}{"00100000":<40}{"IMAGE_SCN_ALIGN_1024BYTES":<10}')
                if opt[2] == "C":
                    print(f'{"":<10}{"":<20}{"00100000":<40}{"IMAGE_SCN_ALIGN_2048BYTES":<10}')
                if opt[2] == "D":
                    print(f'{"":<10}{"":<20}{"00100000":<40}{"IMAGE_SCN_ALIGN_4096BYTES":<10}')
                if opt[2] == "E":
                    print(f'{"":<10}{"":<20}{"00100000":<40}{"IMAGE_SCN_ALIGN_8192BYTES":<10}')
                #백만의 자리 숫자
                if opt[1] in ("1", "3", "5", "7", "9", "B", "D", "F"):
                    print(f'{"":<10}{"":<20}{"01000000":<40}{"IMAGE_SCN_LNK_NRELOC_OVFL":<10}')
                if opt[1] in ("2","3","6","7","A","B","E","F"):
                    print(f'{"":<10}{"":<20}{"02000000":<40}{"IMAGE_SCN_MEM_DISCARDABLE":<10}')
                if opt[1] in ("4","6","7","C","D","E","F"):
                    print(f'{"":<10}{"":<20}{"04000000":<40}{"IMAGE_SCN_MEM_NOT_CACHED":<10}')
                if opt[1] in ("8","9","A","B","C","D","E","F"):
                    print(f'{"":<10}{"":<20}{"08000000":<40}{"IMAGE_SCN_MEM_NOT_PAGED":<10}')
                #천만자리 숫자
                if opt[0] in ("1", "3", "5", "7", "9", "B", "D", "F"):
                    print(f'{"":<10}{"":<20}{"10000000":<40}{"IMAGE_SCN_MEM_SHARED":<10}')
                if opt[0] in ("2","3","6","7","A","B","E","F"):
                    print(f'{"":<10}{"":<20}{"20000000":<40}{"IMAGE_SCN_MEM_EXECUTE":<10}')
                if opt[0] in ("4","6","7","C","D","E","F"):
                    print(f'{"":<10}{"":<20}{"40000000":<40}{"IMAGE_SCN_MEM_READ":<10}')
                if opt[0] in ("8","9","A","B","C","D","E","F"):
                    print(f'{"":<10}{"":<20}{"80000000":<40}{"IMAGE_SCN_MEM_WRITE":<10}')                

            else:
                tmp_value=value[i] #value는 리스트 형식으로 받습니다.
                print(f"{p_offset:<10} {data_hex:<20}{description:<40}{tmp_value:<10}")
    return section_header

def section_list(data):
    print("Section list called")
    for i, name in enumerate(section_header_name):
        section_header = struct.unpack_from("8s7I2HI", data, section_header_offset+(i*40))
        name=f'{section_header[0]}'.replace("b","").replace("\\x00",'').replace("'",'')
        print(f'{i+1}.',"Section",name)
        # print(name,"",section_header)
    c=int(input(">>"))
    if 0<c<=len(section_header_name):
        section_header = struct.unpack_from("8s7I2HI", data, section_header_offset+((c-1)*40))
        section_offset=section_header[4]
        size=section_header[3] #Pointer to Raw Data
        HEX_EDIT_MODE(data,section_offset, size)
    

#Main 시작
try:
    with open(input(">>> 파일 이름을 입력해주세요 : "),'rb') as file: #rb 모드로 읽는 이유는 바이너리 데이터이기 때문이다. #with 문법을 사용하면, close()를 해줄 필요가 없다.
        data=file.read() #data의 형식은 bytes
        print(">>> 파일을 불러오는 데 성공 했습니다.") #바이너리 데이터를 읽음
        print("**************************************************")
        e_magic,e_lfanew=struct.unpack_from("<2s58xI",data)
        nt_headers_size=nt_headers_sizer(data,e_lfanew)
        section_header_name,section_header_offset=image_section_name(data)
        if e_magic != b'MZ':
            print("It's not a PE file.")
            HEX_EDIT_MODE(data)
        else:
            print("Hex-Edit MOD:\tIMAGE_DOS_HEADER = 1")
            print("PE-View MOD:\tIMAGE_DOS_HEADER = 2")
            print("Hex-Edit MOD:\tDOS_Stub = 3")
            print("Hex-Edit MOD:\tIMAGE_NT_HEADERS = 4")
            print("PE-View MOD:\tNT_Signature = 5")
            print("PE-View MOD:\tIMAGE_FILE_HEADER = 6")
            print("Hex-Edit MOD:\tIMAGE_OPTIONAL_HEADER = 7")
            print("PE-View MOD:\tIMAGE_OPTIONAL_HEADER = 8")
            cnt=0
            for i, name in enumerate(section_header_name):
                print("PE-view MOD:\tSECTION_HEADER",name,"=",i+9)
                cnt+=1
            # print("PE-view MOD:\tSECTION_HEADER")
            # print("PE-view MOD:\tSECTION_HEADER text = 9")
            # print("PE-view MOD:\tSECTION_HEADER rdata = 10")
            # print("PE-view MOD:\tSECTION_HEADER data = 11")
            # print("PE-view MOD:\tSECTION_HEADER idata = 12")
            # print("PE-view MOD:\tSECTION_HEADER reloc = 13")
            print("PE-view MOD:\tSECTION list view = ",cnt+9)
            choice=int(input("Enter : 입력>"))
            if choice==1: #IMAGE_DOS_HEADER Hex-Edit
                HEX_EDIT_MODE(data , 0, 64) #64바이트 고정 크기
            elif choice==2: #IMAGE_DOS_HEADER PE-view
                dos_parser(data)
            elif choice==3: #DOS_Stub Hex-Edit
                HEX_EDIT_MODE(data , 64, e_lfanew-64) #DOS_Stub는 e_lfanew 값에 따라 변할 수 있음 #Dos_Stub의 크기는 e_lfanew 의 값에서 DOS_HEADER크기인 64를 뺀 값이다.
            elif choice==4: #IMAGE_NT_HEADERS Hex-Edit
                HEX_EDIT_MODE(data,e_lfanew,nt_headers_size)
            elif choice==5: #NT_Signature PE-View
                nt_sig_parser(data,e_lfanew)
            elif choice==6: #IMAGE_FILE_HEADER PE-View
                nt_file_parser(data,e_lfanew+4)
            elif choice==7: #IMAGE_OPTIONAL_HEADER Hex-Edit
                HEX_EDIT_MODE(data,e_lfanew+24,nt_headers_size-24)
            elif choice==8: #tIMAGE_OPTIONAL_HEADER PE_Edit
                nt_optional_header(data,e_lfanew+24)
            elif 9<=choice<=cnt+8: #SECTION_HEADER PE-View
                section_hader_parser(data,section_header_offset,choice-9)
            elif choice==cnt+9: #SECTION list view
                section_list(data)
                pass
except Exception as e: #에러 발생하면 해당 에러를 출력함
    print(e)

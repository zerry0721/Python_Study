import struct

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
    for i in range(start, start + size, 16):#data 안에 있는 데이터를 start 부터 start+size까지 16바이트씩 읽음
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

def PARSER(data):
    dos_header_format = (
        "<2s"   # e_magic (2바이트) "MZ" 확인
        "H"    # e_cblp (파일의 마지막 페이지에 남은 바이트 수)
        "H"    # e_cp (파일 페이지 수)
        "H"    # e_crlc (재배치 테이블 항목 수)
        "H"    # e_cparhdr (헤더 크기)
        "H"    # e_minalloc (최소 메모리 필요량)
        "H"    # e_maxalloc (최대 메모리 필요량)
        "H"    # e_ss (초기 SS 값)
        "H"    # e_sp (초기 SP 값)
        "H"    # e_csum (파일 체크섬)
        "H"    # e_ip (초기 IP 값)
        "H"    # e_cs (초기 CS 값)
        "H"    # e_lfarlc (재배치 테이블 주소)
        "H"    # e_ovno (오버레이 번호)
        "8s"   # e_res (예약 필드)
        "H"    # e_oemid (OEM 식별자)
        "H"    # e_oeminfo (OEM 정보)
        "20s"  # e_res2 (예약 필드)
        "I"    # e_lfanew (PE 헤더의 오프셋)
    )
    dos_header = struct.unpack_from(dos_header_format,data)
    print(f"{'pFile':<10} {'Data':<50} {'Description':<30} {'Value':<20}")
    return

def PE_VIEW_MODE(data):
    print("pFile     Raw Data                                          Value")

data=bytes()
try:
    with open(input(">>> 파일 이름을 입력해주세요 : "),'rb') as file: #rb 모드로 읽는 이유는 바이너리 데이터이기 때문이다. #with 문법을 사용하면, close()를 해줄 필요가 없다.
        data=file.read() #data의 형식은 bytes
        print(">>> 파일을 불러오는 데 성공 했습니다.") #바이너리 데이터를 읽음
        print("**************************************************")
        PARSER(data)
        e_magic = struct.unpack_from("<2s", data)[0] #struct.unpack_from(format, /,buffer) #기본적으로 하나의 객체만 있어도 튜플의 형태로 반환됨
        if e_magic != b'MZ':
            print("It's not a PE file.")
            HEX_EDIT_MODE(data)
        else:
            PARSER(data)
            print("Hex-Edit MOD:\tIMAGE_DOS_HEADER = 1")
            print("PE-View MOD:\tIMAGE_DOS_HEADER = 2")
            print("Hex-Edit MOD:\tDOS_Stub = 3")
            print("Hex-Edit MOD:\tIMAGE_NT_HEADERS = 4")
            print("PE-View MOD:\tNT_Signature = 5")
            print("PE-View MOD:\tIMAGE_FILE_HEADER = 6")
            print("PE-View MOD:\tIMAGE_OPTIONAL_HEADER = 7")
            print("PE-view MOD:\tSECTION_HEADER text = 8")
            print("PE-view MOD:\tSECTION_HEADER rdata = 9")
            print("PE-view MOD:\tSECTION_HEADER data = 10")
            print("PE-view MOD:\tSECTION_HEADER idata = 11")
            print("PE-view MOD:\tSECTION_HEADER reloc = 12")
            print("PE-view MOD:\tSECTION list view = 13")
            choice=int(input("Enter : 입력>"))
            if choice==1: #IMAGE_DOS_HEADER Hex-Edit
                HEX_EDIT_MODE(data , 0, 64) #64바이트 고정 크기
            elif choice==2: #IMAGE_DOS_HEADER PE-view
                pass
            elif choice==3: #DOS_Stub Hex-Edit
                HEX_EDIT_MODE(data , 64, 64) #DOS_Stub는 e_lfanew 값에 따라 변할 수 있음
            elif choice==4: #IMAGE_NT_HEADERS Hex-Edit
                print()
            elif choice==5: #NT_Signature PE-View
                print()
            elif choice==6: #IMAGE_FILE_HEADER PE-View
                print()
            elif choice==7: #IMAGE_OPTIONAL_HEADER PE-View
                print()

except Exception as e: #에러 발생하면 해당 에러를 출력함
    print(e)

import struct
def PE_VIEW_MODE(data):
    # 예시로 IMAGE_DOS_HEADER에 대한 정보를 출력한다고 가정
    # pFile은 오프셋, Data는 데이터, Description은 필드의 설명, Value는 해석된 값
    
    # DOS 헤더 포맷 정의
    dos_header_format = (
        "<2s"   # e_magic (2바이트) "MZ" 확인
        "2s"    # e_cblp (파일의 마지막 페이지에 남은 바이트 수)
        "2s"    # e_cp (파일 페이지 수)
        "2s"    # e_crlc (재배치 테이블 항목 수)
        "2s"    # e_cparhdr (헤더 크기)
        "2s"    # e_minalloc (최소 메모리 필요량)
        "2s"    # e_maxalloc (최대 메모리 필요량)
        "2s"    # e_ss (초기 SS 값)
        "2s"    # e_sp (초기 SP 값)
        "2s"    # e_csum (파일 체크섬)
        "2s"    # e_ip (초기 IP 값)
        "2s"    # e_cs (초기 CS 값)
        "2s"    # e_lfarlc (재배치 테이블 주소)
        "2s"    # e_ovno (오버레이 번호)
        "8s"    # e_res (예약 필드)
        "2s"    # e_oemid (OEM 식별자)
        "2s"    # e_oeminfo (OEM 정보)
        "20s"   # e_res2 (예약 필드)
        "4s"    # e_lfanew (PE 헤더의 오프셋)
    )
    
    dos_header_size = struct.calcsize(dos_header_format)
    
    # 출력 헤더
    print(f"{'pFile':<10} {'Data':<50} {'Description':<30} {'Value':<20}")
    
    # 데이터 파싱
    dos_header = struct.unpack_from(dos_header_format, data)
    
    descriptions = [
        "e_magic", "e_cblp", "e_cp", "e_crlc", "e_cparhdr",
        "e_minalloc", "e_maxalloc", "e_ss", "e_sp", "e_csum",
        "e_ip", "e_cs", "e_lfarlc", "e_ovno", "e_res",
        "e_oemid", "e_oeminfo", "e_res2", "e_lfanew"
    ]
    
    # 각 필드에 대해 출력
    offset = 0
    for value, desc in zip(dos_header, descriptions):
        # 16진수 문자열로 변환
        data_str = ' '.join(f'{byte:02X}' for byte in value)
        # ASCII 문자로 변환
        ascii_value = ''.join(chr(byte) if 32 <= byte <= 126 else '.' for byte in value)
        # 출력
        print(f"{offset:08X}  {data_str:<50} {desc:<30} {ascii_value}")
        offset += len(value)

# 예시 데이터
data = bytes([
    0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00,
    0x04, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00,
    0xB8, 0x00, 0x00, 0x00, 0x1F, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
])

PE_VIEW_MODE(data)

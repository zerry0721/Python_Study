import struct

try:
    with open(input(">>> 파일 이름을 입력해주세요 : 입력> "), 'rb') as file:
        data = file.read()
        print(">>> 파일을 불러오는 데 성공 했습니다.")
        print("**************************************************")

        # DOS 헤더의 모든 필드를 추출 (IMAGE_DOS_HEADER)
        dos_header_format = (
            "2s"   # e_magic (2바이트) "MZ" 확인
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

        dos_header = struct.unpack_from(dos_header_format, data)

        # 추출된 DOS 헤더 정보 출력
        print(f"DOS 헤더 정보:")
        print(f"e_magic   : {dos_header[0].decode('utf-8')}")
        print(f"e_cblp    : {dos_header[1]}")
        print(f"e_cp      : {dos_header[2]}")
        print(f"e_crlc    : {dos_header[3]}")
        print(f"e_cparhdr : {dos_header[4]}")
        print(f"e_minalloc: {dos_header[5]}")
        print(f"e_maxalloc: {dos_header[6]}")
        print(f"e_ss      : {dos_header[7]}")
        print(f"e_sp      : {dos_header[8]}")
        print(f"e_csum    : {dos_header[9]}")
        print(f"e_ip      : {dos_header[10]}")
        print(f"e_cs      : {dos_header[11]}")
        print(f"e_lfarlc  : {dos_header[12]}")
        print(f"e_ovno    : {dos_header[13]}")
        print(f"e_res     : {dos_header[14]}")
        print(f"e_oemid   : {dos_header[15]}")
        print(f"e_oeminfo : {dos_header[16]}")
        print(f"e_res2    : {dos_header[17]}")
        print(f"e_lfanew  : {dos_header[18]}")
        print("**************************************************")
        
except Exception as e:
    print(f"에러 발생: {e}")
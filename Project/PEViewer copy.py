import struct

def parse_pe_file(file_path):
    try:
        with open(file_path, "rb") as file:
            data = file.read()
        print(f"파일을 불러오는데 성공 했습니다: {file_path}")
    except FileNotFoundError:
        print("파일을 찾을 수 없습니다. 경로를 확인하세요.")
        return None
    except Exception as e:
        print(f"파일을 여는 중 에러가 발생했습니다: {e}")
        return None

    # 1. DOS Header 분석
    e_magic, e_lfanew = struct.unpack_from("2s58xI", data)
    if e_magic != b'MZ':
        print("이 파일은 PE 파일이 아닙니다.")
        return None

    # 2. PE Header 분석
    pe_header_offset = e_lfanew
    pe_signature, machine, num_sections = struct.unpack_from("4s2H", data, pe_header_offset)
    if pe_signature != b'PE\x00\x00':
        print("PE Signature가 맞지 않습니다.")
        return None

    # Optional Header 크기 확인
    optional_header_offset = pe_header_offset + 24  # 24는 고정된 PE 헤더 크기
    optional_header_size = struct.unpack_from("H", data, optional_header_offset - 2)[0]

    # 3. Section Table 파싱
    section_table_offset = optional_header_offset + optional_header_size
    sections = []
    section_size = 40  # 각 섹션 테이블 엔트리의 크기 (40바이트)
    
    for i in range(num_sections):
        section_data = struct.unpack_from("8s6I2H", data, section_table_offset + i * section_size)
        section_name = section_data[0].rstrip(b'\x00').decode('utf-8')
        virtual_size = section_data[1]
        virtual_address = section_data[2]
        raw_data_size = section_data[4]
        raw_data_ptr = section_data[5]
        
        sections.append({
            "name": section_name,
            "virtual_size": virtual_size,
            "virtual_address": virtual_address,
            "raw_data_size": raw_data_size,
            "raw_data_ptr": raw_data_ptr
        })

    # 4. 섹션 목록 출력
    print("************************************************************")
    for idx, section in enumerate(sections, start=1):
        print(f"PE-view MOD: SECTION HEADER {section['name']} = {idx}")
    
    return sections, data

def display_section_data(sections, data, section_num):
    if section_num < 1 or section_num > len(sections):
        print("잘못된 섹션 번호입니다.")
        return
    
    section = sections[section_num - 1]  # 입력된 번호에 맞는 섹션 선택
    section_data = data[section['raw_data_ptr']:section['raw_data_ptr'] + section['raw_data_size']]
    
    print(f"섹션 이름: {section['name']}")
    print(f"섹션 크기: {section['raw_data_size']} 바이트")
    print(f"섹션 데이터 (16진수):")
    
    # 섹션 데이터를 16진수로 출력
    for i in range(0, len(section_data), 16):
        hex_data = ' '.join(f"{b:02X}" for b in section_data[i:i+16])
        print(f"{i:08X}  {hex_data}")


# 1. 사용자로부터 파일 경로 입력받기
file_path = input("파일 이름을 입력해 주세요: 입력> ")
# 2. PE 파일 파싱
result = parse_pe_file(file_path)
if result is None:
    print("NO!")
sections, data = result

# 3. 섹션 번호 입력받기
section_num = int(input("출력하길 원하는 섹션의 번호를 입력하세요: 입력> "))

# 4. 선택된 섹션 데이터 출력
display_section_data(sections, data, section_num)

import struct
import os

class PEViewer:
    def __init__(self, file_path):
        self.file_path = file_path
        self.data = None
        self.dos_header = None
        self.nt_headers = None
        self.section_headers = []

    def read_file(self):
        try:
            with open(self.file_path, 'rb') as f:
                self.data = f.read()
        except IOError as e:
            print(f"파일을 읽는 중 오류 발생: {e}")
            return False
        return True

    def parse_dos_header(self):
        try:
            self.dos_header = struct.unpack('<2s58xI', self.data[:64])
            if self.dos_header[0] != b'MZ':
                print("유효한 PE 파일이 아닙니다: DOS 서명이 없습니다.")
                return False
        except struct.error as e:
            print(f"DOS 헤더 파싱 중 오류 발생: {e}")
            return False
        return True

    def parse_nt_headers(self):
        try:
            offset = self.dos_header[1]
            signature = struct.unpack('<I', self.data[offset:offset+4])[0]
            if signature != 0x00004550:  # "PE\0\0"
                print("유효한 PE 파일이 아닙니다: NT 서명이 없습니다.")
                return False
            
            # File Header
            file_header = struct.unpack('<2H3I2H', self.data[offset+4:offset+24])
            
            # Optional Header
            optional_header_size = file_header[5]
            optional_header_data = self.data[offset+24:offset+24+optional_header_size]
            
            # Magic number to determine if it's PE32 or PE32+
            magic = struct.unpack('<H', optional_header_data[:2])[0]
            
            if magic == 0x10b:  # PE32
                optional_header_format = '<2H3I9I6H4I'
            elif magic == 0x20b:  # PE32+
                optional_header_format = '<2H3I9Q6H4I'
            else:
                print(f"알 수 없는 Optional Header Magic: {hex(magic)}")
                return False
            
            optional_header_size = min(len(optional_header_data), struct.calcsize(optional_header_format))
            optional_header = struct.unpack(optional_header_format[:optional_header_size], optional_header_data[:optional_header_size])
            
            self.nt_headers = (signature,) + file_header + (magic,) + optional_header[1:]
        except struct.error as e:
            print(f"NT 헤더 파싱 중 오류 발생: {e}")
            return False
        return True

    def parse_section_headers(self):
        try:
            offset = self.dos_header[1] + 24 + self.nt_headers[6]  # NT Headers + Size of Optional Header
            num_sections = self.nt_headers[1]
            for i in range(num_sections):
                section = struct.unpack('<8s6I2HI', self.data[offset:offset+40])
                self.section_headers.append(section)
                offset += 40
        except struct.error as e:
            print(f"섹션 헤더 파싱 중 오류 발생: {e}")
            return False
        return True

    def print_dos_header(self):
        print("\nDOS Header:")
        print(f"Magic: {self.dos_header[0]}")
        print(f"PE Header Offset: {self.dos_header[1]}")

    def print_nt_headers(self):
        print("\nNT Headers:")
        print(f"Signature: {hex(self.nt_headers[0])}")
        print(f"Machine: {hex(self.nt_headers[1])}")
        print(f"Number of Sections: {self.nt_headers[2]}")
        print(f"Time Date Stamp: {hex(self.nt_headers[3])}")
        print(f"Size of Optional Header: {self.nt_headers[6]}")
        print(f"Characteristics: {hex(self.nt_headers[7])}")
        print(f"Magic (Optional Header): {hex(self.nt_headers[8])}")
        if len(self.nt_headers) > 11:
            print(f"Address of Entry Point: {hex(self.nt_headers[11])}")
        if len(self.nt_headers) > 13:
            print(f"Image Base: {hex(self.nt_headers[13])}")

    def print_section_headers(self):
        print("\nSection Headers:")
        for i, section in enumerate(self.section_headers):
            name = section[0].decode('utf-8', 'ignore').rstrip('\x00')
            print(f"\nSection {i+1}: {name}")
            print(f"Virtual Size: {hex(section[1])}")
            print(f"Virtual Address: {hex(section[2])}")
            print(f"Size of Raw Data: {hex(section[3])}")
            print(f"Pointer to Raw Data: {hex(section[4])}")
            print(f"Characteristics: {hex(section[9])}")

    def analyze(self):
        if not self.read_file():
            return False
        if not self.parse_dos_header():
            return False
        if not self.parse_nt_headers():
            return False
        if not self.parse_section_headers():
            return False
        return True

    def display_menu(self):
        while True:
            print("\n--- PE Viewer Menu ---")
            print("1. DOS Header")
            print("2. NT Headers")
            print("3. Section Headers")
            print("4. All Headers")
            print("5. Exit")
            choice = input("선택하세요 (1-5): ")

            if choice == '1':
                self.print_dos_header()
            elif choice == '2':
                self.print_nt_headers()
            elif choice == '3':
                self.print_section_headers()
            elif choice == '4':
                self.print_dos_header()
                self.print_nt_headers()
                self.print_section_headers()
            elif choice == '5':
                break
            else:
                print("잘못된 선택입니다. 다시 선택해주세요.")

def main():
    file_path = input("PE 파일 경로를 입력하세요: ")
    if not os.path.exists(file_path):
        print("파일이 존재하지 않습니다.")
        return

    viewer = PEViewer(file_path)
    if viewer.analyze():
        viewer.display_menu()
    else:
        print("PE 파일 분석에 실패했습니다.")

if __name__ == "__main__":
    main()
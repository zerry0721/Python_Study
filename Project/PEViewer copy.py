import struct

def parse_sections(data, offset, number_of_sections):
    section_format = "<8sIIIIII"
    section_size = struct.calcsize(section_format)
    
    sections = []
    for i in range(number_of_sections):
        section_offset = offset + i * section_size
        section_data = struct.unpack_from(section_format, data, section_offset)
        
        # Try different decoding strategies and handle exceptions
        try:
            section_name = section_data[0].decode('utf-8').rstrip('\x00')
        except UnicodeDecodeError:
            # Use latin-1 as a fallback if utf-8 fails
            section_name = section_data[0].decode('latin-1').rstrip('\x00')
        
        section_virtual_address = section_data[1]
        section_size_of_raw_data = section_data[2]
        sections.append({
            "Name": section_name,
            "Virtual Address": f"{section_virtual_address:08X}",
            "Size of Raw Data": f"{section_size_of_raw_data:08X}",
        })
    
    return sections

def print_sections(sections):
    print(f"{'Section Name':<20} {'Virtual Address':<20} {'Size of Raw Data':<20}")
    print("="*60)
    for section in sections:
        print(f"{section['Name']:<20} {section['Virtual Address']:<20} {section['Size of Raw Data']:<20}")

def main(pe_file_path):
    with open(pe_file_path, "rb") as f:
        data = f.read()
    
    # Example values for demonstration purposes
    section_header_offset = 0x1000  # Example offset to the section headers
    number_of_sections = 5  # Example number of sections
    
    sections = parse_sections(data, section_header_offset, number_of_sections)
    print_sections(sections)

# Example usage
main("calc.exe")

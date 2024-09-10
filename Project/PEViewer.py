import struct

def HEX_MODE(data):
    return 

def PE_VIEW(data):
    #DOS 헤더 출력을 위함
    data_Header=[]
    data_Header[0] = struct.unpack_from(">2c",data) # e_magic
    return data_Header
    

data=bytes()
try:
    with open(input(">>> 파일 이름을 입력해주세요 : 입력> "),'rb') as file: #rb 모드로 읽는 이유는 바이너리 데이터이기 때문이다. #with 문법을 사용하면, close()를 해줄 필요가 없다.
        data=file.read() #data의 형식은 bytes
        print(">>> 파일을 불러오는 데 성공 했습니다.") #바이너리 데이터를 읽음
        print("**************************************************")
        # print(data[0:2]) #PE header #Dos Header: e_magic
        # header=PE_VIEW(data)
        # if header[0]!=b'MZ':
        #     print("It's not a PE File!")
        #     exit(0)
        # print(header)
        print("Hex-Edit MOD:\tIMAGE_DOS_HEADER")
        print("")
except Exception as e: #에러 발생하면 해당 에러를 출력함
    print(e)

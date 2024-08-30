#rock paper scissors
import random

s_count=0
f_count=0
price=500
print("코인을 입력하세요 (1회당",price,"원): ")
coin=int(input())
print("남은 코인:",coin)
while coin>=price:
    print("남은 코인:",coin)
    enemy=random.randint(1,3)
    me=int(input("1. 가위 2.바위 3.보 4.종료"))
    if me<1 or me>4:
        print("잘못된 값입니다. 다시 입력해주세요")
        continue
    elif me==enemy:
        print("무승부 입니다.")
        continue
    elif me==1:
        if enemy==2:
            print("패배!")
            f_count+=1
            coin-=price
        elif enemy==3:
            print("승리!")
            s_count+=1
            coin+=price
    elif me==2:
        if enemy==3:
            print("패배!")
            f_count+=1
            coin-=price
        elif enemy==1:
            print("승리!")
            s_count+=1
            coin+=price
    elif me==3:
        if enemy==1:
            print("패배!")
            f_count+=1
            coin-=price
        elif enemy==2:
            print("승리!")
            s_count+=1
            coin+=price 
    elif me==4:
        break
print("남은 코인 반환:",coin)
print("승리:",s_count,"패배:",f_count)
print("게임이 종료되었습니다.")
x=int(input())
cnt=0
for i in range(x):
    str=list(input())
    print(str)
    print(type(str))
    a=[]
    for j in range(len(str)):
        if str[j]!=str[j+1]:
            a.append(j)
        else:
            continue

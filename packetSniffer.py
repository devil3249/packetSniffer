#!/usr/bin/env python3

import socket,struct,time,os,binascii

protoDict = {} #Dictionary for protocol names

def init():
	with open("EtherTypeValues") as f:  # list downloaded from http://en.wikipedia.org/wiki/EtherType#Examples
		for i in f.readlines():
			protoDict[int(i[:6],16)] = i[8:]

def analyseData(data):
	os.system("clear")
	print("Analysing Data:")
	print("\tSize of packet is",len(data))

def analyseEtherData(data):
	print('\nAnalysing Ethernet Header')
	etherData = struct.unpack("!6s6sH",data[:14])
	src_mac = binascii.hexlify(etherData[0])
	dest_mac = binascii.hexlify(etherData[1])
	proto = etherData[2]
	print('\tSrc Mac:',src_mac)
	print('\tDest Mac:',dest_mac)
	print('\tProtocol:',hex(proto), protoDict[proto])
	return data[14:]

def analyseIP(data):
	print("\nAnalysing IP Header")
	ipData = struct.unpack('2B3H2BH2I',data[:20])
	ver = ipData[0] >> 4
	hlen = ipData[0] & 0x0F
	sType = ipData[1]
	totLen = ipData[2]
	Id = ipData[3]
	flags = ipData[4] >> 13
	fragOffset = ipData[4] & 0x1FFF
	ttl = ipData[5]
	proto = ipData[6]
	hChecksum = ipData[7]
	src_ip = socket.inet_ntoa(data[12:16])
	dest_ip = socket.inet_ntoa(data[16:20])

	print('\tVer:',ver,'\thlen:',hlen)
	print('\tService Type:',sType,'\tTotal Length:',totLen)
	print('\tId: ',Id)
	print('\tFlags', bin(flags))
	print('\tFragment Offset',fragOffset)
	print('\tttl: ',ttl,'\tProtocol: ',proto)
	print('\tHeader Checksum: ',hChecksum)
	print('\tSrc IP: ',src_ip)
	print('\tDest IP: ',dest_ip)
	
	return data[hlen*4:]
	


if __name__=='__main__':
	init()
	rawSock = socket.socket(socket.PF_PACKET,socket.SOCK_RAW,socket.htons(0x0003))
		#define ETH_P_ALL 0x0003  2 bytes
		# AF_INET is for ip protocol addressing, PF_PACKET is low level complete packet
	while True:
		data = rawSock.recv(2048)
		analyseData(data)
		data = analyseEtherData(data)
		data = analyseIP(data)
		time.sleep(0.3)

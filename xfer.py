#!/usr/bin/python3

import os, re, sys, time, threading, select, socket, subprocess, random

TIMO = int(os.environ.get("TIMO", 45))
SIZE = 8192
LOCK = threading.Lock()

def gets():
	return int(time.time())

def outs():
	return (time.strftime("%Y_%m_%d-%H:%M:%S") + "." + str(time.time()).split(".")[1])

def uadr(adrs):
	info = adrs.split(":")
	return (info[0], int(info[1]))

def padr(addr):
	return (addr[0] + ":" + str(addr[1]))

def idxs(objc, item):
	try:
		return objc.index(item)
	except:
		return -1

def join(objc):
	try:
		objc.join(timeout=1.75)
	except:
		print(outs(),"ERRO","join")

def comd(path, addr, prot):
	outp = b""
	if (path):
		try:
			cmdl = [path, addr[0], str(addr[1]), prot]
			subp = subprocess.check_output(cmdl, shell=False, text=True)
			outp = uadr(subp.strip())
		except:
			print(outs(),"ERRO","comd")
	return outp

class sock:
	def __init__(self, prot, addr, srcl, dest, conn):
		self.f = 0
		self.j = None
		self.k = prot
		self.t = socket.SOCK_STREAM if (self.k == "tcp") else socket.SOCK_DGRAM
		self.a = addr
		self.d = dest
		self.c = conn
		self.x = conn
		self.s = socket.socket(socket.AF_INET, self.t)
		self.l = gets()
		self.z = [0, 0]
		if (self.k == "udp"):
			self.c = socket.socket(socket.AF_INET, self.t)
		try:
			rndn = random.randint(0, 2**5)
			csrc = srcl[rndn % len(srcl)]
			self.s.bind((csrc, 0))
		except:
			pass
		if (not dest):
			self.fins()
		else:
			if (self.k == "tcp"):
				stat = self.syns(self.d)
				if (not stat):
					self.fins()
		print(outs(),"INFO","conn",self)

	def __str__(self):
		return ("{%s-%s-%s}" % (self.k, padr(self.a), padr(self.d)))

	def syns(self, dest):
		try:
			self.s.settimeout(5)
			self.s.connect(self.d)
			self.s.settimeout(None)
			return self
		except:
			print(outs(),"ERRO","syns",self)
		return None

	def fins(self):
		print(outs(),"INFO","fins",self)
		if (self.f == 1):
			return -1
		socs = [self.c, self.s]
		for objc in socs:
			try:
				objc.shutdown(socket.SHUT_RDWR)
			except:
				pass
			try:
				objc.close()
			except:
				pass
		self.f = 1
		return 1

	def recv(self, kind):
		secs = gets()
		data = b""
		try:
			if (kind == "conn"):
				if (self.t == socket.SOCK_DGRAM):
					pass
				else:
					data = self.c.recv(SIZE)
			if (kind == "sock"):
				if (self.t == socket.SOCK_DGRAM):
					(data, addr) = self.s.recvfrom(SIZE)
				else:
					data = self.s.recv(SIZE)
			self.l = gets()
		except:
			print(outs(),"ERRO","recv",kind,len(data),self)
		if ((secs - self.z[0]) >= 3):
			print(outs(),"INFO","recv",kind,len(data),self)
			self.z[0] = secs
		return data

	def send(self, kind, data):
		secs = gets()
		if ((secs - self.z[1]) >= 3):
			print(outs(),"INFO","send",kind,len(data),self)
			self.z[1] = secs
		try:
			if (kind == "conn"):
				if (self.t == socket.SOCK_DGRAM):
					self.x.sendto(data, self.a)
				else:
					self.c.sendall(data)
			if (kind == "sock"):
				if (self.t == socket.SOCK_DGRAM):
					self.s.sendto(data, self.d)
				else:
					self.s.sendall(data)
			self.l = gets()
		except:
			print(outs(),"ERRO","send",kind,len(data),self)

def xfer(args):
	global LOCK
	(prot, srcl, path, addr, conn, udat, quel, maps) = (args["prot"], args["srcl"], args["path"], args["addr"], args["conn"], args["data"], args["quel"], args["maps"])
	dest = comd(path, addr, prot)
	objc = sock(prot, addr, srcl, dest, conn)
	maps[addr] = objc
	while (not args["this"]):
		time.sleep(0.75)
	with LOCK:
		objc.j = args["this"]
		quel.append(objc)
	while (True):
		if (objc.f != 0):
			break
		if (udat):
			objc.send("sock", udat)
			udat = None
		try:
			(rfds, wfds, efds) = select.select([objc.c, objc.s], [], [], 1.75)
		except:
			objc.f = 9 ; break
		for fdes in rfds:
			if (fdes == objc.c):
				data = objc.recv("conn")
				if (not data):
					objc.f = 9 ; break
				objc.send("sock", data)
			if (fdes == objc.s):
				data = objc.recv("sock")
				if (not data):
					objc.f = 9 ; break
				objc.send("conn", data)
	objc.fins()

def main():
	global LOCK

	prot = sys.argv[1]
	host = uadr(sys.argv[2])
	srcl = sys.argv[3].split(",")
	path = sys.argv[4]

	print(outs(),"INFO",TIMO,"args",prot,host,srcl,path)

	if (prot != "tcp"):
		ssoc = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		ssoc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		ssoc.bind(host)

	else:
		ssoc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		ssoc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		ssoc.bind(host)
		ssoc.listen(96)

	clis = []
	maps = {}
	quel = []

	while (True):
		secs = gets()
		dels = []
		indx = 0

		with LOCK:
			while (len(quel) > 0):
				objc = quel.pop(0)
				clis.append(objc)

		for objc in clis:
			if (objc.f == 0):
				if ((objc.k == "udp") and ((secs - objc.l) >= TIMO)):
					objc.f = 6
			if (objc.f == 1):
				dels.append(indx)
			indx += 1

		dels.sort() ; dels.reverse()
		for idno in dels:
			addr = clis[idno].a
			thrd = clis[idno].j
			if (addr in maps.keys()):
				del maps[addr]
			join(thrd)
			del clis[idno]

		try:
			(rfds, wfds, efds) = select.select([ssoc], [], [], 1.75)
		except KeyboardInterrupt:
			break
		except:
			print(outs(),"ERRO","sels")
			(rfds, wfds, efds) = ([], [], [])

		for fdes in rfds:
			(data, addr, conn, objc) = (None, None, None, None)

			if (prot != "tcp"):
				(data, addr) = ssoc.recvfrom(SIZE)
				if (addr in maps.keys()):
					objc = maps[addr]
					objc.send("sock", data)
				else:
					conn = ssoc

			else:
				(conn, addr) = ssoc.accept()

			if (not objc):
				args = {"prot":prot, "srcl":srcl, "path":path, "addr":addr, "conn":conn, "data":data, "quel":quel, "maps":maps, "this":None}
				thrd = threading.Thread(target=xfer, args=(args, ))
				args["this"] = thrd
				thrd.start()

if (__name__ == "__main__"):
	main()

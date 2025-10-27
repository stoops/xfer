#!/usr/bin/python3

import os, re, sys
import select, socket, subprocess
import random, time, threading

from argparse import ArgumentParser

LOGO = 5
TIMO = {0:135}
SIZE = (2 ** (13 + 1))
LOCK = threading.Lock()
UDPS = socket.SOCK_DGRAM
TCPS = socket.SOCK_STREAM
LOCL = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

LOCL.bind(("127.0.0.1", random.randint(7000, 9000)))
for i in os.environ.get("TIMO", "").strip().split(";"):
	try:
		j = i.strip().split(":")
		p = j[0].strip().split(",")
		u = j[1].strip()
		t = int(u)
		for k in p:
			if (k):
				n = int(k)
				TIMO[n] = t
	except:
		pass

def gets():
	return int(time.time())

def logs(*args):
	dstr = time.strftime("%Y-%m-%d_%H:%M:%S")
	sstr = str(time.time()).split(".")[1].ljust(9,"0")
	strs = (dstr + "." + sstr)
	for argv in args:
		strs += (" " + str(argv))
	strs += "\n"
	sys.stdout.write(strs)
	sys.stdout.flush()

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
		objc.join()
	except:
		logs("ERRO","join")

def comd(path, addr, prot):
	outp = b""
	if (path):
		try:
			cmdl = [path, addr[0], str(addr[1]), prot]
			subp = subprocess.check_output(cmdl, shell=False, text=True)
			outp = uadr(subp.strip())
		except:
			logs("ERRO","comd",prot,addr)
	return outp

class sock:
	def __init__(self, prot, addr, srcl, dest, conn):
		self.f = 1
		self.j = None
		self.k = prot
		self.t = UDPS if (self.k != "tcp") else TCPS
		self.a = addr
		self.d = dest
		self.c = conn if (self.k != "udp") else LOCL
		self.x = conn
		self.s = socket.socket(socket.AF_INET, self.t)
		self.w = srcl
		self.b = "0.0.0.0"
		self.l = gets()
		self.z = [0, 0]
		if (not dest):
			self.f = -9
		else:
			stat = self.bind()
			if (not stat):
				self.f = -8
			else:
				if (self.k == "tcp"):
					stat = self.syns()
					if (not stat):
						self.f = -7
		logs("INFO","conn",self)

	def __str__(self):
		k = self.k
		try:
			a = padr(self.a)
		except:
			a = "None"
		try:
			d = padr(self.d)
		except:
			d = "None"
		try:
			b = padr(self.b)
		except:
			b = "None"
		try:
			c = self.c.fileno()
		except:
			c = -9
		try:
			s = self.s.fileno()
		except:
			s = -9
		l = self.l
		f = self.f
		return ("{%s_%s_%s_%s_%s:%s_%s.%s}" % (k, a, d, b, c, s, l, f))

	def bind(self):
		try:
			leng = len(self.w)
			rndn = random.randint(0, 2**5)
			self.b = (self.w[rndn % leng], 0)
			self.s.bind(self.b)
			return self
		except:
			logs("ERRO","bind",self)
		return None

	def syns(self):
		try:
			self.s.settimeout(5)
			self.s.connect(self.d)
			self.s.settimeout(None)
			return self
		except:
			logs("ERRO","syns",self)
		return None

	def fins(self):
		logs("INFO","fins",self)
		if (self.s):
			if (self.s != LOCL):
				try:
					self.s.shutdown(socket.SHUT_RDWR)
				except:
					pass
				try:
					self.s.close()
				except:
					pass
			self.s = None
		if (self.c):
			if (self.c != LOCL):
				try:
					self.c.shutdown(socket.SHUT_RDWR)
				except:
					pass
				try:
					self.c.close()
				except:
					pass
			self.c = None
		self.f = -1

	def recv(self, kind):
		secs = gets()
		data = b""
		try:
			if (kind == "conn"):
				if (self.t == UDPS):
					logs("ERRO","recu",len(data),self)
				else:
					data = self.c.recv(SIZE)
			if (kind == "sock"):
				if (self.t == UDPS):
					(data, addr) = self.s.recvfrom(SIZE)
				else:
					data = self.s.recv(SIZE)
			self.l = secs
			if ((secs - self.z[0]) >= LOGO):
				logs("INFO","recv",len(data),self)
				self.z[0] = secs
		except Exception as e:
			logs("ERRO","recv",len(data),self,e)
		return data

	def send(self, kind, data):
		secs = gets()
		try:
			if (kind == "conn"):
				if (self.t == UDPS):
					self.x.sendto(data, self.a)
				else:
					self.c.sendall(data)
			if (kind == "sock"):
				if (self.t == UDPS):
					self.s.sendto(data, self.d)
				else:
					self.s.sendall(data)
			self.l = secs
			if ((secs - self.z[1]) >= LOGO):
				logs("INFO","send",len(data),self)
				self.z[1] = secs
		except Exception as e:
			logs("ERRO","send",len(data),self,e)

def xfer(args):
	global LOCK

	(argv, addr, conn, quel, maps) = (args["argv"], args["addr"], args["conn"], args["quel"], args["maps"])

	if (not addr in maps.keys()):
		dest = comd(argv.file, addr, argv.prot)
		objc = sock(argv.prot, addr, argv.bind, dest, conn)
		maps[addr] = objc
	else:
		objc = maps[addr]

	while (not args["this"]):
		time.sleep(0.75)

	with LOCK:
		objc.j = args["this"]
		quel.append(objc)

	try:
		port = objc.d[1] if (objc.d[1] in TIMO.keys()) else 0
	except:
		port = 0

	while (True):
		secs = gets()

		if (objc.f != 1):
			break

		if ((objc.t == UDPS) and ((secs - objc.l) >= TIMO[port])):
			objc.f = -19 ; break

		try:
			(rfds, wfds, efds) = select.select([objc.c, objc.s], [], [], 1.75)
		except:
			objc.f = -18 ; break

		for fdes in rfds:
			if (fdes == objc.c):
				data = objc.recv("conn")
				if (not data):
					objc.f = -17 ; break
				objc.send("sock", data)

			if (fdes == objc.s):
				data = objc.recv("sock")
				if (not data):
					objc.f = -16 ; break
				objc.send("conn", data)

	objc.fins()

def mgmt(args):
	global LOCK

	(argv, clis, maps, quel) = (args["argv"], args["clis"], args["maps"], args["quel"])
	last = 0 ; nums = 0

	while (True):
		secs = gets()

		with LOCK:
			while (len(quel) > 0):
				objc = quel.pop(0)
				clis.append(objc)

		indx = (len(clis) - 1)
		while (indx > -1):
			objc = clis[indx]
			if (objc.f == -1):
				addr = objc.a
				thrd = objc.j
				join(thrd)
				if (addr in maps.keys()):
					del maps[addr]
				del clis[indx]
				nums += 1
			indx -= 1

		if ((secs - last) >= LOGO):
			logs("INFO","mgmt",nums)
			last = secs ; nums = 0

		time.sleep(0.75)

def main():
	global LOCK

	argp = ArgumentParser()
	argp.add_argument("-p", "--prot", type=str, required=True, help="prot")
	argp.add_argument("-l", "--locl", type=str, required=True, help="addr:port")
	argp.add_argument("-b", "--bind", type=str, required=True, help="addr,addr,addr,...")
	argp.add_argument("-f", "--file", type=str, required=True, help="file")
	argv = argp.parse_args()

	loca = uadr(argv.locl)
	argv.locl = loca

	srcl = argv.bind.split(",")
	argv.bind = srcl

	logs("INFO",TIMO,"args",argv)

	if (argv.prot != "tcp"):
		ssoc = socket.socket(socket.AF_INET, UDPS)
		ssoc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		ssoc.bind(argv.locl)

	else:
		ssoc = socket.socket(socket.AF_INET, TCPS)
		ssoc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		ssoc.bind(argv.locl)
		ssoc.listen(96)

	clis = []
	maps = {}
	quel = []

	args = {"argv":argv, "clis":clis, "maps":maps, "quel":quel}
	thrm = threading.Thread(target=mgmt, args=(args, ))
	thrm.start()

	while (True):
		try:
			(rfds, wfds, efds) = select.select([ssoc], [], [], 1.75)
		except KeyboardInterrupt:
			break
		except:
			logs("ERRO","sels")
			(rfds, wfds, efds) = ([], [], [])

		for fdes in rfds:
			(addr, conn, objc) = (None, None, None)

			if (argv.prot != "tcp"):
				(data, addr) = ssoc.recvfrom(SIZE)
				if (not addr in maps.keys()):
					conn = ssoc
					dest = comd(argv.file, addr, argv.prot)
					temp = sock(argv.prot, addr, argv.bind, dest, conn)
					maps[addr] = temp
					temp.send("sock", data)
				else:
					objc = maps[addr]
					objc.send("sock", data)

			else:
				(conn, addr) = ssoc.accept()

			if (not objc):
				args = {"argv":argv, "addr":addr, "conn":conn, "quel":quel, "maps":maps, "this":None}
				thrd = threading.Thread(target=xfer, args=(args, ))
				args["this"] = thrd
				thrd.start()

if (__name__ == "__main__"):
	main()

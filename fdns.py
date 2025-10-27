#!/usr/bin/python3

import os, sys, random, time
import base64, json, threading, traceback
import select, socket, ssl, struct

from ipaddress import IPv6Address
from urllib import parse, request
from dataclasses import dataclass, astuple

@dataclass
class DNSH:
	idno: int = 0
	flag: int = 0
	ques: int = 0
	answ: int = 0
	auth: int = 0
	adds: int = 0

@dataclass
class DNSQ:
	name: bytes
	type: int
	clas: int

@dataclass
class DNSR:
	name: bytes
	type: int
	clas: int
	ttlz: int
	size: int
	data: bytes

BSIZ = 9000
QTYP = { 1:b"A", 28:b"AAAA", 12:b"PTR", 5:b"CNAME", 2:b"NS", 15:b"MX", 16:b"TXT", 6:b"SOA", 65:b"HTTPS" }
LOCK = threading.Lock()
LOCC = threading.Lock()

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

def pars(data):
	outp = (None, None)
	try:
		indx = 0 ; leng = 12
		temp = struct.unpack("!HHHHHH", data[indx:leng])
		indx = leng ; leng += 0
		head = DNSH(*temp)
		name = b""
		for x in range(0, 256):
			if (data[indx] == 0):
				break
			size = data[indx]
			indx += 1 ; leng += (1 + size)
			name += (data[indx:leng] + b".")
			indx = leng ; leng += 0
		indx += 1 ; leng += (1 + 4)
		temp = struct.unpack("!%ssHH" % (len(name), ), name + data[indx:leng])
		indx = leng ; leng += 0
		body = DNSQ(*temp)
		outp = (head, body)
	except Exception as e:
		logs("ERRO", e, traceback.format_exc())
	return outp

def sslq(host, ques, data):
	form = b""
	if (data):
		bsfe = base64.b64encode(data)
		urle = parse.quote(bsfe, safe="").encode()
		form += (b"GET /dns-query?dns=%s HTTP/1.1\r\n" % (urle, ))
	else:
		form += (b"GET /dns-query?name=%s&type=%s HTTP/1.1\r\n" % (ques.name, QTYP.get(ques.type, QTYP[1]), ))
	form += (b"Host: %s\r\n" % (host, ))
	form += (b"User-Agent: fossjon.com/1.1337\r\n")
	if (data):
		form += (b"Accept: application/dns-message\r\n")
	else:
		form += (b"Accept: application/dns-json\r\n")
	form += (b"\r\n")
	return form

def enco(strs):
	outp = b""
	info = strs.split(".")
	for item in info:
		leng = (len(item) & 0xff)
		if (leng > 0):
			outp += (leng.to_bytes(1, byteorder="big") + item.encode())
	leng = 0
	outp += leng.to_bytes(1, byteorder="big")
	return outp

def mxan(inpt):
	try:
		info = inpt.encode().split(b" ")
		numb = int(info[0])
		doma = enco(info[1].decode())
		pack = struct.pack("!H", numb)
		return (pack + doma)
	except:
		pass
	return b"*"

def answ(qhed, qbdy, data, flag):
	outp = b""
	try:
		info = data.split(b"\r\n\r\n", 1)
		resp = json.loads(info[1])
		resl = (resp.get("Answer", []) + resp.get("Authority", []))
		# todo answ auth leng size
		qnam = enco(qbdy.name.decode().strip("."))
		qlen = len(qnam)
		rbdy = DNSQ(name=qnam, type=qbdy.type, clas=qbdy.clas)
		tupl = astuple(rbdy)
		resq = struct.pack("!%ssHH" % (qlen, ), *tupl)
		repl = []
		resr = b""
		for item in resl:
			kind = item["type"]
			if (QTYP.get(kind, b"?") == b"A"):
				rdat = socket.inet_aton(item["data"])
			elif (QTYP.get(kind, b"?") == b"AAAA"):
				rdat = IPv6Address(item["data"]).packed
			elif (QTYP.get(kind, b"?") == b"MX"):
				rdat = mxan(item["data"])
			else:
				rdat = item["data"].encode()
			rlen = len(rdat)
			abdy = DNSR(name=qnam, type=kind, clas=1, ttlz=item["TTL"], size=rlen, data=rdat)
			tupl = astuple(abdy)
			resr += struct.pack("!%ssHHIH%ss" % (qlen, rlen, ), *tupl)
			repl.append(abdy)
		rhed = DNSH(idno=qhed.idno, flag=0x8180, ques=qhed.ques, answ=len(resl), auth=0, adds=0)
		tupl = astuple(rhed)
		resh = struct.pack("!HHHHHH", *tupl)
		if (flag):
			logs(">", rhed, rbdy, repl[0:])
		outp = (resh + resq + resr)
	except Exception as e:
		logs("ERRO", e, traceback.format_exc(), data)
	return outp

def clen(data):
	pres = b"content-length:"
	prel = len(pres)
	for line in data.split(b"\r\n"):
		if line.lower().startswith(pres):
			try:
				return int(line[prel:].strip())
			except:
				pass
	return BSIZ

def blen(data):
	try:
		return len(data.split(b"\r\n\r\n")[1])
	except:
		pass
	return 0

def proc(args):
	global LOCC

	(remo, host, bind, addr, data, serv, cach, clis) = (args["remo"], args["host"], args["bind"], args["addr"], args["data"], args["serv"], args["cach"], args["clis"])

	brnd = bind[random.randint(0, len(bind)-1)]
	(head, body) = pars(data)
	secs = gets()
	outp = b""
	flag = False

	if (head and body):
		kind = QTYP.get(body.type, QTYP[1])
		name = base64.b64encode(body.name+b"-"+kind).decode()

		if (name in cach.keys()):
			with LOCC:
				try:
					temp = cach[name]["data"]
					outp = base64.b64decode(temp.encode())
				except Exception as e:
					logs("ERRO", e, traceback.format_exc())

		if (not outp):
			flag = True
			logs("<", head, body)
			#logs("!", "INFO", "sock")
			csoc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			try:
				reqs = sslq(host, body, None)
				ctxt = ssl.create_default_context()
				csoc.bind((brnd, 0))
				csoc.settimeout(5)
				csoc.connect(remo)
				#csoc.settimeout(None)
				ssoc = ctxt.wrap_socket(csoc, server_hostname=host)
				ssoc.sendall(reqs)
				outp = ssoc.recv(BSIZ)
				if (outp):
					with LOCC:
						if (blen(outp) < clen(outp)):
							outp += ssoc.recv(BSIZ)
						temp = base64.b64encode(outp).decode()
						cach[name] = {"data":temp, "last":secs, "init":1}
			except Exception as e:
				logs("ERRO", e, traceback.format_exc())
			try:
				csoc.shutdown(socket.SHUT_RDWR)
			except:
				pass
			try:
				csoc.close()
			except:
				pass

		try:
			if (not outp):
				logs("WARN", "outp")
			else:
				repl = answ(head, body, outp, flag)
				serv.sendto(repl, addr)
		except Exception as e:
			logs("ERRO", e, traceback.format_exc())

	with LOCK:
		clis.append({"stat":-1, "addr":addr, "this":args["this"]})

	return None

def mgmt(args):
	global LOCK
	global LOCC

	(cach, clis, logf) = (args["cach"], args["clis"], args["logf"])

	last = 0

	while (True):
		secs = gets()

		with LOCK:
			indx = (len(clis) - 1)
			while (indx > -1):
				item = clis[indx]
				stat = item["stat"]
				thrd = item["this"]
				if ((stat == -1) and thrd):
					logs("*", "INFO", item)
					try:
						thrd.join()
					except Exception as e:
						logs("ERRO", "join", traceback.format_exc())
					clis.pop(indx)
				indx -= 1

		if ((secs - last) >= 15):
			with LOCC:
				flag = 0
				keys = list(cach.keys())
				for name in keys:
					if ((secs - cach[name]["last"]) >= (15 * 60)):
						del cach[name]
						flag = 1
					elif (cach[name]["init"] == 1):
						cach[name]["init"] = 0
						flag = 1
				if (flag == 1):
					with open(logf+".tmp", "w") as fobj:
						json.dump(cach, fobj, indent=4)
					os.rename(logf+".tmp", logf)
			last = secs

		time.sleep(5.75)

	return None

def main():
	global LOCK

	loca = sys.argv[1].split(":")
	locl = (loca[0], int(loca[1]))

	bind = sys.argv[2].split(",")

	rema = sys.argv[3].split(":")
	remo = (rema[0], int(rema[1]))
	host = rema[2].encode()

	logf = sys.argv[4]

	serv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	serv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	serv.bind(locl)

	clis = []
	cach = {}

	try:
		with open(logf, "r") as fobj:
			cach = json.load(fobj)
	except:
		pass

	# todo rate limi

	args = {"cach":cach, "clis":clis, "logf":logf}
	thrm = threading.Thread(target=mgmt, args=(args, ))
	thrm.start()

	while (True):
		socs = [serv]
		(rfds, wfds, efds) = select.select(socs, [], [], 1.75)
		for sock in rfds:
			if (sock == serv):
				(data, addr) = serv.recvfrom(BSIZ)
				args = {"remo":remo, "host":host, "bind":bind, "addr":addr, "data":data, "serv":serv, "cach":cach, "clis":clis, "this":None}
				thrd = threading.Thread(target=proc, args=(args, ))
				args["this"] = thrd
				thrd.start()

if (__name__ == "__main__"):
	main()

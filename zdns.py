#!/usr/bin/python3

import os, sys, random, time
import base64, json, threading, traceback
import select, socket, ssl, struct

import dns.message, dns.rdataclass, dns.rdatatype, dns.rdata, dns.rrset

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

def dnst(kind):
	try:
		return str(dns.rdatatype.RdataType(kind).name).encode() # QTYP.get(body.type, b"?")
	except:
		return b"A"

def pars(data):
	outp = (None, None, None)
	try:
		qdns = dns.message.from_wire(data)
		if (len(qdns.question) > 1):
			logs("WARN", qdns.question)
		ques = qdns.question[0]
		head = DNSH(qdns.id, 0, 0, 0, 0, 0)
		body = DNSQ(str(ques.name).encode(), ques.rdtype.value, 0)
		outp = (head, body, qdns)
	except Exception as e:
		logs("ERRO", e, traceback.format_exc())
	return outp

def sslq(host, body, data):
	form = b""
	if (data):
		bsfe = base64.b64encode(data)
		urle = parse.quote(bsfe, safe="").encode()
		form += (b"GET /dns-query?dns=%s HTTP/1.1\r\n" % (urle, ))
	else:
		kind = dnst(body.type)
		form += (b"GET /dns-query?name=%s&type=%s HTTP/1.1\r\n" % (body.name, kind, ))
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
		outp = b""
		info = inpt.encode().split(b" ")
		numb = int(info[0])
		doma = enco(info[1].decode())
		pack = struct.pack("!H", numb)
		outp = (pack + doma)
		return outp
	except:
		pass
	return b"\x00"

def soan(inpt):
	try:
		outp = b""
		info = inpt.encode().split(b" ")
		outp += enco(info[0].decode())
		outp += enco(info[1].decode())
		outp += int(info[2]).to_bytes(4, "big")
		outp += int(info[3]).to_bytes(4, "big")
		outp += int(info[4]).to_bytes(4, "big")
		outp += int(info[5]).to_bytes(4, "big")
		outp += int(info[6]).to_bytes(4, "big")
		return outp
	except:
		pass
	return b"\x00"

def answ(qhed, qbdy, qdns, data, logo):
	outp = b""
	try:
		info = data.split(b"\r\n\r\n", 1)
		resp = json.loads(info[1])
		resl = resp.get("Answer", [])
		real = resp.get("Authority", [])
		qnam = enco(qbdy.name.decode())
		qlen = len(qnam)
		rdns = dns.message.make_response(qdns)
		outl = []
		for item in resl:
			try:
				name = (item["name"].strip(".") + ".")
				kind = item["type"]
				data = dns.rdata.from_text(dns.rdataclass.IN, kind, item["data"])
				rset = dns.rrset.from_rdata(name, item["TTL"], data)
				rdns.answer.append(rset)
				outl.append(item["data"])
			except:
				pass
		for item in real:
			try:
				name = (item["name"].strip(".") + ".")
				kind = item["type"]
				data = dns.rdata.from_text(dns.rdataclass.IN, kind, item["data"])
				rset = dns.rrset.from_rdata(name, item["TTL"], data)
				rdns.authority.append(rset)
				outl.append(item["data"])
			except:
				pass
		if (logo):
			logs(">", qbdy.name, resl[0:])
		if (not outl):
			logs("WARN", qbdy.name, resl)
		else:
			outp = rdns.to_wire()
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

def send(head, body, qdns, outp, logo, stat, serv, addr):
	try:
		if (not outp):
			logs("WARN", "outp", body.name)
		else:
			repl = answ(head, body, qdns, outp, logo)
			if (not repl):
				logs("WARN", "repl", body.name)
			else:
				if (not stat):
					serv.sendto(repl, addr)
				return True
	except Exception as e:
		logs("ERRO", e, traceback.format_exc())
	return False

def fins(sock):
	try:
		sock.shutdown(socket.SHUT_RDWR)
	except:
		pass
	try:
		sock.close()
	except:
		pass

def proc(args):
	global LOCC

	(remo, host, bind, addr, data, serv, cach, clis) = (args["remo"], args["host"], args["bind"], args["addr"], args["data"], args["serv"], args["cach"], args["clis"])

	brnd = bind[random.randint(0, len(bind)-1)]
	(head, body, qdns) = pars(data)
	secs = gets()
	outp = b""
	logo = False
	refr = False
	stat = False

	if (head and body):
		kind = dnst(body.type)
		name = base64.b64encode(body.name+b"~"+kind).decode()

		if (name in cach.keys()):
			try:
				with LOCC:
					temp = cach[name]["data"]
					last = cach[name]["last"]
				outp = base64.b64decode(temp.encode())
				stat = send(head, body, qdns, outp, logo, stat, serv, addr)
				if (((secs - last) >= (5 * 60))):
					refr = True
			except Exception as e:
				logs("ERRO", e, traceback.format_exc())

		if ((not stat) or refr):
			logo = True
			logs("<", head, body)
			csoc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			try:
				reqs = sslq(host, body, None)
				ctxt = ssl.create_default_context()
				csoc.bind((brnd, 0))
				csoc.settimeout(5)
				csoc.connect(remo)
				ssoc = ctxt.wrap_socket(csoc, server_hostname=host)
				ssoc.sendall(reqs)
				outp = ssoc.recv(BSIZ)
				if (outp):
					if (blen(outp) < clen(outp)):
						outp += ssoc.recv(BSIZ)
					stat = send(head, body, qdns, outp, logo, stat, serv, addr)
					if (stat):
						with LOCC:
							temp = base64.b64encode(outp).decode()
							cach[name] = {"data":temp, "last":secs, "init":1}
			except Exception as e:
				logs("ERRO", e, traceback.format_exc())
			fins(csoc)

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
					if ((secs - cach[name]["last"]) >= (55 * 60)):
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

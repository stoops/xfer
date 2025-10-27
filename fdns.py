#!/usr/bin/python3

import os, sys, random, time
import base64, json, threading, traceback
import select, socket, ssl, struct

import dns.message, dns.rdataclass, dns.rdatatype, dns.rdata, dns.rrset

from argparse import ArgumentParser
from ipaddress import IPv4Address, IPv6Address
from dataclasses import dataclass, astuple
from urllib import parse, request

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
LOCK = threading.Lock()
LOCC = threading.Lock()

def gets():
	return int(time.time())

def fins(sock):
	try:
		sock.shutdown(socket.SHUT_RDWR)
	except:
		pass
	try:
		sock.close()
	except:
		pass

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
		return str(dns.rdatatype.RdataType(kind).name).encode()
	except:
		return b"?"

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

def send(head, body, qdns, outp, logo, stat, serv, addr):
	try:
		if (not outp):
			logs("WARN", "outp", body.name)
		else:
			if (not stat):
				tupl = astuple(head)
				qhed = struct.pack("!HHHHHH", *tupl)
				txid = qhed[0:2]
				if (logo):
					temp = (txid + outp)
					logs("INFO", ">", body.name, len(temp), temp.hex()[0:96])
				serv.sendto(txid + outp, addr)
			return True
	except Exception as e:
		logs("ERRO", e, traceback.format_exc())
	return False

def proc(args):
	global LOCC

	(argv, addr, data, serv, cach, clis) = (args["argv"], args["addr"], args["data"], args["serv"], args["cach"], args["clis"])

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
				if (((secs - last) >= (3.75 * 60))):
					refr = True
			except Exception as e:
				logs("ERRO", e, traceback.format_exc())

		if ((not stat) or refr):
			logo = True
			logs("<", head, body)
			brnd = argv.bind[random.randint(0, len(argv.bind)-1)]
			csoc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			try:
				leng = len(data).to_bytes(2, "big")
				ctxt = ssl.create_default_context()
				csoc.bind((brnd, 0))
				csoc.settimeout(5)
				csoc.connect(argv.remo)
				ssoc = ctxt.wrap_socket(csoc, server_hostname=argv.host)
				ssoc.sendall(leng + data)
				outp = b""
				for x in range(0, 5):
					if (len(outp) >= 2):
						break
					outp += ssoc.recv(BSIZ)
				resl = int.from_bytes(outp[0:2], "big")
				for x in range(0, 5):
					if (len(outp) >= resl):
						break
					outp += ssoc.recv(BSIZ)
				outp = outp[4:]
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

	(argv, cach, clis) = (args["argv"], args["cach"], args["clis"])

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

		if ((secs - last) >= (0.75 * 60)):
			with LOCC:
				flag = 0
				keys = list(cach.keys())
				for name in keys:
					if ((secs - cach[name]["last"]) >= (argv.time * 60)):
						del cach[name]
						flag = 1
					elif (cach[name]["init"] == 1):
						cach[name]["init"] = 0
						flag = 1
				if (flag == 1):
					with open(argv.file+".tmp", "w") as fobj:
						json.dump(cach, fobj, indent=4)
					os.rename(argv.file+".tmp", argv.file)
			last = secs

		time.sleep(5.75)

	return None

def main():
	global LOCK

	argp = ArgumentParser()
	argp.add_argument("-l", "--locl", type=str, required=True, help="addr:port")
	argp.add_argument("-r", "--remo", type=str, required=True, help="addr:port")
	argp.add_argument("-b", "--bind", type=str, required=True, help="addr,addr,addr,...")
	argp.add_argument("-c", "--host", type=str, required=True, help="host")
	argp.add_argument("-t", "--time", type=str, required=True, help="time")
	argp.add_argument("-f", "--file", type=str, required=True, help="file")
	argv = argp.parse_args()

	loca = argv.locl.split(":")
	argv.locl = (loca[0], int(loca[1]))

	rema = argv.remo.split(":")
	argv.remo = (rema[0], int(rema[1]))

	bind = argv.bind.split(",")
	argv.bind = bind

	host = argv.host.encode()
	argv.host = host

	numb = float(argv.time)
	argv.time = numb

	logs("INFO", "main", argv)

	serv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	serv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	serv.bind(argv.locl)

	clis = []
	cach = {}

	try:
		with open(argv.file, "r") as fobj:
			cach = json.load(fobj)
	except:
		pass

	# todo rate limi

	args = {"argv":argv, "cach":cach, "clis":clis}
	thrm = threading.Thread(target=mgmt, args=(args, ))
	thrm.start()

	while (True):
		socs = [serv]
		(rfds, wfds, efds) = select.select(socs, [], [], 1.75)
		for sock in rfds:
			if (sock == serv):
				(data, addr) = serv.recvfrom(BSIZ)
				args = {"argv":argv, "addr":addr, "data":data, "serv":serv, "cach":cach, "clis":clis, "this":None}
				thrd = threading.Thread(target=proc, args=(args, ))
				args["this"] = thrd
				thrd.start()

if (__name__ == "__main__"):
	main()

#!/usr/bin/python3

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

def pars(data):
	outp = (None, None, None)
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

def adat(kind, data):
	try:
		if (QTYP.get(kind, b"?") == b"A"):
			rdat = socket.inet_aton(data)
		elif (QTYP.get(kind, b"?") == b"AAAA"):
			rdat = IPv6Address(data).packed
		elif (QTYP.get(kind, b"?") == b"CNAME"):
			rdat = enco(data)
		elif (QTYP.get(kind, b"?") == b"MX"):
			rdat = mxan(data)
		elif (QTYP.get(kind, b"?") == b"SOA"):
			rdat = soan(data)
		else:
			rdat = data.encode()
		return rdat
	except:
		return b"\x00"

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

def answ(qhed, qbdy, qdns, data, flag):
	outp = b""
	try:
		info = data.split(b"\r\n\r\n", 1)
		resp = json.loads(info[1])
		resl = (resp.get("Answer", []) + resp.get("Authority", []))
		qnam = enco(qbdy.name.decode())
		qlen = len(qnam)
		rbdy = DNSQ(name=qnam, type=qbdy.type, clas=qbdy.clas)
		tupl = astuple(rbdy)
		resq = struct.pack("!%ssHH" % (qlen, ), *tupl)
		repl = []
		resr = b""
		rdns = dns.message.make_response(qdns)
		for item in resl:
			kind = item["type"]
			rdat = adat(kind, item["data"])
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

'''
if (blen(outp) < clen(outp)):
	outp += ssoc.recv(BSIZ)
'''

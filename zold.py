#!/usr/bin/python3

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

(function(){
    function _$rapyd$_in(val, arr) {
        if (arr instanceof Array || typeof arr === "string") return arr.indexOf(val) != -1;
        else {
            for (i in arr) {
                if (arr.hasOwnProperty(i) && i === val) return true;
            }
            return false;
        }
    }
    function enumerate(item) {
        var arr = [];
        for (var i = 0; i < item.length; i++) {
            arr[arr.length] = [i, item[i]];
        }
        return arr;
    }
    function len(obj) {
        if (obj instanceof Array || typeof obj === "string") return obj.length;
        else {
            var count = 0;
            for (var i in obj) {
                if (obj.hasOwnProperty(i)) count++;
            }
            return count;
        }
    }
    function _$rapyd$_extends(child, parent) {
        child.prototype = Object.create(parent.prototype);
        child.prototype.constructor = child;
    }
    var dgram, dns, EventEmitter, lutils, log, BUFFER_SIZE, DEFAULT_TTL, DNS_RATE_LIMIT, DNS_DEFAULT_HOST, DNS_PORT, DNS_ENCODING, DNS_POINTER_FLAG, DNS_FLAGS, DNS_RCODES, DNS_CLASSES, RECORD_TYPES;
    dgram = require("dgram");
    dns = require("dns");
    EventEmitter = require("events").EventEmitter;
    lutils = require("./lutils");
    log = lutils.logger;
    BUFFER_SIZE = 2048;
    DEFAULT_TTL = 600;
    DNS_RATE_LIMIT = 20;
    DNS_DEFAULT_HOST = "8.8.8.8";
    DNS_PORT = 53;
    DNS_ENCODING = "ascii";
    DNS_POINTER_FLAG = 192;
    DNS_FLAGS = {
        QR: 1 << 15,
        OPCODE: 15 << 11,
        AA: 1 << 10,
        TC: 1 << 9,
        RD: 1 << 8,
        RA: 1 << 7,
        RCODE: 15 << 0
    };
    DNS_RCODES = {
        "NoError": 0,
        "FormErr": 1,
        "ServFail": 2,
        "NXDomain": 3,
        "NotImp": 4,
        "Refused": 5,
        "YXDomain": 6,
        "YXRRSet": 7,
        "NXRRSet": 8,
        "NotAuth": 9,
        "NotAuth": 9,
        "NotZone": 10,
        "BADVERS": 16,
        "BADSIG": 16,
        "BADKEY": 17,
        "BADTIME": 18,
        "BADMODE": 19,
        "BADNAME": 20,
        "BADALG": 21,
        "BADTRUNC": 22
    };
    DNS_CLASSES = {
        IN: 1,
        CS: 2,
        CH: 3,
        HS: 4
    };
    RECORD_TYPES = {
        A: 1,
        NS: 2,
        MD: 3,
        MF: 4,
        CNAME: 5,
        SOA: 6,
        MB: 7,
        MG: 8,
        MR: 9,
        NULL: 10,
        WKS: 11,
        PTR: 12,
        HINFO: 13,
        MINFO: 14,
        MX: 15,
        TXT: 16,
        RP: 17,
        AFSDB: 18,
        X25: 19,
        ISDN: 20,
        RT: 21,
        NSAP: 22,
        NSAPPTR: 23,
        SIG: 24,
        KEY: 25,
        PX: 26,
        GPOS: 27,
        AAAA: 28,
        LOC: 29,
        NXT: 30,
        EID: 31,
        NIMLOC: 32,
        SRV: 33,
        ATMA: 34,
        NAPTR: 35,
        KX: 36,
        CERT: 37,
        A6: 38,
        DNAME: 39,
        SINK: 40,
        OPT: 41,
        APL: 42,
        DS: 43,
        SSHFP: 44,
        IPSECKEY: 45,
        RRSIG: 46,
        NSEC: 47,
        DNSKEY: 48,
        DHCID: 49,
        NSEC3: 50,
        NSEC3PARAM: 51,
        TLSA: 52,
        HIP: 55,
        NINFO: 56,
        RKEY: 57,
        TALINK: 58,
        CDS: 59,
        SPF: 99,
        UINFO: 100,
        UID: 101,
        GID: 102,
        UNSPEC: 103,
        NID: 104,
        L32: 105,
        L64: 106,
        LP: 107,
        EUI48: 108,
        EUI64: 109,
        TKEY: 249,
        TSIG: 250,
        IXFR: 251,
        AXFR: 252,
        MAILB: 253,
        MAILA: 254,
        ANY: 255,
        URI: 256,
        CAA: 257,
        TA: 32768,
        DLV: 32769
    };
    function read_domain(buf, offset) {
        var domain, llen, is_pointer_type, lower_llen, raw_offset, label, ret;
        " parse encoded domain names\n    03www05baidu03com00 => www.baidu.com\n    ";
        domain = [];
        raw_offset = -1;
        while (true) {
            llen = buf.readUInt8(offset);
            offset += 1;
            if (llen == 0) {
                break;
            }
            is_pointer_type = llen & DNS_POINTER_FLAG;
            if (is_pointer_type !== 0) {
                lower_llen = buf.readUInt8(offset);
                offset += 1;
                if (raw_offset < 0) {
                    raw_offset = offset;
                }
                offset = (llen & ~DNS_POINTER_FLAG) << 8 | lower_llen;
                continue;
            }
            label = buf.toString(DNS_ENCODING, offset, offset + llen);
            domain.push(label);
            offset += llen;
        }
        if (raw_offset >= 0) {
            offset = raw_offset;
        }
        ret = {
            "name": domain.join("."),
            "offset": offset,
            "has_pointer_type": raw_offset >= 0
        };
        return ret;
    }
    function write_domain(buf, name, offset, do_compress) {
        if (typeof do_compress === "undefined") do_compress = true;
        var pointer, parts, wlen, tail;
        "Write a domain name in DNS encoding";
        if (!buf.offset_cache) {
            buf.offset_cache = {};
        }
        if (_$rapyd$_in(name, buf.offset_cache) && do_compress === true) {
            pointer = buf.offset_cache[name];
            buf.writeUInt16BE(DNS_POINTER_FLAG << 8 | pointer, offset);
            offset += 2;
        } else {
            parts = name.split(".");
            buf.offset_cache[name] = offset;
            wlen = buf.write(parts[0], offset + 1, DNS_ENCODING);
            buf.writeUInt8(wlen, offset);
            offset += 1;
            offset += wlen;
            if (parts.length > 1) {
                tail = parts.slice(1);
                offset = write_domain(buf, tail.join("."), offset, do_compress);
            } else {
                buf.writeUInt8(0, offset);
                offset += 1;
            }
        }
        return offset;
    }
    function decode_base64_label(label_string) {
        var lbuf, name_info;
        lbuf = Buffer(label_string, "base64");
        name_info = read_domain(lbuf, 0);
        return name_info["name"];
    }
    function encode_ip(aip) {
        var buf, parts, _$rapyd$_Unpack, i, d;
        "Encode a string ip to uint32 coded as base64";
        buf = Buffer(4);
        parts = aip.split(".");
        var _$rapyd$_Iter0 = enumerate(parts);
        for (var _$rapyd$_Index0 = 0; _$rapyd$_Index0 < _$rapyd$_Iter0.length; _$rapyd$_Index0++) {
            _$rapyd$_Unpack = _$rapyd$_Iter0[_$rapyd$_Index0];
            i = _$rapyd$_Unpack[0];
            d = _$rapyd$_Unpack[1];
            buf[i] = parseInt(d);
        }
        return buf.toString("base64", 0, 4);
    }
    function decode_ip(eip) {
        var buf, b, ip32, result;
        "decode a base64 encoded uint32 ip to string ip";
        result = [];
        buf = Buffer(eip, "base64");
        ip32 = buf.readUInt32BE(0);
        while (ip32 > 0) {
            b = ip32 % 256;
            ip32 = parseInt(ip32 / 256);
            result.push("" + b);
        }
        while (len(result) < 4) {
            result.push("0");
        }
        result.reverse();
        result = result.join(".");
        return result;
    }
    function DnsError(msg){
        var self = this;
        Error.prototype.constructor.call(self, msg);
        self.name = "DnsError";
        self.message = msg;
    };

    _$rapyd$_extends(DnsError, Error);

    function DnsMessage(buf){
        var self = this;
        if (typeof buf === "undefined") buf = null;
        self.id = 0;
        self.flags = 0;
        self.question = [];
        self.answer = [];
        self.authority = [];
        self.additional = [];
        self.has_pointer_type = false;
        if (buf !== null) {
            self.parse_buffer(buf);
        }
    };


    DnsMessage.prototype.parse_buffer = function parse_buffer(buf){
        var self = this;
        var offset;
        "Parse content in buf as a DNS message";
        offset = 0;
        offset = self.parse_header(buf, offset);
        offset = self.parse_records(buf, offset);
    };

    DnsMessage.prototype.parse_header = function parse_header(buf, offset){
        var self = this;
        "Parse DNS headers";
        self.id = buf.readUInt16BE(offset);
        offset += 2;
        self.flags = buf.readUInt16BE(offset);
        offset += 2;
        return offset;
    };

    DnsMessage.prototype.parse_records = function parse_records(buf, offset){
        var self = this;
        var question_count, answer_count, authority_count, additional_count, _$rapyd$_Unpack;
        "Parse question/answser record of a DNS message";
        question_count = buf.readUInt16BE(offset);
        offset += 2;
        answer_count = buf.readUInt16BE(offset);
        offset += 2;
        authority_count = buf.readUInt16BE(offset);
        offset += 2;
        additional_count = buf.readUInt16BE(offset);
        offset += 2;
        _$rapyd$_Unpack = self.parse_question(buf, offset, question_count);
        self.question = _$rapyd$_Unpack[0];
        offset = _$rapyd$_Unpack[1];
        _$rapyd$_Unpack = self.parse_resource_record(buf, offset, answer_count);
        self.answer = _$rapyd$_Unpack[0];
        offset = _$rapyd$_Unpack[1];
        _$rapyd$_Unpack = self.parse_resource_record(buf, offset, authority_count);
        self.authority = _$rapyd$_Unpack[0];
        offset = _$rapyd$_Unpack[1];
        _$rapyd$_Unpack = self.parse_resource_record(buf, offset, additional_count);
        self.additional = _$rapyd$_Unpack[0];
        offset = _$rapyd$_Unpack[1];
        return offset;
    };

    DnsMessage.prototype.parse_one_question = function parse_one_question(buf, offset){
        var self = this;
        var domain_info, qtype, klass, data;
        "Parse one piece of the question record";
        domain_info = read_domain(buf, offset);
        if (domain_info["has_pointer_type"] == true) {
            self.has_pointer_type = true;
        }
        offset = domain_info["offset"];
        qtype = buf.readUInt16BE(offset);
        offset += 2;
        klass = buf.readUInt16BE(offset);
        offset += 2;
        data = {
            "name": domain_info["name"],
            "type": qtype,
            "class": klass
        };
        return [data, offset];
    };

    DnsMessage.prototype.parse_question = function parse_question(buf, offset, count){
        var self = this;
        var questions, _$rapyd$_Unpack, data, i;
        "\n            QNAME: domain name\n            QTYPE: query type: A, MX, ...\n            QCLASS: request record being requested\n        ";
        questions = [];
        for (i = 0; i < count; i++) {
            _$rapyd$_Unpack = self.parse_one_question(buf, offset);
            data = _$rapyd$_Unpack[0];
            offset = _$rapyd$_Unpack[1];
            questions.push(data);
        }
        return [questions, offset];
    };

    DnsMessage.prototype.parse_resource_record = function parse_resource_record(buf, offset, count){
        var self = this;
        var resource_record, _$rapyd$_Unpack, data, rdlen, i;
        "\n            The RR data\n            QNAME: domain name\n            QTYPE: query type: A, MX, ...\n            QCLASS: request record being requested\n            TTL:   time to live in seconds (uint32)\n            RLENGTH: record length (uint16)\n            RDATA: record data (For A query, a uint32 for IP)\n        ";
        resource_record = [];
        for (i = 0; i < count; i++) {
            _$rapyd$_Unpack = self.parse_one_question(buf, offset);
            data = _$rapyd$_Unpack[0];
            offset = _$rapyd$_Unpack[1];
            data["ttl"] = buf.readUInt32BE(offset);
            offset += 4;
            rdlen = buf.readUInt16BE(offset);
            offset += 2;
            data["rdata"] = self.read_rdata(buf, offset, rdlen, data["type"]);
            offset += rdlen;
            resource_record.push(data);
        }
        return [resource_record, offset];
    };

    DnsMessage.prototype.read_rdata = function read_rdata(buf, offset, rdlen, data_type){
        var self = this;
        var tmp_buf, pref, delta, label_info, clen, tmp_offset, extra_len, result;
        "Read rdata from the buffer\n           To decompress labels, we have to take account of the record type\n        ";
        tmp_buf = Buffer(BUFFER_SIZE);
        tmp_offset = 0;
        if (_$rapyd$_in(data_type, [ RECORD_TYPES.CNAME, RECORD_TYPES.DNAME, RECORD_TYPES.PTR, RECORD_TYPES.NS, RECORD_TYPES.MADNAME, RECORD_TYPES.MGMNAME, RECORD_TYPES.MR ])) {
            label_info = read_domain(buf, offset);
            clen = write_domain(tmp_buf, label_info["name"], 0, false);
            result = tmp_buf.toString("base64", 0, clen);
        } else if (_$rapyd$_in(data_type, [ RECORD_TYPES.MX ])) {
            delta = 0;
            pref = buf.readUInt16BE(offset);
            delta += 2;
            clen = tmp_buf.writeUInt16BE(pref, tmp_offset);
            tmp_offset += 2;
            label_info = read_domain(buf, offset + delta);
            clen = write_domain(tmp_buf, label_info["name"], tmp_offset, false);
            result = tmp_buf.toString("base64", 0, clen);
        } else if (_$rapyd$_in(data_type, [ RECORD_TYPES.SOA ])) {
            label_info = read_domain(buf, offset);
            clen = write_domain(tmp_buf, label_info["name"], tmp_offset, false);
            tmp_offset = clen;
            label_info = read_domain(buf, label_info["offset"]);
            clen = write_domain(tmp_buf, label_info["name"], clen, false);
            tmp_offset = clen;
            extra_len = 5 * 4;
            buf.copy(tmp_buf, tmp_offset, label_info["offset"], label_info["offset"] + extra_len);
            result = tmp_buf.toString("base64", 0, tmp_offset + extra_len);
        } else {
            result = buf.toString("base64", offset, offset + rdlen);
        }
        return result;
    };

    DnsMessage.prototype.write_buf = function write_buf(buf){
        var self = this;
        var offset;
        "Output the message to a buf suitable to socket send";
        offset = 0;
        offset = self.write_headers(buf, offset);
        offset = self.write_records(buf, offset);
        return offset;
    };

    DnsMessage.prototype.write_headers = function write_headers(buf, offset){
        var self = this;
        buf.writeUInt16BE(self.id, offset);
        offset += 2;
        buf.writeUInt16BE(self.flags, offset);
        offset += 2;
        return offset;
    };

    DnsMessage.prototype.write_records = function write_records(buf, offset){
        var self = this;
        buf.writeUInt16BE(len(self.question), offset);
        offset += 2;
        buf.writeUInt16BE(len(self.answer), offset);
        offset += 2;
        buf.writeUInt16BE(len(self.authority), offset);
        offset += 2;
        buf.writeUInt16BE(len(self.additional), offset);
        offset += 2;
        offset = self.write_questions(buf, self.question, offset);
        offset = self.write_resource_record(buf, self.answer, offset);
        offset = self.write_resource_record(buf, self.authority, offset);
        offset = self.write_resource_record(buf, self.additional, offset);
        return offset;
    };

    DnsMessage.prototype.write_one_question = function write_one_question(buf, data, offset){
        var self = this;
        offset = write_domain(buf, data["name"], offset);
        buf.writeUInt16BE(data["type"], offset);
        offset += 2;
        buf.writeUInt16BE(data["class"], offset);
        offset += 2;
        return offset;
    };

    DnsMessage.prototype.write_questions = function write_questions(buf, questions, offset){
        var self = this;
        var data;
        var _$rapyd$_Iter1 = questions;
        for (var _$rapyd$_Index1 = 0; _$rapyd$_Index1 < _$rapyd$_Iter1.length; _$rapyd$_Index1++) {
            data = _$rapyd$_Iter1[_$rapyd$_Index1];
            offset = self.write_one_question(buf, data, offset);
        }
        return offset;
    };

    DnsMessage.prototype.write_resource_record = function write_resource_record(buf, resource_record, offset){
        var self = this;
        var wlen, rr;
        var _$rapyd$_Iter2 = resource_record;
        for (var _$rapyd$_Index2 = 0; _$rapyd$_Index2 < _$rapyd$_Iter2.length; _$rapyd$_Index2++) {
            rr = _$rapyd$_Iter2[_$rapyd$_Index2];
            offset = self.write_one_question(buf, rr, offset);
            buf.writeUInt32BE(rr["ttl"], offset);
            offset += 4;
            wlen = buf.write(rr["rdata"], offset + 2, "base64");
            buf.writeUInt16BE(wlen, offset);
            offset += 2;
            offset += wlen;
        }
        return offset;
    };

    
    
    function DnsLookupError(msg){
        var self = this;
        DnsError.prototype.constructor.call(self, msg);
        self.name = "DnsLookupError";
    };

    _$rapyd$_extends(DnsLookupError, DnsError);

    function DnsUDPClient(options){
        var self = this;
        self.options = options;
        self.timeout = 1e4;
        self.timeout_id = -1;
        self.client = null;
    };

    _$rapyd$_extends(DnsUDPClient, EventEmitter);

    DnsUDPClient.prototype.lookup = function lookup(msg){
        var self = this;
        var client, buf, offset, tp;
        "msg: DnsMessage, or Buffer";
        client = dgram.createSocket("udp4");
        self.client = client;
        client.unref();
        function _on_msg(b, r) {
            self._on_message(b, r);
        }
        function _on_error(err) {
            log.error("Err on DnsUDPClient lookup:", err);
        }
        client.on("message", _on_msg);
        client.on("error", _on_error);
        if (msg instanceof Buffer) {
            buf = msg;
            offset = buf.length;
        } else if (msg instanceof DnsMessage) {
            buf = Buffer(BUFFER_SIZE);
            offset = msg.write_buf(buf);
        } else {
            tp = typeof msg;
            throw new DnsLookupError("Unknown msg type when lookup(): " + tp);
        }
        client.send(buf, 0, offset, DNS_PORT, self.options["dns_host"]);
        function _on_kill_me_timeout() {
            self.kill_me();
        }
        self.timeout_id = setTimeout(_on_kill_me_timeout, self.timeout);
    };

    DnsUDPClient.prototype._on_message = function _on_message(buf, remote_info){
        var self = this;
        if (buf.length > BUFFER_SIZE) {
            BUFFER_SIZE = buf.length;
        }
        self.emit("resolved", buf);
        if (self.timeout_id != -1) {
            clearTimeout(self.timeout_id);
        }
        self.client.close();
    };

    DnsUDPClient.prototype.kill_me = function kill_me(){
        var self = this;
        "on timeout, close the udp socket";
        self.client.close();
        self.timeout_id = -1;
        self.emit("timeout");
    };

    function DnsProxy(options, router){
        var self = this;
        if (typeof router === "undefined") router = null;
        var rate_limit;
        "Router is used to route local name to ip\n            options:\n                listen_port: dns proxy port. default: 53\n                listen_address: dns proxy address. default: 0.0.0.0\n                dns_host: remote DNS server we do real DNS lookup.\n                          default: 8.8.8.8\n                dns_rate_limit: dns lookup/second rate limit\n            router: a router class to direct domain name to fake ip.\n                    Should have a method router.lookup(domain_name)\n                    return an ip address or None\n            Events:\n                \"listening\": emit when the server has been bound to port\n\n        ";
        if (router === null) {
            router = BaseRouter();
        }
        self.timeout = 30 * 1e3;
        self.router = router;
        self.banned = {};
        self.banned_record_types = [ "ANY", "TXT" ];
        if (!options["dns_host"]) {
            options["dns_host"] = DNS_DEFAULT_HOST;
        }
        self.options = options;
        rate_limit = self.options["dns_rate_limit"] || DNS_RATE_LIMIT;
        self.rate_limiter = lutils.createRateLimiter({
            "rate-limit": rate_limit
        });
        self.rate_limiter.set_name("DNS Proxy");
        self.query_map = {};
        self.usock = dgram.createSocket("udp4");
        function _on_message(b, r) {
            self._on_dns_message(b, r);
        }
        function _on_error(err) {
            self._on_dns_error(err);
        }
        function _on_listening() {
            self._on_dns_listening();
        }
        self.usock.on("message", _on_message);
        self.usock.on("listening", _on_listening);
        self.usock.on("error", _on_error);
    };

    _$rapyd$_extends(DnsProxy, EventEmitter);

    DnsProxy.prototype._on_dns_message = function _on_dns_message(buf, remote_info){
        var self = this;
        var raddress, rport, dns_msg, btype, q, ret;
        raddress = remote_info.address;
        if (self.rate_limiter.over_limit(raddress) || self.banned[raddress]) {
            return;
        }
        if (buf.length > BUFFER_SIZE) {
            BUFFER_SIZE = buf.length;
        }
        rport = remote_info.port;
        try {
            dns_msg = new DnsMessage(buf);
        } catch (_$rapyd$_Exception) {
            var e = _$rapyd$_Exception;
            log.error("DNS Proxy DoS attack: decode message failed:", e, raddress);
            self.rate_limiter.add_deny(raddress);
            return;
        }
        var _$rapyd$_Iter3 = dns_msg.question;
        for (var _$rapyd$_Index3 = 0; _$rapyd$_Index3 < _$rapyd$_Iter3.length; _$rapyd$_Index3++) {
            q = _$rapyd$_Iter3[_$rapyd$_Index3];
            var _$rapyd$_Iter4 = self.banned_record_types;
            for (var _$rapyd$_Index4 = 0; _$rapyd$_Index4 < _$rapyd$_Iter4.length; _$rapyd$_Index4++) {
                btype = _$rapyd$_Iter4[_$rapyd$_Index4];
                if (q["type"] == RECORD_TYPES[btype]) {
                    self.banned[raddress] = true;
                    log.warn("DNS Proxy DoS (%s):", btype, q, raddress);
                    return;
                }
            }
            if (q["class"] !== DNS_CLASSES.IN) {
                self.banned[raddress] = true;
                log.warn("DNS Proxy DoS bad class:", q, raddress);
                return;
            }
        }
        ret = self.local_router_lookup(dns_msg, rport, raddress);
        if (ret === false) {
            if (self.options["dns_relay"]) {
                self.remote_lookup(buf, dns_msg, rport, raddress);
            } else {
                self.answer_refused(dns_msg, rport, raddress);
            }
        }
    };

    DnsProxy.prototype.local_router_lookup = function local_router_lookup(dns_msg, rport, raddress){
        var self = this;
        var rec_name, ip, ret, q, send_msg, buf, length;
        "Short cut, if only an \"A\" query for routed domains,\n           send out a \"A\" response immediately\n        ";
        ret = false;
        ip = null;
        var _$rapyd$_Iter5 = dns_msg.question;
        for (var _$rapyd$_Index5 = 0; _$rapyd$_Index5 < _$rapyd$_Iter5.length; _$rapyd$_Index5++) {
            q = _$rapyd$_Iter5[_$rapyd$_Index5];
            rec_name = q["name"];
            ip = self.router.lookup(rec_name);
            if (_$rapyd$_in(q["type"], [ RECORD_TYPES.A ]) && ip !== null) {
                ret = true;
            } else {
                ret = false;
                break;
            }
        }
        if (ret === true) {
            send_msg = self.create_a_message(dns_msg.id, rec_name, ip);
            send_msg.question = dns_msg.question;
            log.debug("DNS local router:", send_msg.answer[0]["name"], raddress);
            buf = Buffer(BUFFER_SIZE);
            length = send_msg.write_buf(buf);
            self.send_response(buf, length, rport, raddress);
        }
        return ret;
    };

    DnsProxy.prototype.remote_lookup = function remote_lookup(buf, dns_msg, rport, raddress){
        var self = this;
        var dns_client, query_key, d, time_stamp;
        "query on remote DNS server";
        log.debug("DNS remote lookup:", dns_msg.question[0], raddress);
        dns_client = new DnsUDPClient(self.options);
        query_key = dns_msg.id + raddress + rport;
        d = new Date();
        time_stamp = d.getTime();
        self.query_map[query_key] = [ dns_client, time_stamp ];
        function _on_resolved(buf) {
            self.handle_lookup_result(buf, rport, raddress);
        }
        dns_client.on("resolved", _on_resolved);
        dns_client.lookup(dns_msg);
    };

    DnsProxy.prototype._on_dns_error = function _on_dns_error(err){
        var self = this;
        log.error("Err on dns proxy:", err);
    };

    DnsProxy.prototype._on_dns_listening = function _on_dns_listening(){
        var self = this;
        var addr;
        addr = self.usock.address();
        log.info("DNS proxy listens on %s:%d", addr.address, addr.port);
        self.emit("listening");
    };

    DnsProxy.prototype.create_a_message = function create_a_message(msg_id, name, ip){
        var self = this;
        var msg;
        "Create a DnsMessage with type \"A\" query result";
        msg = new DnsMessage();
        msg.id = msg_id;
        msg.flags = DNS_FLAGS.QR | DNS_FLAGS.AA;
        msg.answer = [ {
            "name": name,
            "type": RECORD_TYPES.A,
            "class": DNS_CLASSES.IN,
            "ttl": DEFAULT_TTL,
            "rdata": encode_ip(ip)
        } ];
        return msg;
    };

    DnsProxy.prototype.handle_lookup_result = function handle_lookup_result(buf, rport, raddress){
        var self = this;
        var msg, aliases, rec_name, changed, cname, ip, record, records, offset, query_key, d, time_stamp;
        "process remote real dns lookup response";
        msg = new DnsMessage(buf);
        changed = false;
        aliases = {};
        var _$rapyd$_Iter6 = [ msg.answer, msg.authority, msg.additional ];
        for (var _$rapyd$_Index6 = 0; _$rapyd$_Index6 < _$rapyd$_Iter6.length; _$rapyd$_Index6++) {
            records = _$rapyd$_Iter6[_$rapyd$_Index6];
            var _$rapyd$_Iter7 = records;
            for (var _$rapyd$_Index7 = 0; _$rapyd$_Index7 < _$rapyd$_Iter7.length; _$rapyd$_Index7++) {
                record = _$rapyd$_Iter7[_$rapyd$_Index7];
                rec_name = record["name"];
                if (_$rapyd$_in(record["type"], [ RECORD_TYPES.A, RECORD_TYPES.AAAA ])) {
                    ip = self.router.lookup(rec_name);
                    if (ip === null && _$rapyd$_in(rec_name, aliases)) {
                        ip = aliases[rec_name];
                    }
                    if (ip !== null) {
                        record["rdata"] = encode_ip(ip);
                        changed = true;
                    }
                }
                if (_$rapyd$_in(record["type"], [ RECORD_TYPES.CNAME, RECORD_TYPES.DNAME ])) {
                    cname = decode_base64_label(record["rdata"]);
                    ip = self.router.lookup(rec_name);
                    if (ip !== null) {
                        aliases[cname] = ip;
                    } else if (_$rapyd$_in(rec_name, aliases)) {
                        aliases[cname] = aliases[rec_name];
                    }
                }
            }
        }
        if (changed === true) {
            buf = Buffer(BUFFER_SIZE);
            offset = msg.write_buf(buf);
        } else {
            offset = buf.length;
        }
        query_key = msg.id + raddress + rport;
        d = new Date();
        time_stamp = d.getTime();
        if (_$rapyd$_in(time_stamp, self.query_map)) {
            delete self.query_map[time_stamp];
        }
        self.send_response(buf, offset, rport, raddress);
    };

    DnsProxy.prototype.answer_refused = function answer_refused(dns_message, rport, raddress){
        var self = this;
        var send_msg, buf, length;
        "Send a Refused dns answer message to the client";
        log.debug("DNS Refused:", dns_message.question[0], raddress);
        send_msg = new DnsMessage();
        send_msg.id = dns_message.id;
        send_msg.flags = DNS_FLAGS.QR | DNS_RCODES["Refused"];
        buf = Buffer(BUFFER_SIZE);
        length = send_msg.write_buf(buf);
        self.send_response(buf, length, rport, raddress);
    };

    DnsProxy.prototype.send_response = function send_response(buf, length, rport, raddress){
        var self = this;
        self.usock.send(buf, 0, length, rport, raddress);
    };

    DnsProxy.prototype.start = function start(ip){
        var self = this;
        if (typeof ip === "undefined") ip = "0.0.0.0";
        var port;
        port = self.options["listen_port"] || DNS_PORT;
        if (_$rapyd$_in("listen_address", self.options)) {
            ip = self.options["listen_address"];
        }
        self.usock.bind(port, ip);
        function _on_clean_interval() {
            self.clean_query_map();
        }
        self.clean_interval = setInterval(_on_clean_interval, 10 * 1e3);
    };

    DnsProxy.prototype.clean_query_map = function clean_query_map(){
        var self = this;
        var d, now, time_stamp, k;
        "Clean up query map periodically";
        d = new Date();
        now = d.getTime();
        var _$rapyd$_Iter8 = self.query_map;
        for (var _$rapyd$_Index8 = 0; _$rapyd$_Index8 < _$rapyd$_Iter8.length; _$rapyd$_Index8++) {
            k = _$rapyd$_Iter8[_$rapyd$_Index8];
            time_stamp = k[1];
            if (now - time_stamp > self.timeout) {
                delete self.query_map[k];
            }
        }
    };

    function PublicIPBox(domain){
        var self = this;
        "Get public IP of the given domain name.\n\n        @domain: can be the string \"lookup\" or a string of domain name\n        ";
        self.domain = domain;
        self.ip = null;
        self.check_timeout = 10 * 60 * 1e3;
        self.check_iid = null;
        self.start_lookup();
    };


    PublicIPBox.prototype._on_interval = function _on_interval(){
        var self = this;
        var target;
        "lookup public IP and set it";
        target = self.domain;
        function _on_public_ip(public_ip) {
            "Update public IP";
            if (!public_ip) {
                log.warn("Failed to find valid public ip:", self.domain, self.ip);
            } else if (public_ip != self.ip) {
                self.ip = public_ip;
                log.debug("public_ip:", self.domain, self.ip);
            }
        }
        if (target == "lookup") {
            lutils.get_public_ip(_on_public_ip);
        } else {
            function _on_dns_lookup(err, addr, fam) {
                if (err) {
                    log.warn("public_update error:", err);
                }
                _on_public_ip(addr);
            }
            dns.lookup(target, _on_dns_lookup);
        }
    };

    PublicIPBox.prototype.start_lookup = function start_lookup(){
        var self = this;
        self._on_interval();
        if (!self.check_iid) {
            function _on_interval() {
                self._on_interval();
            }
            self.check_iid = setInterval(_on_interval, self.check_timeout);
        }
    };

    function createPublicIPBox(domain_name) {
        var ipbox;
        ipbox = new PublicIPBox(domain_name);
        return ipbox;
    }
    function BaseRouter(address_map){
        var self = this;
        self.address_map = address_map;
        self.public_ip_box = null;
    };


    BaseRouter.prototype.set_public_ip_box = function set_public_ip_box(public_ip_box){
        var self = this;
        self.public_ip_box = public_ip_box;
    };

    BaseRouter.prototype.set = function set(domain, ip){
        var self = this;
        "Add a new domain => ip route";
        self.address_map[domain] = ip;
    };

    BaseRouter.prototype.lookup = function lookup(address){
        var self = this;
        var ip_box, result;
        "lookup ip of a given domain name";
        result = null;
        if (_$rapyd$_in(address, self.address_map)) {
            result = self.address_map[address];
        }
        ip_box = self.public_ip_box;
        if (ip_box !== null && result == ip_box.domain) {
            result = ip_box.ip;
        }
        return result;
    };

    function createServer(options, router) {
        var s;
        s = new DnsProxy(options, router);
        return s;
    }
    function createBaseRouter(address_map) {
        var r;
        r = new BaseRouter(address_map);
        return r;
    }
    function DnsResolver(dns_server, dns_port){
        var self = this;
        self.server = dns_server;
        self.port = dns_port || DNS_PORT;
        self.timeout = 1e4;
        self.id_count = 1;
    };

    _$rapyd$_extends(DnsResolver, EventEmitter);

    DnsResolver.prototype.lookup = function lookup(domain, callback, err_callback){
        var self = this;
        var client, msg_id, msg, buf, offset, timeout_id;
        "Lookup ip of a domain\n        @callback: func(name, ip)\n        ";
        client = dgram.createSocket("udp4");
        client.unref();
        msg_id = self.id_count;
        self.id_count += 1;
        function _on_msg(b, r) {
            self._on_message(b, r, callback);
            clearTimeout(timeout_id);
            client.close();
        }
        function _on_error(err) {
            clearTimeout(timeout_id);
            err.message += ": " + domain;
            if (err_callback) {
                err_callback(err);
            } else {
                self.emit("error", err);
            }
        }
        client.on("message", _on_msg);
        client.on("error", _on_error);
        msg = self.create_a_question(msg_id, domain);
        buf = Buffer(BUFFER_SIZE);
        offset = msg.write_buf(buf);
        log.debug("DNS lookup of %s @%s:%d", domain, self.server, self.port);
        client.send(buf, 0, offset, self.port, self.server);
        function _on_kill_me_timeout() {
            var err;
            client.close();
            err = new DnsLookupError("timeout: " + domain);
            log.debug(err);
            if (err_callback) {
                err_callback(err);
            } else {
                self.emit("error", err);
            }
        }
        timeout_id = setTimeout(_on_kill_me_timeout, self.timeout);
    };

    DnsResolver.prototype.create_a_question = function create_a_question(msg_id, name){
        var self = this;
        var msg;
        "Create a DnsMessage with type \"A\" query question";
        msg = new DnsMessage();
        msg.id = msg_id;
        msg.flags = DNS_FLAGS.RD;
        msg.question = [ {
            "name": name,
            "type": RECORD_TYPES.A,
            "class": DNS_CLASSES.IN
        } ];
        return msg;
    };

    DnsResolver.prototype.ip_from_a_message = function ip_from_a_message(dns_msg){
        var self = this;
        var rec, ans, ip;
        "retrieve lookup result ip from a DNS message";
        rec = null;
        var _$rapyd$_Iter9 = dns_msg.answer;
        for (var _$rapyd$_Index9 = 0; _$rapyd$_Index9 < _$rapyd$_Iter9.length; _$rapyd$_Index9++) {
            ans = _$rapyd$_Iter9[_$rapyd$_Index9];
            if (ans["type"] == RECORD_TYPES.A) {
                rec = ans;
                break;
            }
        }
        if (rec === null) {
            return null;
        }
        ip = decode_ip(rec["rdata"]);
        return {
            "name": rec["name"],
            "ip": ip
        };
    };

    DnsResolver.prototype._on_message = function _on_message(buf, remote_info, callback){
        var self = this;
        var msg, result, name, ip;
        "receive a DNS query result";
        if (buf.length > BUFFER_SIZE) {
            BUFFER_SIZE = buf.length;
        }
        msg = new DnsMessage(buf);
        name = null;
        ip = null;
        result = self.ip_from_a_message(msg);
        if (result !== null) {
            name = result["name"];
            ip = result["ip"];
        }
        if (callback) {
            callback(name, ip);
        }
        self.emit("resolved", name, ip);
    };

    function createDnsResolver(address, port) {
        var s;
        s = new DnsResolver(address, port);
        return s;
    }
    function main() {
        var router, options, childp, qs, cmd_prefix, dr;
        "Run test";
        log.set_level(log.DEBUG);
        router = new BaseRouter({
            "www.sohu.com": "127.0.0.1"
        });
        options = {
            "dns_host": "8.8.8.8",
            "listen_port": 2e3
        };
        new DnsProxy(options, router).start();
        childp = require("child_process");
        qs = [ "www.sohu.com", "www.sohu.com mx", "fhk.a.sohu.com" ];
        cmd_prefix = "/usr/bin/dig @127.0.0.1 -p 2000 ";
        function rerun(error, stdout, stderr) {
            var cmd;
            if (stdout) {
                console.log(stdout);
            }
            if (error) {
                console.log(error);
            }
            if (qs.length > 0) {
                cmd = cmd_prefix + qs.pop();
                console.log("$", cmd);
                childp.exec(cmd, rerun);
            }
        }
        rerun();
        dr = new DnsResolver("156.154.71.1");
        function rcb(n, i) {
            console.log("resolver callback", n, i);
        }
        dr.lookup("h1.edu.bj.ie.sogou.com", rcb);
        dr.lookup("h2.edu.bj.ie.sogou.com");
        dr.on("resolved", rcb);
    }
    if (require.main === module) {
        main();
    }
    exports.DnsProxy = DnsProxy;
    exports.BaseRouter = BaseRouter;
    exports.createDnsResolver = createDnsResolver;
    exports.createServer = createServer;
    exports.createBaseRouter = createBaseRouter;
    exports.createPublicIPBox = createPublicIPBox;
})();
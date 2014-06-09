(function(){
    function _$rapyd$_extends(child, parent) {
        child.prototype = Object.create(parent.prototype);
        child.prototype.constructor = child;
    }
    function _$rapyd$_in(val, arr) {
        if (arr instanceof Array || typeof arr === "string") return arr.indexOf(val) != -1;
        else {
            for (i in arr) {
                if (arr.hasOwnProperty(i) && i === val) return true;
            }
            return false;
        }
    }
    var SOCKET_TIMEOUT, UAGENT_CHROME, RATE_LIMITER_DENY_TIMEOUT, http, net, url, dns, EventEmitter, shared_urls, shared_tools, sogou, string_starts_with, to_title_case, SOGOU_IPS, logger, url_match, USER_DOMAIN_MAP;
    "Local utility functions and classes";
    SOCKET_TIMEOUT = 10 * 1e3;
    UAGENT_CHROME = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_8_2) AppleWebKit/537.11 (KHTML, like Gecko) Chrome/23.0.1271.95 Safari/537.11";
    RATE_LIMITER_DENY_TIMEOUT = 5 * 60;
    http = require("http");
    net = require("net");
    url = require("url");
    dns = require("dns");
    EventEmitter = require("events").EventEmitter;
    shared_urls = require("../shared/urls");
    shared_tools = require("../shared/tools");
    sogou = require("../shared/sogou");
    string_starts_with = shared_tools.string_starts_with;
    to_title_case = shared_tools.to_title_case;
    SOGOU_IPS = [ "121.195.", "123.126.", "220.181." ];
    function Logger(level){
        var self = this;
        if (typeof level === "undefined") level = null;
        self.CRITICAL = 50;
        self.ERROR = 40;
        self.WARN = 30;
        self.INFO = 20;
        self.DEBUG = 10;
        self.NOTSET = 0;
        if (level === null) {
            level = self.INFO;
        }
        self.level = level;
    };


    Logger.prototype.set_level = function set_level(level){
        var self = this;
        self.level = level;
    };

    Logger.prototype._log = function _log(){
        var self = this;
        var level = arguments[0];
        var args = [].slice.call(arguments, 1);
        if (level >= self.level) {

    var str = "[";

    var currentTime = new Date();
    var years = currentTime.getFullYear();
    var months = currentTime.getMonth()+1;
    var dates = currentTime.getDate();
    var hours = currentTime.getHours();
    var minutes = currentTime.getMinutes();
    var seconds = currentTime.getSeconds();

    if (months <10) {
        months = "0" + months;
    }
    if (dates <10) {
        dates = "0" + dates;
    }
    if (minutes < 10) {
        minutes = "0" + minutes;
    }
    if (seconds < 10) {
        seconds = "0" + seconds;
    }
    str += months + "/" + dates + "/" + years +" " +hours%12 + ":" + minutes + ":" + seconds;
    if(hours > 11){
        str += " PM]";
    } else {
        str += " AM]";
    }            

    process.stdout.write(str+" ");
            console.log.apply(console, [].concat(args));
        }
    };

    Logger.prototype.msg = function msg(){
        var self = this;
        var args = [].slice.call(arguments, 0);
        self._log.apply(self, [self.NOTSET].concat(args));
    };

    Logger.prototype.debug = function debug(){
        var self = this;
        var args = [].slice.call(arguments, 0);
        self._log.apply(self, [self.DEBUG].concat(args));
    };

    Logger.prototype.info = function info(){
        var self = this;
        var args = [].slice.call(arguments, 0);
        self._log.apply(self, [self.INFO].concat(args));
    };

    Logger.prototype.log = function log(){
        var self = this;
        var args = [].slice.call(arguments, 0);
        self.info.apply(self, [].concat(args));
    };

    Logger.prototype.warn = function warn(){
        var self = this;
        var args = [].slice.call(arguments, 0);
        self._log.apply(self, [self.WARN].concat(args));
    };

    Logger.prototype.error = function error(){
        var self = this;
        var args = [].slice.call(arguments, 0);
        self._log.apply(self, [self.ERROR].concat(args));
    };

    Logger.prototype.critical = function critical(){
        var self = this;
        var args = [].slice.call(arguments, 0);
        self._log.apply(self, [self.CRITICAL].concat(args));
    };

    logger = new Logger();
    function add_sogou_headers(req_headers, hostname) {
        var sogou_auth, timestamp, sogou_tag, random_ip;
        sogou_auth = sogou.new_sogou_auth_str();
        timestamp = Math.round(Date.now() / 1e3).toString(16);
        sogou_tag = sogou.compute_sogou_tag(timestamp, hostname);
        req_headers["X-Sogou-Auth"] = sogou_auth;
        req_headers["X-Sogou-Timestamp"] = timestamp;
        req_headers["X-Sogou-Tag"] = sogou_tag;
        random_ip = shared_tools.new_random_ip();
        req_headers["X-Forwarded-For"] = random_ip;
        req_headers["Client-IP"] = random_ip;
    }
    function URLMatch(url_list, prefix_len){
        var self = this;
        "Speedup regex matching to a long list of urls\n\n        use prefix of the regex pattern as keys to category the url list\n        into groups\n        ";
        self.prefix_len = prefix_len || 15;
        self.regex_map = self.create_map(url_list, self.prefix_len);
    };


    URLMatch.prototype.create_map = function create_map(url_list, prefix_len){
        var self = this;
        var url_map, k, val_list, url, regex_map, regex_list;
        "create a map between the prefix of urls to regex list";
        url_map = {};
        var _$rapyd$_Iter0 = url_list;
        for (var _$rapyd$_Index0 = 0; _$rapyd$_Index0 < _$rapyd$_Iter0.length; _$rapyd$_Index0++) {
            url = _$rapyd$_Iter0[_$rapyd$_Index0];
            k = url.slice(0, prefix_len);
            if (k.indexOf("*") >= 0) {
                k = "any";
            }
            val_list = url_map[k] || [];
            if (val_list.length === 0) {
                url_map[k] = val_list;
            }
            val_list.push(url);
        }
        regex_map = {};
        var _$rapyd$_Iter1 = Object.keys(url_map);
        for (var _$rapyd$_Index1 = 0; _$rapyd$_Index1 < _$rapyd$_Iter1.length; _$rapyd$_Index1++) {
            k = _$rapyd$_Iter1[_$rapyd$_Index1];
            regex_list = shared_urls.urls2regexs(url_map[k]);
            regex_map[k] = regex_list;
        }
        return regex_map;
    };

    URLMatch.prototype.test = function test(url){
        var self = this;
        var k, regex_list, ret, pattern;
        k = url.slice(0, self.prefix_len);
        regex_list = self.regex_map[k] || self.regex_map["any"];
        ret = false;
        var _$rapyd$_Iter2 = regex_list;
        for (var _$rapyd$_Index2 = 0; _$rapyd$_Index2 < _$rapyd$_Iter2.length; _$rapyd$_Index2++) {
            pattern = _$rapyd$_Iter2[_$rapyd$_Index2];
            if (pattern.test(url)) {
                ret = true;
                break;
            }
        }
        return ret;
    };

    url_match = null;
    function is_valid_url(target_url) {
        var white_pattern;
        if (url_match === null) {
            url_match = new URLMatch(shared_urls.url_list);
        }
        var _$rapyd$_Iter3 = shared_urls.url_regex_whitelist;
        for (var _$rapyd$_Index3 = 0; _$rapyd$_Index3 < _$rapyd$_Iter3.length; _$rapyd$_Index3++) {
            white_pattern = _$rapyd$_Iter3[_$rapyd$_Index3];
            if (white_pattern.test(target_url)) {
                return false;
            }
        }
        if (url_match.test(target_url)) {
            return true;
        }
        if (string_starts_with(target_url, "http://httpbin.org")) {
            return true;
        }
        return false;
    }
    function SogouManager(dns_resolver, proxy_list){
        var self = this;
        if (typeof proxy_list === "undefined") proxy_list = null;
        "\n        @dns_resolver : an optional DnsResolver to lookup sogou server IP\n        @proxy_list: user supplied proxy list instead of sogou proxy servers\n        ";
        self.dns_resolver = dns_resolver;
        self.proxy_list = proxy_list;
        self.sogou_network = null;
    };

    _$rapyd$_extends(SogouManager, EventEmitter);

    SogouManager.prototype.new_proxy_address = function new_proxy_address(){
        var self = this;
        var random_num, new_addr, good_net;
        "Return a new proxy server address";
        if (self.proxy_list !== null) {
            random_num = Math.floor(Math.random() * self.proxy_list.length);
            new_addr = self.proxy_list[random_num];
        } else {
            new_addr = sogou.new_sogou_proxy_addr();
            if (self.sogou_network) {
                good_net = new_addr.indexOf(self.sogou_network) >= 0;
                while (!good_net) {
                    new_addr = sogou.new_sogou_proxy_addr();
                    good_net = new_addr.indexOf(self.sogou_network) >= 0;
                }
            }
        }
        return new_addr;
    };

    SogouManager.prototype.renew_sogou_server = function renew_sogou_server(depth){
        var self = this;
        if (typeof depth === "undefined") depth = 0;
        var new_addr, parts, new_domain, new_port, new_ip, addr_info;
        new_addr = self.new_proxy_address();
        parts = new_addr.split(":");
        new_domain = parts[0];
        new_port = parseInt(parts[1] || 80);
        new_ip = null;
        if (self.dns_resolver && !net.isIPv4(new_addr)) {
            function _lookup_cb(name, ip) {
                var addr_info;
                addr_info = {
                    "address": name,
                    "ip": ip,
                    "port": new_port
                };
                self.check_sogou_server(addr_info, depth);
            }
            function _err_cb(err) {
                self.emit("error", err);
            }
            self.dns_resolver.lookup(new_domain, _lookup_cb, _err_cb);
        } else {
            addr_info = {
                "address": new_domain,
                "port": new_port
            };
            self.check_sogou_server(addr_info, depth);
        }
    };

    SogouManager.prototype._on_check_sogou_success = function _on_check_sogou_success(addr_info){
        var self = this;
        var domain;
        "Called when sogou server check success";
        self.emit("renew-address", addr_info);
        domain = addr_info["address"];
        function _on_lookup(err, addr, family) {
            var valid, sgip;
            valid = false;
            if (/sogou\.com$/.test(domain) === false) {
                valid = true;
            }
            var _$rapyd$_Iter4 = SOGOU_IPS;
            for (var _$rapyd$_Index4 = 0; _$rapyd$_Index4 < _$rapyd$_Iter4.length; _$rapyd$_Index4++) {
                sgip = _$rapyd$_Iter4[_$rapyd$_Index4];
                if (addr.indexOf(sgip) === 0) {
                    valid = true;
                    break;
                }
            }
            if (!valid) {
                logger.warn("WARN: sogou IP (%s -> %s) seems invalid", domain, addr);
            }
        }
        if (!addr_info["ip"]) {
            dns.lookup(addr_info["address"], 4, _on_lookup);
        } else {
            _on_lookup(null, addr_info["ip"], null);
        }
    };

    SogouManager.prototype.check_sogou_server = function check_sogou_server(addr_info, depth){
        var self = this;
        if (typeof depth === "undefined") depth = 0;
        var new_addr, new_ip, new_port, headers, options, req;
        "check validity of proxy.\n        emit \"renew-address\" on success\n        ";
        if (depth >= 10) {
            logger.warn("WARN: renew sogou failed, max depth reached");
            self.emit("renew-address", addr_info);
            return;
        }
        new_addr = addr_info["address"];
        new_ip = addr_info["ip"];
        new_port = addr_info["port"];
        if (/sogou\.com$/.test(new_addr) === false) {
            self._on_check_sogou_success(addr_info);
            return;
        }
        headers = {
            "Accept-Language": "en-US,en;q=0.8,zh-CN;q=0.6,zh;q=0.4,zh-TW;q=0.2",
            "Accept-Encoding": "deflate",
            "Accept": "text/html,application/xhtml+xml," + "application/xml;q=0.9,*/*;q=0.8",
            "User-Agent": UAGENT_CHROME,
            "Accept-Charset": "gb18030,utf-8;q=0.7,*;q=0.3"
        };
        options = {
            host: new_ip || new_addr,
            port: new_port,
            headers: headers
        };
        logger.debug("check sogou adderss:", addr_info, options.host);
        function on_response(res) {
            if (400 == res.statusCode) {
                self._on_check_sogou_success(addr_info);
            } else {
                logger.error("[ub.uku.js] statusCode for %s is unexpected: %d", new_addr, res.statusCode);
                self.renew_sogou_server(depth + 1);
            }
        }
        req = http.request(options, on_response);
        function on_socket(socket) {
            function on_socket_timeout() {
                req.abort();
                logger.error("[ub.uku.js] Timeout for %s. Aborted.", new_addr);
            }
            socket.setTimeout(SOCKET_TIMEOUT, on_socket_timeout);
        }
        req.on("socket", on_socket);
        function on_error(err) {
            logger.error("[ub.uku.js] Error when testing %s: %s", new_addr, err);
            self.renew_sogou_server(depth + 1);
        }
        req.on("error", on_error);
        req.end();
    };

    function RateLimiter(options){
        var self = this;
        "\n            options:\n                rate-limit: access/sec\n                deny-timeout: timeout for reactive on denied IP\n        ";
        self.options = options;
        self.name = null;
        self.deny_timeout = RATE_LIMITER_DENY_TIMEOUT * 1e3;
        if (options["deny-timeout"]) {
            self.deny_timeout = options["deny-timeout"] * 1e3;
        }
        self.interval_reset = null;
        self.access_counts = {};
        self.deny_map = {};
        self.start();
    };


    RateLimiter.prototype.set_name = function set_name(name){
        var self = this;
        self.name = name;
    };

    RateLimiter.prototype._do_reset = function _do_reset(){
        var self = this;
        var now, time_stamp, k;
        "Reset rate count and deny queue";
        self.access_counts = {};
        now = Date.now();
        var _$rapyd$_Iter5 = Object.keys(self.deny_map);
        for (var _$rapyd$_Index5 = 0; _$rapyd$_Index5 < _$rapyd$_Iter5.length; _$rapyd$_Index5++) {
            k = _$rapyd$_Iter5[_$rapyd$_Index5];
            time_stamp = self.deny_map[k];
            if (now > time_stamp) {
                delete self.deny_map[k];
            }
        }
    };

    RateLimiter.prototype.over_limit = function over_limit(saddr){
        var self = this;
        var ac_count, msg, ret;
        "Check if the rate limit is over for a source address";
        if (self.options["rate-limit"] < 0) {
            return false;
        }
        if (self.deny_map[saddr]) {
            return true;
        }
        ret = false;
        ac_count = self.access_counts[saddr] || 0;
        ac_count += 1;
        self.access_counts[saddr] = ac_count;
        if (ac_count > self.options["rate-limit"]) {
            msg = "DoS Flood Attack:";
            if (self.name !== null) {
                msg = self.name + " " + msg;
            }
            logger.warn(msg, saddr);
            ret = true;
            self.add_deny(saddr);
        }
        return ret;
    };

    RateLimiter.prototype.add_deny = function add_deny(saddr){
        var self = this;
        "Add a source address to the deny map";
        self.deny_map[saddr] = Date.now() + self.deny_timeout;
        if (self.access_counts[saddr]) {
            delete self.access_counts[saddr];
        }
    };

    RateLimiter.prototype.start = function start(){
        var self = this;
        "start the periodic check";
        if (self.options["rate-limit"] <= 0) {
            return;
        }
        if (self.interval_reset) {
            clearInterval(self.interval_reset);
            self.interval_reset = null;
        }
        function _do_reset() {
            self._do_reset();
        }
        self.interval_reset = setInterval(_do_reset, 1e3);
    };

    RateLimiter.prototype.stop = function stop(){
        var self = this;
        "stop the periodic check";
        if (self.interval_reset) {
            clearInterval(self.interval_reset);
            self.interval_reset = null;
        }
        self.access_counts = {};
        self.deny_map = {};
    };

    function createRateLimiter(options) {
        var rl;
        rl = new RateLimiter(options);
        return rl;
    }
    function createSogouManager(dns_resolver, proxy_list) {
        if (typeof proxy_list === "undefined") proxy_list = null;
        var s;
        s = new SogouManager(dns_resolver, proxy_list);
        return s;
    }
    function filtered_request_headers(headers, forward_cookie) {
        var ret_headers, field;
        ret_headers = {};
        var _$rapyd$_Iter6 = Object.keys(headers);
        for (var _$rapyd$_Index6 = 0; _$rapyd$_Index6 < _$rapyd$_Iter6.length; _$rapyd$_Index6++) {
            field = _$rapyd$_Iter6[_$rapyd$_Index6];
            if (string_starts_with(field, "proxy-")) {
                if (field == "proxy-connection") {
                    ret_headers.Connection = headers["proxy-connection"];
                }
            } else if (field == "cookie") {
                if (forward_cookie) {
                    ret_headers.Cookie = headers.cookie;
                }
            } else if (field == "user-agent") {
                if (headers["user-agent"].indexOf("CloudFront") != -1 || headers["user-agent"].indexOf("CloudFlare") != -1) {
                    ret_headers["User-Agent"] = UAGENT_CHROME;
                } else {
                    ret_headers["User-Agent"] = headers["user-agent"];
                }
            } else if (field != "via" && !string_starts_with(field, "x-")) {
                ret_headers[to_title_case(field)] = headers[field];
            }
        }
        return ret_headers;
    }
    USER_DOMAIN_MAP = null;
    function fetch_user_domain() {
        var domain_dict, parsed_url, hostname, u;
        "Fetch a list of domains for the filtered ub.uku urls";
        if (USER_DOMAIN_MAP !== null) {
            return USER_DOMAIN_MAP;
        }
        domain_dict = {};
        var _$rapyd$_Iter7 = shared_urls.url_list;
        for (var _$rapyd$_Index7 = 0; _$rapyd$_Index7 < _$rapyd$_Iter7.length; _$rapyd$_Index7++) {
            u = _$rapyd$_Iter7[_$rapyd$_Index7];
            if (u.indexOf("https") === 0) {
                continue;
            }
            parsed_url = url.parse(u);
            hostname = parsed_url.hostname;
            if (hostname && !(_$rapyd$_in(hostname, domain_dict))) {
                domain_dict[hostname] = true;
            }
        }
        USER_DOMAIN_MAP = domain_dict;
        return USER_DOMAIN_MAP;
    }
    function get_public_ip(cb) {
        "get public ip from http://httpbin.org/ip then call cb";
        function _on_ip_response(res) {
            var content;
            content = "";
            function _on_data(x) {
                content += x.toString("utf-8");
            }
            function _on_end() {
                var content_json, lookup_ip;
                content_json = JSON.parse(content);
                lookup_ip = content_json["origin"];
                cb(lookup_ip);
            }
            function _on_error(err) {
                logger.error("Err on get public ip:", err);
            }
            res.on("data", _on_data);
            res.on("end", _on_end);
            res.on("error", _on_error);
        }
        http.get("http://httpbin.org/ip", _on_ip_response);
    }
    exports.logger = logger;
    exports.add_sogou_headers = add_sogou_headers;
    exports.is_valid_url = is_valid_url;
    exports.createSogouManager = createSogouManager;
    exports.createRateLimiter = createRateLimiter;
    exports.filtered_request_headers = filtered_request_headers;
    exports.fetch_user_domain = fetch_user_domain;
    exports.get_public_ip = get_public_ip;
})();

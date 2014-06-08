(function(){
    function _$rapyd$_extends(child, parent) {
        child.prototype = Object.create(parent.prototype);
        child.prototype.constructor = child;
    }
    function getattr(obj, name) {
        return obj[name];
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
    var httpProxy, http, EventEmitter, sogou, dns_proxy, lutils, log, HTTP_RATE_LIMIT, MAX_ERROR_COUNT;
    httpProxy = require("http-proxy");
    http = require("http");
    EventEmitter = require("events").EventEmitter;
    sogou = require("../shared/sogou");
    dns_proxy = require("./dns-proxy");
    lutils = require("./lutils");
    log = lutils.logger;
    HTTP_RATE_LIMIT = 10;
    MAX_ERROR_COUNT = {
        "reset_count": 1,
        "refuse_count": 2,
        "timeout_count": 4
    };
    
    
    function ReverseSogouProxy(options){
        var self = this;
        var rate_limit;
        "\n            options:\n                listen_port: dns proxy port. default: 80\n                listen_address: dns proxy address. default: 0.0.0.0\n                sogou_dns: dns used to lookup sogou server ip\n                sogou_network: sogou network: \"dxt\" or \"edu\"\n                external_ip: optional public ip of a exit router\n            events:\n                \"listening\": emit after server has been bound to listen port\n        ";
        self.options = options;
        self.banned = {};
        self.sogou_renew_timeout = 10 * 60 * 1e3;
        self.public_ip_box = null;
        self.request_id = 1;
        self.proxy_host = "0.0.0.0";
        self.proxy_port = 80;
        if (options["listen_port"]) {
            self.proxy_port = options["listen_port"];
        }
        if (options["listen_address"]) {
            self.proxy_host = options["listen_address"];
        }
        self.proxy = self.setup_proxy(options);
        self.server = self.setup_server(options);
        rate_limit = self.options["http_rate_limit"] || HTTP_RATE_LIMIT;
        self.rate_limiter = lutils.createRateLimiter({
            "rate-limit": rate_limit
        });
        self.rate_limiter.set_name("HTTP Proxy");
        self.reset_sogou_flags();
        self.setup_sogou_manager();
        self.sogou_info = {
            "address": sogou.new_sogou_proxy_addr()
        };
    };

    _$rapyd$_extends(ReverseSogouProxy, EventEmitter);

    ReverseSogouProxy.prototype.setup_sogou_manager = function setup_sogou_manager(){
        var self = this;
        var sg_dns, dns_resolver;
        "Manage which sogou proxy server we choose";
        dns_resolver = null;
        if (self.options["sogou_dns"]) {
            sg_dns = self.options["sogou_dns"];
            log.info("Sogou proxy DNS solver:", sg_dns);
            dns_resolver = dns_proxy.createDnsResolver(sg_dns);
        }
        self.sogou_manager = lutils.createSogouManager(dns_resolver, self.options["proxy_list"]);
        self.sogou_manager.sogou_network = self.options["sogou_network"];
        function _on_renew_address(addr_info) {
            log.info("renewed sogou server:", addr_info);
            self.sogou_info = addr_info;
            self.reset_sogou_flags();
        }
        function _on_error(err) {
            self.in_changing_sogou = -1;
            log.error("Error on renew sogou:", err);
        }
        self.sogou_manager.on("renew-address", _on_renew_address);
        self.sogou_manager.on("error", _on_error);
        self.renew_sogou_server(true);
    };

    ReverseSogouProxy.prototype.reset_sogou_flags = function reset_sogou_flags(){
        var self = this;
        "sogou server renew related flags";
        self.in_changing_sogou = -1;
        self.reset_count = 0;
        self.refuse_count = 0;
        self.timeout_count = 0;
    };

    ReverseSogouProxy.prototype.renew_sogou_server = function renew_sogou_server(forced){
        var self = this;
        if (typeof forced === "undefined") forced = false;
        var need_reset, k;
        "Change to a new sogou proxy server";
        need_reset = forced;
        var _$rapyd$_Iter0 = Object.keys(MAX_ERROR_COUNT);
        for (var _$rapyd$_Index0 = 0; _$rapyd$_Index0 < _$rapyd$_Iter0.length; _$rapyd$_Index0++) {
            k = _$rapyd$_Iter0[_$rapyd$_Index0];
            if (getattr(self, k) > MAX_ERROR_COUNT[k]) {
                need_reset = true;
                break;
            }
        }
        if (need_reset === false) {
            return;
        }
        if (0 < (_$rapyd$_Temp = self.in_changing_sogou) && _$rapyd$_Temp < Date.now()) {
            return;
        }
        self.in_changing_sogou = Date.now() + self.sogou_renew_timeout;
        log.debug("changing sogou server...");
        self.sogou_manager.renew_sogou_server();
    };

    ReverseSogouProxy.prototype.setup_proxy = function setup_proxy(options){
        var self = this;
        var proxy;
        "create the node proxy server instance";
        proxy = httpProxy.createServer();
        function on_error(err, req, res) {
            self._on_proxy_error(err, req, res);
        }
        function on_proxy_response(res) {
            self._on_proxy_response(res);
        }
        proxy.on("error", on_error);
        proxy.on("proxyRes", on_proxy_response);
        return proxy;
    };

    ReverseSogouProxy.prototype.setup_server = function setup_server(options){
        var self = this;
        var server;
        "create the standard node http server to accept request";
        function on_request(req, res) {
            self.do_proxy(req, res);
        }
        function _on_connection(sock) {
            self._on_server_connection(sock);
        }
        function _on_client_error(err, sock) {
            var r_ip;
            r_ip = sock.remoteAddress;
            if (!r_ip) {
                try {
                    r_ip = sock._peername["address"];
                } catch (_$rapyd$_Exception) {
                }
            }
            log.error("HTTP Server clientError:", err, r_ip);
        }
        function _on_error(err) {
            log.error("HTTP Server Error:", err);
            process.exit({code: 2});
        }
        server = http.createServer(on_request);
        server.on("connection", _on_connection);
        server.on("clientError", _on_client_error);
        server.on("error", _on_error);
        return server;
    };

    ReverseSogouProxy.prototype.do_proxy = function do_proxy(req, res){
        var self = this;
        var raw_host, host_parts, host, port, domain_map, proxy, url, to_use_proxy, forward_cookies, si, sogou_host, sogou_port, proxy_options, headers;
        "The handler of node proxy server";
        raw_host = req.headers["host"] || req.headers["Host"];
        if (!raw_host) {
            self._handle_unknown_host(req, res);
            return;
        }
        host_parts = raw_host.split(":");
        host = host_parts[0];
        port = parseInt(host_parts[1] || 80);
        domain_map = lutils.fetch_user_domain();
        if (!domain_map[host]) {
            self._handle_unknown_host(req, res);
            return;
        }
        proxy = self.proxy;
        if (req.url.indexOf("http") !== 0) {
            if (port == 80) {
                url = "http://" + host + req.url;
            } else {
                url = "http://" + host + ":" + port + req.url;
            }
            req.url = url;
        } else {
            url = req.url;
        }
        to_use_proxy = lutils.is_valid_url(url);
        log.debug("do_proxy[%s] req.url:", self.request_id, url, to_use_proxy);
        req.headers["X-Droxy-SG"] = "" + to_use_proxy;
        req.headers["X-Droxy-RID"] = "" + self.request_id;
        self.request_id += 1;
        forward_cookies = false;
        if (req.url.indexOf("http") === 0) {
            forward_cookies = true;
        }
        if (to_use_proxy) {
            si = self.sogou_info;
            sogou_host = si["ip"] || si["address"];
            sogou_port = si["port"];
            lutils.add_sogou_headers(req.headers, req.headers["host"]);
            proxy_options = {
                "target": {
                    "host": sogou_host,
                    "port": sogou_port
                },
                "toProxy": true
            };
        } else {
            proxy_options = {
                "target": req.url
            };
        }
        headers = lutils.filtered_request_headers(req.headers, forward_cookies);
        req.headers = headers;
        log.debug("do_proxy[%s] headers:", headers["X-Droxy-Rid"], headers, req.socket.remoteAddress);
        proxy.web(req, res, proxy_options);
    };

    ReverseSogouProxy.prototype._on_server_connection = function _on_server_connection(sock){
        var self = this;
        var raddress;
        "Prevent DoS";
        raddress = sock.remoteAddress;
        if (self.rate_limiter.over_limit(raddress) || self.banned[raddress]) {
            sock.destroy();
        }
    };

    ReverseSogouProxy.prototype._on_proxy_error = function _on_proxy_error(err, req, res){
        var self = this;
        log.error("_on_proxy_error:", err, req.headers["Host"], req.url, req.socket.remoteAddress);
        if ("ECONNRESET" === err.code) {
            self.reset_count += 1;
        } else if ("ECONNREFUSED" === err.code) {
            self.refuse_count += 1;
        } else if ("ETIMEDOUT" === err.code) {
            self.timeout_count += 1;
        } else {
            self.reset_count += 1;
        }
        self.renew_sogou_server();
    };

    ReverseSogouProxy.prototype._on_proxy_response = function _on_proxy_response(res){
        var self = this;
        var req, to_use_proxy, req_id, via, mitm, s;
        req = res.req;
        to_use_proxy = parseInt(req._headers["x-droxy-sg"]);
        req_id = parseInt(req._headers["x-droxy-rid"]);
        mitm = false;
        if (res.statusCode >= 400) {
            via = res.headers["via"];
            if (!via) {
                via = res.headers["Via"];
            }
            if (to_use_proxy == "true" && (!via || via.indexOf("sogou-in.domain") < 0)) {
                mitm = true;
            }
        }
        if (mitm === true) {
            s = res.socket;
            log.warn("We are fucked by man-in-the-middle[%d]:\n", req_id, res.headers, res.statusCode, s.remoteAddress + ":" + s.remotePort);
            res.statusCode = 502;
            self.refuse_count += 1;
            self.renew_sogou_server();
        } else {
            log.debug("_on_proxy_response[%d] headers:", req_id, res.headers, res.statusCode);
        }
    };

    ReverseSogouProxy.prototype._handle_unknown_host = function _handle_unknown_host(req, res){
        var self = this;
        var sock, raddress, local_hosts;
        "In case we see an request with unknown/un-routed \"host\" ";
        sock = req.socket;
        raddress = sock.remoteAddress;
        sock.destroy();
        local_hosts = [ self.options["listen_address"], self.options["external_ip"] ];
        if (self.public_ip_box !== null) {
            local_hosts.push(self.public_ip_box.ip);
        }
        if (_$rapyd$_in(raddress, local_hosts)) {
            self.rate_limiter.add_deny(raddress);
        } else {
            self.banned[raddress] = true;
        }
        log.warn("HTTP Proxy DoS attack:", req.headers, req.url, raddress);
    };

    ReverseSogouProxy.prototype._on_listening = function _on_listening(){
        var self = this;
        var addr;
        addr = self.server.address();
        log.info("Sogou proxy listens on %s:%d", addr.address, addr.port);
        self.emit("listening");
    };

    ReverseSogouProxy.prototype.set_public_ip_box = function set_public_ip_box(public_ip_box){
        var self = this;
        self.public_ip_box = public_ip_box;
    };

    ReverseSogouProxy.prototype.start = function start(){
        var self = this;
        var sogou_renew_timer;
        function _on_listen() {
            self._on_listening();
        }
        self.server.listen(self.proxy_port, self.proxy_host, _on_listen);
        function on_renew_timeout() {
            self.renew_sogou_server(true);
        }
        sogou_renew_timer = setInterval(on_renew_timeout, self.sogou_renew_timeout);
        sogou_renew_timer.unref();
    };

    function createServer(options) {
        var s;
        s = new ReverseSogouProxy(options);
        return s;
    }
    function main() {
        var options, s, client_options;
        "Run test";
        log.set_level(log.DEBUG);
        function run_local_proxy() {
            var proxy;
            proxy = httpProxy.createServer();
            function on_request(req, res) {
                proxy.web(req, res, {
                    "target": req.url
                });
            }
            http.createServer(on_request).listen(9010);
        }
        run_local_proxy();
        options = {
            "listen_port": 8080,
            "listen_address": "127.0.0.1",
            "sogou_dns": "8.8.4.4"
        };
        s = new ReverseSogouProxy(options);
        s.start();
        client_options = {
            "host": "127.0.0.1",
            "port": 8080,
            "path": "http://httpbin.org/ip",
            "headers": {
                "Host": "httpbin.org"
            }
        };
        log.info("wait for a while...");
        function on_client_start() {
            log.info("start download...");
            function on_response(res) {
                res.pipe(process.stdout);
            }
            http.get(client_options, on_response);
        }
        setTimeout(on_client_start, 12e3);
    }
    if (require.main === module) {
        main();
    }
    exports.ReverseSogouProxy = ReverseSogouProxy;
    exports.createServer = createServer;
})();
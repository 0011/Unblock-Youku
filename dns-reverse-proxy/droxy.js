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
    var path, fs, net, dnsproxy, reversesogouproxy, lutils, log, appname, server_count;
    path = require("path");
    fs = require("fs");
    net = require("net");
    dnsproxy = require("./dns-proxy");
    reversesogouproxy = require("./reverse-sogou-proxy");
    lutils = require("./lutils");
    log = lutils.logger;
    appname = "ub.uku.droxy";
    function load_resolv_conf() {
        var fname, data, lines, parts, dns_host, line;
        "Parse /etc/resolv.conf and return 1st dns host found";
        fname = "/etc/resolv.conf";
        data = fs.readFileSync(fname, "utf-8");
        lines = data.split("\n");
        dns_host = null;
        var _$rapyd$_Iter0 = lines;
        for (var _$rapyd$_Index0 = 0; _$rapyd$_Index0 < _$rapyd$_Iter0.length; _$rapyd$_Index0++) {
            line = _$rapyd$_Iter0[_$rapyd$_Index0];
            if (line[0] == "#") {
                continue;
            }
            parts = line.split(" ");
            if (parts[0].toLowerCase() == "nameserver") {
                dns_host = parts[1];
                break;
            }
        }
        return dns_host;
    }
    function load_dns_map(target_ip) {
        var domain_map, dmap, domain;
        "Create a DNS router to map a list of domain name to a target ip";
        if (!target_ip) {
            target_ip = "127.0.0.1";
        }
        domain_map = lutils.fetch_user_domain();
        dmap = {};
        var _$rapyd$_Iter1 = Object.keys(domain_map);
        for (var _$rapyd$_Index1 = 0; _$rapyd$_Index1 < _$rapyd$_Iter1.length; _$rapyd$_Index1++) {
            domain = _$rapyd$_Iter1[_$rapyd$_Index1];
            dmap[domain] = target_ip;
        }
        dmap["httpbin.org"] = target_ip;
        return dmap;
    }
    function load_router_from_file(fname, dns_map) {
        var data, rdict, k;
        "Load domain -> ip map from a JSON file";
        if (!(fname && fs.existsSync(fname))) {
            log.error("extra router file not found:", fname);
            process.exit(2);
        }
        data = fs.readFileSync(fname, "utf-8");
        data = data.replace(/,(\s*[\}|\]])/g, "$1");
        rdict = JSON.parse(data);
        var _$rapyd$_Iter2 = Object.keys(rdict);
        for (var _$rapyd$_Index2 = 0; _$rapyd$_Index2 < _$rapyd$_Iter2.length; _$rapyd$_Index2++) {
            k = _$rapyd$_Iter2[_$rapyd$_Index2];
            dns_map[k] = rdict[k];
        }
    }
    function load_extra_url_list(fname) {
        var data, url_list, shared_urls, url_regex, u, r;
        "Add extra url list to the shared urls\n    The input file is a JSON file with a single array of url pattern strings\n    ";
        if (!(fname && fs.existsSync(fname))) {
            log.error("extra url filter file not found:", fname);
            process.exit(2);
        }
        data = fs.readFileSync(fname, "utf-8");
        data = data.replace(/,(\s*[\}|\]])/g, "$1");
        url_list = JSON.parse(data);
        shared_urls = require("../shared/urls.js");
        url_regex = shared_urls.urls2regexs(url_list);
        var _$rapyd$_Iter3 = url_list;
        for (var _$rapyd$_Index3 = 0; _$rapyd$_Index3 < _$rapyd$_Iter3.length; _$rapyd$_Index3++) {
            u = _$rapyd$_Iter3[_$rapyd$_Index3];
            shared_urls.url_list.push(u);
        }
        var _$rapyd$_Iter4 = url_regex;
        for (var _$rapyd$_Index4 = 0; _$rapyd$_Index4 < _$rapyd$_Iter4.length; _$rapyd$_Index4++) {
            r = _$rapyd$_Iter4[_$rapyd$_Index4];
            shared_urls.url_regex_list.push(r);
        }
    }
    function drop_root(options) {
        var chroot, rdir, ruser, k, resolv_path, _;
        "change root and drop root priviledge";
        try {
            chroot = require("chroot");
            rdir = options["chroot_dir"];
            ruser = options["run_as"];
            chroot(rdir, ruser);
            var _$rapyd$_Iter5 = Object.keys(process.env);
            for (var _$rapyd$_Index5 = 0; _$rapyd$_Index5 < _$rapyd$_Iter5.length; _$rapyd$_Index5++) {
                k = _$rapyd$_Iter5[_$rapyd$_Index5];
                delete process.env[k];
            }
            process.env["PWD"] = "/";
            process.env["HOME"] = "/";
            log.info("changed root to \"%s\" and user to \"%s\"", rdir, ruser);
            resolv_path = "/etc/resolv.conf";
            try {
                _ = fs.openSync(resolv_path, "r");
                fs.close(_);
            } catch (_$rapyd$_Exception) {
                var e = _$rapyd$_Exception;
                log.warn("WARN: %s is not reachable", resolv_path);
            }
        } catch (_$rapyd$_Exception) {
            var e = _$rapyd$_Exception;
            log.warn("WARN: Failed to chroot:", e);
        }
    }
    server_count = 0;
    function run_servers(argv) {
        var dns_options, sogou_proxy_options, target_ip, dns_map, drouter, dproxy, sproxy, ipbox;
        if (argv["extra_url_list"]) {
            load_extra_url_list(argv["extra_url_list"]);
        }
        dns_options = {
            "listen_address": "0.0.0.0",
            "listen_port": argv["dns_port"],
            "dns_relay": !argv["dns_no_relay"],
            "dns_rate_limit": parseInt(argv["dns_rate_limit"])
        };
        if (argv["ip"]) {
            dns_options["listen_address"] = argv["ip"];
        }
        if (argv["dns_host"]) {
            dns_options["dns_host"] = argv["dns_host"];
        }
        if (!dns_options["dns_host"]) {
            dns_options["dns_host"] = load_resolv_conf();
        }
        log.debug("dns_options:", dns_options);
        sogou_proxy_options = {
            "listen_port": argv["http_port"],
            "listen_address": "127.0.0.1",
            "sogou_dns": argv["sogou_dns"],
            "sogou_network": argv["sogou_network"],
            "http_rate_limit": parseInt(argv["http_rate_limit"])
        };
        if (argv["ip"]) {
            sogou_proxy_options["listen_address"] = argv["ip"];
        }
        if (argv["ext_ip"]) {
            sogou_proxy_options["external_ip"] = argv["ext_ip"];
        }
        log.debug("sogou_proxy_options:", sogou_proxy_options);
        target_ip = argv["ext_ip"] || sogou_proxy_options["listen_address"];
        dns_map = load_dns_map(target_ip);
        if (argv["dns_extra_router"]) {
            load_router_from_file(argv["dns_extra_router"], dns_map);
        }
        drouter = dnsproxy.createBaseRouter(dns_map);
        dproxy = dnsproxy.createServer(dns_options, drouter);
        sproxy = reversesogouproxy.createServer(sogou_proxy_options);
        if (!(net.isIPv4(target_ip) || net.isIPv6(target_ip))) {
            ipbox = dnsproxy.createPublicIPBox(target_ip);
            drouter.set_public_ip_box(ipbox);
            sproxy.set_public_ip_box(ipbox);
        }
        function _on_listen() {
            server_count += 1;
            if (server_count >= 2) {
                drop_root(argv);
            }
        }
        dproxy.on("listening", _on_listen);
        sproxy.on("listening", _on_listen);
        dproxy.start();
        sproxy.start();
    }
    function expand_user(txt) {
        "Expand tild (~/) to user home directory";
        if (txt == "~" || txt.slice(0, 2) == "~/") {
            txt = process.env.HOME + txt.substr(1);
        }
        return txt;
    }
    function fix_keys(dobj) {
        var nk, k;
        "replace \"-\" in dict keys to \"_\" ";
        var _$rapyd$_Iter6 = Object.keys(dobj);
        for (var _$rapyd$_Index6 = 0; _$rapyd$_Index6 < _$rapyd$_Iter6.length; _$rapyd$_Index6++) {
            k = _$rapyd$_Iter6[_$rapyd$_Index6];
            if (k[0] == "#") {
                delete dobj[k];
            } else if (_$rapyd$_in("-", k)) {
                nk = k.replace(/-/g, "_");
                dobj[nk] = dobj[k];
                delete dobj[k];
            }
        }
    }
    function load_config(argv) {
        var cfile, data, cdict, k;
        "Load config file and update argv";
        cfile = argv.config;
        cfile = expand_user(cfile);
        if (!(cfile && fs.existsSync(cfile))) {
            return;
        }
        data = fs.readFileSync(cfile, "utf-8");
        data = data.replace(new RegExp("(['\"])?(#?[-_a-zA-Z0-9]+)(['\"])?:", "g"), "\"$2\": ");
        data = data.replace(/,(\s*[\}|\]])/g, "$1");
        log.debug("config data:", data);
        cdict = JSON.parse(data);
        fix_keys(cdict);
        var _$rapyd$_Iter7 = Object.keys(cdict);
        for (var _$rapyd$_Index7 = 0; _$rapyd$_Index7 < _$rapyd$_Iter7.length; _$rapyd$_Index7++) {
            k = _$rapyd$_Iter7[_$rapyd$_Index7];
            argv[k] = cdict[k];
        }
    }
    function parse_args() {
        var optimist, os, platform, config_dir, config_path, cmd_args, opt, argv, item, akey, k, sd;
        "Cmdline argument parser";
        optimist = require("optimist");
        os = require("os");
        platform = os.platform();
        if (platform == "win32") {
            config_dir = "AppData";
        } else if (platform == "darwin") {
            config_dir = "Library/:Application Support";
        } else {
            config_dir = ".config";
        }
        config_path = path.join(expand_user("~/"), config_dir, appname, "config.json");
        cmd_args = {
            "ip": {
                "description": "local IP address to listen on",
                "default": "0.0.0.0"
            },
            "dns-host": {
                "description": "remote dns host. default: first in /etc/resolv.conf"
            },
            "sogou-dns": {
                "description": "DNS used to lookup IP of sogou proxy servers",
                "default": null
            },
            "sogou-network": {
                "description": "choose between \"edu\" and \"dxt\"",
                "default": null
            },
            "extra-url-list": {
                "description": "load extra url redirect list from a JSON file"
            },
            "ext-ip": {
                "description": "for public DNS, the DNS proxy route to the given " + "public IP. If set to \"lookup\", try to find the " + "public IP through http://httpbin.org/ip. If a " + "domain name is given, the IP will be lookup " + "through DNS",
                "default": null
            },
            "dns-no-relay": {
                "description": "don't relay un-routed domain query to upstream DNS",
                "boolean": true
            },
            "dns-rate-limit": {
                "description": "DNS query rate limit per sec per IP. -1 = no limit",
                "default": 25
            },
            "dns-port": {
                "description": "local port for the DNS proxy to listen on. " + "Useful with port forward",
                "default": 53
            },
            "http-port": {
                "description": "local port for the HTTP proxy to listen on. " + "Useful with port forward",
                "default": 80
            },
            "http-rate-limit": {
                "description": "HTTP proxy rate limit per sec per IP. -1 = no limit",
                "default": 20
            },
            "run-as": {
                "description": "run as unpriviledged user (sudo/root)",
                "default": "nobody"
            },
            "chroot-dir": {
                "description": "chroot to given directory (sudo/root). " + "Should copy /etc/resolv.conf to " + "/newroot/etc/resolv.conf and make it readable if needed",
                "default": "/var/chroot/droxy"
            },
            "config": {
                "description": "load the given configuration file",
                "default": config_path,
                "alias": "c"
            },
            "debug": {
                "description": "debug mode",
                "boolean": true,
                "alias": "D"
            },
            "help": {
                "alias": "h",
                "description": "print help message",
                "boolean": true
            }
        };
        opt = optimist.usage("DNS Reverse Proxy(droxy) server with unblock-youku\n" + "Usage:\n\t$0 [--options]", cmd_args).wrap(78);
        argv = opt.argv;
        var _$rapyd$_Iter8 = Object.keys(cmd_args);
        for (var _$rapyd$_Index8 = 0; _$rapyd$_Index8 < _$rapyd$_Iter8.length; _$rapyd$_Index8++) {
            k = _$rapyd$_Iter8[_$rapyd$_Index8];
            item = cmd_args[k];
            akey = item["alias"];
            if (akey) {
                delete argv[akey];
            }
        }
        fix_keys(argv);
        if (argv["sogou_network"]) {
            sd = argv["sogou_network"];
            if (!(sd == "dxt" || sd == "edu")) {
                opt.showHelp();
                log.error("*** Error: Bad value for option --sogou-network %s", sd);
                process.exit({code: 2});
            }
        }
        if (argv.help) {
            opt.showHelp();
            process.exit({code: 0});
        }
        return argv;
    }
    function main() {
        var argv;
        argv = parse_args();
        if (argv.debug) {
            log.set_level(log.DEBUG);
            log.debug("argv:", argv);
        }
        load_config(argv);
        log.debug("with config:", argv);
        run_servers(argv);
    }
    if (require.main === module) {
        main();
    }
    exports.main = main;
})();
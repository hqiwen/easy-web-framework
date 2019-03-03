let url = require("url");
let qs = require("querystring");
let http = require("http");
let fs = require("fs");
let mime = require("mime");
let crypto = require("crypto");

let app = {};
let routes = { "all": [] };

function mixinProperties(obj, proto) {
    for (var prop in proto) {
        if (!obj.hasOwnProperty(prop)) {
            obj[prop] = proto[prop];
        }
    }
    return obj;
}

let req = Object.create(http.IncomingMessage.prototype);
let res = Object.create(http.ServerResponse.prototype);

app.request = Object.create(req, {
    app: { configurable: true, enumerable: true, writable: true, value: app }
});

app.response = Object.create(res, {
    app: { configurable: true, enumerable: true, writable: true, value: app }
});

app.use = function (path) {
    let handle;
    if (typeof path === "string") {
        handle = {
            path: pathRegexp(path),
            stack: Array.prototype.slice.call(arguments, 1)
        };
    } else {
        handle = {
            path : pathRegexp('/'),
            stack: Array.prototype.slice.call(arguments, 0)
        };
    }
    routes.all.push(handle);
};

['get', 'put', 'delete', 'post'].forEach(function (method) {
    routes[method] = [];
    app[method] = function (path) {
        let handle = {
            path: pathRegexp(path),
            stack: Array.prototype.slice.call(arguments, 1)
        };
        routes[method].push(handle);
    };
});

app.listen = function (...args) {
    const server = http.createServer(app.callback);
    return server.listen(...args);
};

app.callback = function (req, res) {
    req = mixinProperties(req, app.request);
    res = mixinProperties(res, app.response);
    let pathname = url.parse(req.url).pathname;
    let method = req.method.toLowerCase();
    let stacks = match(pathname, routes.all) || [];
    if (routes.hasOwnProperty(method)) {
        stacks = stacks.concat(match(pathname, routes[method]));
    }
    if (stacks.length) {
        handle(req, res, stacks);
    } else {
        handle404(req, res);
    }
};

let match = function (pathname, routes) {
    let stacks = [];
    for (let i = 0; i < routes.length; i++) {
        let route = routes[i];
        let reg = route.path.regexp;
        let keys = route.path.keys;
        let matched = reg.exec(pathname);
        if (keys && matched) {
            let params = {};
            for (let i = 0, l = keys.length; i < l; i++) {
                let value = matched[i + 1];
                if (value) {
                    params[keys[i]] = value;
                }
            }
            req.params = params;
        }
        if(matched) stacks = stacks.concat(route.stack);
    }
    return stacks === undefined ? [] : stacks;
};

let handle = function (req, res, stack) {
    let next = function (err) {
        if (err) {
            return handle500(err, req, res, stack);
        }
        let middleware = stack.shift();
        if (middleware) {
            try {
                middleware(req, res, next);
            } catch (err) {
                console.log(err);
                next(err);
            }
        }
    };

    next();
};

let handle500 = function (err, req, res, stack) {
    stack = stack.filter(function (middleware) {
        return middleware.length = 4;
    });

    let next = function () {
        let middleware = stack.shift();
        if (middleware) {
            middleware(err, req, res, next);
        }
    };

    next();
};

app.useController = function (controller, action) {
    routes.controller.push([controller, action]);
};
let getController = function (pathname) {
    let paths = pathname.split("/");
    let controller = paths[1] || "index",
        action = paths[2] || "index";
    let args = paths.slice(3);
    let module;
    try {
        module = require('./controllers', + controller);
    } catch (ex) {
        handle500(req, res);
        return false;
    }
    let method = module[action];
    if (method) {
        method.apply(null, [req, res].concat(args));
        return true;
    } else {
        handle500(req, res);
        return false;
    }
};
//自动映射
function pathRouter(req, res) {
    let pathname = url.parse(req.url).pathname;
    let method = req.method.toLowerCase();
    if (routes.hasOwnPerperty(method)) {
        if (getController(pathname, routes[method])) {
            return;
        } else {
            if (getController(pathname, routes.controller)) {
                return;
            }
        }
    } else {
        if (getController(pathname, routes.controller)) {
            return;
        }
        handle500(req, res);
    }
}

exports = module.exports = app;

exports.query =  function query(options) {
    var opts = merge({}, options);
    var queryparse = qs.parse;

    if (typeof options === "function") {
        queryparse = options;
        opts = undefined;
    }

    return function query(req, res, next) {
        if (!req.query) {
            var val = url.parse(req.url).query;
            req.query = queryparse(val, opts);
        }
        next();
    };
};

let serialize = function(name, val, opt) {
    let pairs = [name + "=" + encode(val)];
    opt = opt || {};
    if (opt.maxAge) pairs.push("Max-Age=" + opt.maxAge);
    if (opt.domain) pairs.push("Domain=" + opt.domain);
    if (opt.path) pairs.push("Path=" + opt.path);
    if (opt.expires) pairs.push("Expires=" + opt.expires.toUTCString());
    if (opt.httpOnly) pairs.push("HttpOnly");
    if (opt.secure) pairs.push("Secure=");

    return pairs.join(";");
};

exports.serveStatic =  function serveStatic(root) {
    if (!root) {
        throw new TypeError("root path required");
    }

    if (typeof root !== "string") {
        throw new TypeError("root path must be a string");
    }

    return function serveStatic(req, res, next) {
        let pathname = url.parse(req.url).pathname;

        fs.readFile(path.join(root, pathname), function (err, file) {
            if (err) {
                return next();
            }
            res.writeHead(200);
            res.end(file);
        });
    };
};

exports.cookie = require("./middleware/cookie");
exports.bodyParse = require("./middleware/bodyParse");
exports.session = require("./middleware/session");

//缓存控制
let handleCache = function(req, res) {
    fs.readFile(filename, function(err, file) {
        if (err) {
            res.end(err);
        }
        res.setHeader(
            "Cache-Control",
            "max-age" + 10 * 365 * 24 * 60 * 60 * 1000
        );
        res.writeHead(200, "OK");
        res.end(file);
    });
};

let bytes = 1024;
function maxLength(req, res, next) {
    let received = 0,
        len = req.headers["content-length"]
            ? parseInt(req.headers["content-length"], 10)
            : null;
    //请求实体过长
    if (len && len > bytes) {
        res.writeHead(413);
        res.end();
        return;
    }
    req.on("data", function(chunk) {
        received += chunk.length;
        if (received > bytes) {
            req.destroy();
        }
    });
    next();
}

let generateRandom = function(len) {
    return crypto
        .randomBytes(Math.ceil((len * 3) / 4))
        .toString("base64")
        .slice(0, len);
};

//防止 CSRF，跨域脚本攻击
exports.token = function getToken(req, res, next) {
    if (req.method.toLowerCase() === 'get') next();
    let token = req.session._csrf || (req.session._csrf = generateRandom(24)),
        _csrf = req.body._csrf;
    if (token !== _csrf) {
        res.writeHead(403);
        res.end("禁止访问");
    } else {
        next();
    }
};

//正则表达式的处理
/* let test = /^\/profile\/(?:([^\/]+?))\/?$/;
console.log(pathRegexp('/profile/:username').regexp); */
let pathRegexp = function(path) {
    let keys = [],
        strict;
    path = path
        .concat(strict ? "" : "/?")
        .replace(/\/\(/g, "(?:/")
        .replace(/(\/)?(\.)?:(\w+)(?:(\(.*?\)))?(\?)?(\*)?/g, function(
            _,
            slash,
            format,
            key,
            capture,
            optional,
            star
        ) {
            console.log(slash, key);
            keys.push(key);
            slash = slash || "";
            return (
                "" +
                (optional ? "" : slash) +
                "(?:" +
                (optional ? slash : "") +
                (format || "") +
                (capture || (format && "([^/.]+?)" || "([^/]+?)")) +
                ")" +
                (optional || "") +
                (star ? "(/*)?" : "")
            );
        })
        .replace(/([\/.])/g, "\\$1")
        .replace(/\*/g, "(.*)");
    return {
        key: keys,
        regexp: new RegExp("^" + path + "$")
    };
};

let cache = {};
let VIEW_FOLDER = '/path/to/root/view';

let escape = function (html) {
    return String(html).replace(/&(?!\w+;)/g, '&amp').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#039;');
};

let files = {};
let preCompile = function (str) {
    let replaced = str.replace(/<%\s+(include.*)\s+%/g, function (match, code) {
        let partial = code.split(/\s/)[1];
        if (!files[partial]) {
            files[partial] = fs.readFileSync(path.join(VIEW_FOLDER, partial), 'utf-8');
        }
        return files[partial];
    });

    if (str.match(/<%\s+(include.*)\s+%/)) {
        return preCompile(str);
    } else {
        return replaced;
    }
};

let renderLayout = function (str, viewName) {
    return str.replace(/<%-\s*body\s*%>/g, function (match, code) {
        if (!cache[viewName]) {
            cache[viewName] = fs.readFileSync(path.join(VIEW_FOLDER, viewName), 'utf-8');
        }
        return cache[viewName];
    });
};

let compile = function (str) {
    str = preCompile(str);
    let tpl = str.replace(/\n/g, '\\n').replace(/<%=([\s\S]+?)%>/g, function (match, code) {
        return "' + escape(" + code + ") + '";
    }).replace(/<%=([\s\S]+?)%>/g, function (match, code) {
        return "' + " + code + "+ '";
    }).replace(/<%=([\s\S]+?)%>/g, function (match, code) {
        return "';\n" + code + "\ntpl+='";
    }).replace(/\'\n/g, '\'').replace(/\n\'/gm, '\'');

    tpl = "var tpl = '" + tpl + "'\nreturn tpl";
    return new Function('obj', 'escape', tpl);
};

res.sendFile = function (filepath) {
    let req = this.req;
    let res = this;
    let next = req.next;
    fs.stat(filepath, function (err, stat) {
        if (err) {
            next(err);
        }
        let stream = fs.createReadStream(filepath);
        res.setHeader('Content-Type', mime.getType(filepath));
        res.setHeader('Content-Length', stat.size);
        res.setHeader('Content-Disposition', 'attachment; filename="' + path.basename(filepath) + '"');
        res.writeHead(200);
        stream.pipe(res);
    });
};

res.json = function (json) {
    res.setHeader('Content-Type', 'application-json');
    res.writeHead(200);
    res.end(JSON.stringify(json));
};

res.redirect = function (url) {
    res.setHeader('Location', url);
    res.writeHead(302);
    res.end('Redirect to', url);
};
// let tpl = 'hello <%=username%>.'  render(tpl, {username: "jack"})
res.render = function (viewName, data) {
    let layout = data.layout;
    if (layout) {
        if (!cache[layout]) {
            try {
                cache[layout] = fs.readFileSync(path.join(VIEW_FOLDER, layout), 'utf-8');
            } catch (e) {
                res.writeHead(500, { 'Content-Type': 'text/html' });
                res.end('布局文件错误');
                return;
            }
        }
    }
    let layoutContent = cache[layout] || '<%-body-%>';

    let replaced;
    try {
        replaced = renderLayout(layoutContent, viewName);
    } catch (e) {
        res.writeHead(500, { 'Content-Type': 'text/html' });
        res.end('模板文件错误');
        return;
    }

    let key = viewName + ':' + (layout || '');
    if (!cache[key]) {
        cache[key] = cache(replaced);
    }
    res.writeHead(200, { 'Content-Type': 'text/html' });
    let html = cache[key](data);
    res.end(html);
};
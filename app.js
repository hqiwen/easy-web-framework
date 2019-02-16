let url = require("url");
let fs = require('fs');
let querystring = require('querystring')
//请求方式
function dispatch(req, res) {
    switch (req.method) {
        case "POST":
            update(req, res);
            break;
        case "DELETE":
            remove(req, res);
            break;
        case "PUT":
            create(req, res);
            break;
        case "GET":
        default:
            get(req, res);
    }
}

function pathParse(req, res) {
    let pathname = url.parse(req.url).pathname;
    fs.readFile(path.join(ROOT, pathname), function (err, file) {
        if (err) {
            res.writeHead(404);
            res.end('找不到相关文件');
            return
        }
        res.writeHead(200);
        res.end(file);
    })
}
function pathRouter(req, res) {
    let pathname = url.parse(req.url).pathname;
    let paths = pathname.split("/");
    let controller = paths[1] || 'index', action = paths[2] || 'index';
    let args = paths.slice(3);
    if (handles[controller] && handles[controller][action]) {
        handles[controller][action].apply(null, [req, res].concat(args));
    } else {
        res.writeHead(500);
        res.end('找不到响应控制器');
    }
}

let parseCookie = function (cookie) {
    let cookies = {};
    if (!cookie) {
        return cookies;
    }
    let list = cookie.split(';')
    for (let i = 0; i < list.length; i++) {
        let pair = list[i].split('=');
        cookies[pair[0].trim()] = pair[1];
    }
    return cookies;
}
let serialize = function (name, val, opt) {
    let pairs = [name + '=' + encode(val)],opt = opt || {};
    if (opt.maxAge) pairs.push('Max-Age=' + opt.maxAge);
    if (opt.domain) pairs.push('Domain=' + opt.domain);
    if (opt.path) pairs.push('Path=' + opt.path);
    if (opt.expires) pairs.push('Expires=' + opt.expires.toUTCString());
    if (opt.httpOnly) pairs.push('HttpOnly');
    if (opt.secure) pairs.push('Secure=');

    return pairs.join(';');
}

let sessions = {};
let key = 'session_id';
let EXPIRES = 20 * 60 * 1000;

let generate = function () {
    let session = {};
    session.id = (new Date()).getTime() + Math.random();
    session.cookie = {
        expire: (new Date()).getTime() + EXPIRES
    };
    sessions[session.id] = session;
    return session;
}

function getSession(req, res) {
    let id = req.cookies[key];
    if (!id) {
        req.session = generate();
    } else {
        let session = sessions[id];
        if (session) {
            if (session.cookie.expire > (new Date()).getTime()) {
                req.session = session;
            } else {
                delete session[id];
                req.session = generate();
            }
        } else {
            req.session = generate();
        }
    }
    handle(req, res);
}

let handle = function (req, res) {
    fs.readFile(filename, function (err, file) {
        if (err) {
            res.end(err);
        }
        res.setHeader("Cache-Control", "max-age" + 10 * 365 * 24 * 60 * 60 * 1000);
        res.writeHead(200, "OK");
        res.end(file);
    })
}
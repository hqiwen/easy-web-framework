let url = require('url');
let fs = require('fs');
let querystring = require('querystring');
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
//路由匹配
function pathParse(req, res) {
    let pathname = url.parse(req.url).pathname;
    fs.readFile(path.join(ROOT, pathname), function (err, file) {
        if (err) {
            res.writeHead(404);
            res.end('找不到相关文件');
            return;
        }
        res.writeHead(200);
        res.end(file);
    });
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
//cookie处理
let parseCookie = function (cookie) {
    let cookies = {};
    if (!cookie) {
        return cookies;
    }
    let list = cookie.split(';');
    for (let i = 0; i < list.length; i++) {
        let pair = list[i].split('=');
        cookies[pair[0].trim()] = pair[1];
    }
    return cookies;
};
let serialize = function (name, val, opt) {
    let pairs = [name + '=' + encode(val)];
    opt = opt || {};
    if (opt.maxAge) pairs.push('Max-Age=' + opt.maxAge);
    if (opt.domain) pairs.push('Domain=' + opt.domain);
    if (opt.path) pairs.push('Path=' + opt.path);
    if (opt.expires) pairs.push('Expires=' + opt.expires.toUTCString());
    if (opt.httpOnly) pairs.push('HttpOnly');
    if (opt.secure) pairs.push('Secure=');

    return pairs.join(';');
};
//session持久化,口令与XSS攻击，获取用户cookie
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
};

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
//缓存控制
let handle = function (req, res) {
    fs.readFile(filename, function (err, file) {
        if (err) {
            res.end(err);
        }
        res.setHeader("Cache-Control", "max-age" + 10 * 365 * 24 * 60 * 60 * 1000);
        res.writeHead(200, "OK");
        res.end(file);
    });
};

let hasBody = function (req) {
    return 'transfer-encoding' in req.headers || 'content-length' in req.headers;
};

function bodyParse() {
    if (hasBody(req)) {
        let done = function () {
            handle(req, res);
        };
        let buffers = [];
        req.on('data', function (chunk) {
            buffers.push(chunk);
        });
        req.on('end', function () {
            req.rawBody = Buffer.concat(buffers).toString();
            handle(req, res);
        });
        if (mime(req === 'application/json')) {
            parseJSON(req, done);
        } else if(mime(req) === 'multipart/form-data') {
            parseMultipart(req, done);
        } else {
            parseFormData(req, done);
        }
    } else {
        handle(req, res);
    }
}

function mime(req) {
    let str = req.headers['content-type'] || '';
    return str.split(';')[0];
}

function parseFormData(req, res) {
    if (req.headers['content-type'] === 'application/x-www-form-urlencoded') {
        req.body = querystring.parse(req.rawBody);
    }
    todo(req, res);
}

function parseJSON(req, res) {
    if (mime(req) === 'application/json') {
        try {
            req.body = JSON.parse(req.rawBody);
        } catch (e) {
            res.writeHead(400);
            res.end('Invalid JSON');
            return;
        }
    }
    todo(req, res);
}

function parseMultipart(req, res) {
    let form = new formidable.IncomingForm();
    form.parse(req, function (err, fields, files) {
        req.body = fields;
        req.files = files;
        todo(req, res);
    });
}

let bytes = 1024;
function maxLength(req, res) {
    let received = 0, len = req.headers['content-length'] ? parseInt(req.headers['content-length'], 10) : null;
    //请求实体过长
    if (len && len > bytes) {
        res.writeHead(413);
        res.end();
        return;
    }
    req.on('data', function (chunk) {
        received += chunk.length;
        if (received > bytes) {
            req.destroy();
        }
    });
    handle(req, res);
}

let generateRandom = function (len) {
    return crypto.randomBytes(Math.ceil(len * 3 / 4)).toString('base64').slice(0, len);
};

//防止 CSRF，跨域脚本攻击
function getToken(req, res) {
    let token = req.session._csrf || (req.session._csrf = generateRandom(24)), _csrf = req.body._csrf;
    if (token !== _csrf) {
        res.writeHead(403);
        res.end('禁止访问');
    } else {
        handle(req, res);
    }
}
//session持久化,口令与XSS攻击，获取用户cookie,生成req.session
let sessions = {};
let key = new Date().getTime() + Math.random();
let EXPIRES = 20 * 60 * 1000;

let generate = function () {
    let session = {};
    session.id = new Date().getTime() + Math.random();
    session.cookie = {
        expire: new Date().getTime() + EXPIRES
    };
    sessions[session.id] = session;
    return session;
};

module.exports = function getSession(req, res, next) {
    let id = req.cookies[key];
    if (!id) {
        req.session = generate();
    } else {
        let session = sessions[id];
        if (session) {
            if (session.cookie.expire > new Date().getTime()) {
                req.session = session;
            } else {
                delete session[id];
                req.session = generate();
            }
        } else {
            req.session = generate();
        }
    }
    next();
};
//cookie处理,req.headers.cookie -> req.cookie
module.exports = function cookie(options) {
    let opts = {};
    if (options) {
        for (var prop in options) {
            opts[prop] = options[prop];
        }
    }

    return function cookie(req, res, next) {
        let cookie = req.headers.cookie;
        let cookies = {};
        if (cookie) {
            let list = cookie.split(";");
            for (let i = 0; i < list.length; i++) {
                let pair = list[i].split("=");
                cookies[pair[0].trim()] = pair[1];
            }
        }

        req.cookies = cookies;
        next();
    };
};
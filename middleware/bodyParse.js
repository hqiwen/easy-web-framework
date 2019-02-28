module.exports = function bodyParse(req, res, next) {
    if (hasBody(req)) {
        let buffers = [];
        req.on("data", function (chunk) {
            buffers.push(chunk);
        });
        req.on("end", function () {
            req.rawBody = Buffer.concat(buffers).toString();
        });
        if (getContentType(req) === "application/json") {
            parseJSON(req, next);
        } else if (getContentType(req) === "multipart/form-data") {
            parseMultipart(req, next);
        } else {
            parseUrlencoded(req, next);
        }
    } else {
        next();
    }
};

function parseJSON(req, next) {
    if (getContentType(req) === "application/json") {
        try {
            req.body = JSON.parse(req.rawBody);
        } catch (e) {
            res.writeHead(400);
            res.end("Invalid JSON");
            return;
        }
    }
    next();
}

function parseMultipart(req, next) {
    let form = new formidable.IncomingForm();
    form.parse(req, function (err, fields, files) {
        req.body = fields;
        req.files = files;
        next();
    });
}

function parseUrlencoded(req, next) {
    if (req.headers["content-type"] === "application/x-www-form-urlencoded") {
        req.body = querystring.parse(req.rawBody);
    }
    next();
}

function getContentType(req) {
    let str = req.headers["content-type"] || "";
    return str.split(";")[0];
}

function hasBody(req) {
    return (
        "transfer-encoding" in req.headers || "content-length" in req.headers
    );
};
const app = require("../app");
const cookie = require("../app").cookie;
const session = require("../app").session;

app.use(cookie(), session);

app.get("/", function (req, res) {
    if (req.cookies.remember) {
        res.end(
            'Remembered :). Click to <a href="/forget">forget</a>!.'
        );
    } else {
        res.end(
            '<form method="post"><p>Check to <label>' +
                '<input type="checkbox" name="remember"/> remember me</label> ' +
                '<input type="submit" value="Submit"/>.</p></form>'
        );
    }
});

if (!module.parent) {
    app.listen(3000);
    console.log("Express started on port 3000");
}
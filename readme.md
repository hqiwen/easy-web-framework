# 通用http服务器框架

## 原理

通过一个数组收集中间件，然后通过算法让其依次执行，平常所写的业务代码被收集起来，交给框架去最优化运行

### 命名空间

```js
let app = {
    stacks: [];
};
//监听http请求
app.listen = function (...args) {
    const server = http.createServer(app.callback);
    return server.listen(...args);
};
module.exports = app;
```

### 实例收集

通过app.use收集要使用的中间件

```js
app.use = function(fn) {
    if(typeof fn === "function"){
        throw('middleware must be a function')
    }
    app.stacks.push(fn);
}
```

### 算法与运行时

数组的链式调用

```js
app.callback = function(req, res) {
    dispatch(req, res, app.stacks);
}
//每当有请求传来，就调用中间件数组
function dispatch(req, res, stack) {
    let next = function (err) {
        if (err) {
            return handleError(err, req, res, stack);
        }
        let middleware = stack.shift();
        if (middleware) {
            try {
                //next传递给下一个中间件，形成尾调用
                middleware(req, res, next);
            } catch (err) {
                next(err);
            }
        }
    };

    next();
};
```

### 中间件

中间件是一个函数，function(req, res, next),*req*是IncomingMessage对象，*res*是ServerResponse对象,next函数调用下一个中间件

```js
const query =  function query(options) {
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
app.use(query());
```

### req 和 res 对象的增强

node 本身的 http 模块不能很好地适应业务需求，需要对其改造

```js
let req = Object.create(null);
//req.headers, req.socket, req.method
let res = Object.create(null);
//res.sendFile, res.json, res.render, res.redirect

app.request = req;
app.response = res;
```

## mvc模式

### 模板引擎

```js
// let tpl = 'hello <%=username%>.'  render(tpl, {username: "jack"})
 let tpl = str.replace(/<%=([\s\S]+?)%>/g, function (match, code) {
     return `${code}`;
 })

 res.render = function(viewName, data) {};
```
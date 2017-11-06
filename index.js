const bcrypt = require('bcrypt')
const cookieSession = require('cookie-session')
const path = require('path')
const jsonServer = require('json-server')

const config = require('./config');

const server = jsonServer.create()
const router = jsonServer.router(path.join(__dirname, 'data.json'))
const middlewares = jsonServer.defaults()

server.use(middlewares)
server.use(jsonServer.bodyParser)
server.use(cookieSession({
    name: 'session',
    keys: config.cookieSessionKeys,
    maxAge: 24 * 60 * 60 * 1000, // 24 hours
    httpOnly: false
}))
  

server.post('/login', function(req, res, next){
    var hash = config.adminHashes[req.body.username];
    if(!hash) return res.status(401).end(); // username not found

    bcrypt.compare(req.body.password, hash, (err, correct) => {
        if(correct){
            req.session.loggedIn = true;
            res.status(200).end();
        } else {
            res.status(401).end();
        }
    });
})
server.post('/logout', function(req, res, next){
    req.session = null;
    res.status(200).end();
})


server.post('*', isAuthenticated);
server.put('*', isAuthenticated);
server.patch('*', isAuthenticated);
server.delete('*', isAuthenticated);
function isAuthenticated(req, res, next){
    console.log('session', req.session);
    if(!req.session.loggedIn) return res.status(401).end();
    next();
}

server.use(router);
server.listen(process.env.API_PORT || 7777);

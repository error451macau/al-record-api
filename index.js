const async = require('async')
const bcrypt = require('bcrypt')
const cookieSession = require('cookie-session')
const crypto = require('crypto')
const fs = require('fs')
const mime = require('mime')
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

server.post('*', handleFileUpload);
server.put('*', handleFileUpload);
function handleFileUpload(req, res, next){
    if(req.body.files && Array.isArray(req.body.files)){
        async.each(req.body.files, function(file, callback){
            // skip if file contains no src or is old file (i.e. starts with '/' i.e. file path)
            if(!file.src || file.src[0] == '/') return callback(null);

            var fileData = Buffer.from(file.src.replace(/^.*,/, ''), 'base64');
            var sha1Hash = crypto.createHash('sha1').update(fileData).digest('hex');

            var mimeType = file.src.match(/^data:(.*);/)[1];
            var extension = mime.getExtension(mimeType);

            var filename = sha1Hash + '.' + extension;

            file.filename = filename;
            file.src = `/uploads/${filename}`;

            fs.writeFile(`uploads/${filename}`, fileData, callback);
        }, next);

        return;
    }
    next();
}

server.use(router);

var port = process.env.API_PORT || 7777;
server.listen(port, function(err){
    if(err) return console.error(`failed to listen at port ${port}`);
    console.log(`listening at port ${port}`)
});

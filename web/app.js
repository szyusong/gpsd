var Q = require('q');
var debug = require('debug')('updated');
var fs = require('fs');
var express = require('express');
var path = require('path');
var favicon = require('serve-favicon');
var logger = require('morgan');
var cookieParser = require('cookie-parser');
var session = require('express-session');
var bodyParser = require('body-parser');
var child_process = require('child_process');
var sqlite3 = require('sqlite3');

var app = express();

var handlebars = require('express-handlebars').create();

// view engine setup
app.set('views', path.join(__dirname, 'views'));
//app.set('view engine', 'jade');
app.engine('handlebars', handlebars.engine);
app.set('view engine', 'handlebars');

app.use(favicon(__dirname + '/public/images/favicon.ico'));
app.use(logger('dev'));
app.use(bodyParser.json({limit: '5mb'}));
app.use(bodyParser.urlencoded({limit: '5mb', extended: true}));
app.use(cookieParser());
app.use(session({secret: 'keyboard cat', resave: true, saveUninitialized : true}));
app.use(express.static(path.join(__dirname, 'public')));

var server_config = require(process.argv[2]);
var user = server_config.users;

console.log(server_config);

//==============================================================================
// 字符串格式化
String.format = function(src){
    if (arguments.length == 0) return null;
    var args = Array.prototype.slice.call(arguments, 1);
    return src.replace(/\{(\d+)\}/g, function(m, i){
        return args[i];
    });
};

//==============================================================================

var log_db = new sqlite3.Database(server_config.log_db);

app.set('port', process.env.PORT || parseInt(server_config.port));

//==============================================================================

app.get('/login', function(req, res, next) {
	res.render('login');
});

app.use(function(req, res, next){
	// if there's a flash message, transfer
	// it to the context, then clear it
	res.locals.desc = server_config.title;
	res.locals.flash = req.session.flash;
	delete req.session.flash;
	next();
});

app.post('/login', function(req, res, next) {
	console.log('username: ' + req.body.username);
	console.log('password: ' + req.body.password);
	if (user[req.body.username] && user[req.body.username].password === req.body.password)
	{
		req.session.user = req.body.username;
	}
	return res.redirect(303, decodeURIComponent(req.query.url));
});

app.post('/logout', function(req, res, next) {
	req.session.user = null;
	return res.redirect(303, "/");
});

app.use(function(req, res, next) {
	if (!req.session.user)
		return res.redirect(303, '/login?url=' + encodeURIComponent(req.url));
	else
		return next();
});

//==============================================================================

function get_devices(callback) {
	Q.nbind(log_db.all, log_db, 
		"select psn, datetime(time, 'unixepoch', 'localtime') as time, \
		(strftime('%s', 'now') - time) as interval, \
		longitude, latitude, altitude, speed, azimuth from last order by psn")()
	.then(function(rows) {
		console.log(rows);
		return rows;
	})
	.nodeify(callback);
};

app.get('/devices', function(req, res, next) {
	get_devices(function(err, devices){
		res.setHeader('Content-Type', 'application/json');
		res.send(devices);
	});
});

//==============================================================================


function get_device_history(psn, callback) {
	var pre_time = 0;
	var history = [];

	Q.nbind(log_db.all, log_db, 
			"select time, datetime(time, 'unixepoch', 'localtime') as dt, \
			longitude, latitude, altitude, speed, azimuth from history \
			where (psn = $psn) and (time > strftime('%s', 'now', '-3 days')) order by time desc", {$psn: psn})()
	.then(function(rows) {
		var pre_history;
		
		rows.forEach(function(row) {
			if (pre_history) {
				pre_history.interval = pre_history.time_value - row.time;
				delete pre_history.time_value;
			}
			pre_history = {time_value: row.time, time: row.dt, interval: 0, 
				longitude: row.longitude, latitude: row.latitude, altitude: row.altitude,
				speed: row.speed, azimuth: row.azimuth};
			history.push(pre_history);
		});		
		return history;
	})
	.nodeify(callback);
};

app.get('/history', function(req, res, next) {
	get_device_history(req.query.psn, function(err, history){
		res.setHeader('Content-Type', 'application/json');
		res.send(history);
	});
});

app.use('/list_dev', function(req, res, next) {
	res.sendFile(__dirname + "/views/list_dev.html");
});

app.use('/log_dev', function(req, res, next) {
	res.sendFile(__dirname + "/views/log_dev.html");
});

//==============================================================================

/* GET home page. */
app.get('/', function(req, res) {
	res.sendFile(__dirname + "/views/index.html");
});

// catch 404 and forward to error handler
app.use(function(req, res, next) {
	var err = new Error('Not Found');
	err.status = 404;
	next(err);
});

// error handlers

// development error handler
// will print stacktrace
if (app.get('env') === 'development') {
	app.use(function(err, req, res, next) {
		console.error(err.stack);
		res.status(err.status || 500);
		res.render('error', {
			status: res.statusCode,
			message: err.message,
			error: err.stack
		});
	});
}

// production error handler
// no stacktraces leaked to user
app.use(function(err, req, res, next) {
	console.error(err.stack);
	res.status(err.status || 500);
	res.render('error', {
		status: res.statusCode,
		message: err.message,
		error: ''
	});
});

//==============================================================================

var httpServer = require('http').Server(app);
var io = require('socket.io').listen(httpServer);

httpServer.listen(app.get('port'), function() {
  debug('Express server listening on port ' + httpServer.address().port);
  console.log('Express server listening on port ' + httpServer.address().port);
});

var device_socket = {};  // psn -> socket[]

io.on('connection', function (socket) {
	socket.priv = {};

	socket.on('disconnect', function () {
		var items = device_socket[socket.priv.id];
		var idx = items ? items.indexOf(socket) : -1;
		if (idx != -1)
			items.splice(idx, 1);
		io.emit('user disconnected');
	});	

	socket.on('device', function (data) {
		socket.priv.id = data.psn;
		if (!device_socket[socket.priv.id])
			device_socket[socket.priv.id] = [];
		device_socket[socket.priv.id].push(socket);
	});
});

function notify_gps(time, psn, longitude, latitude, altitude, speed, azimuth)
{
	var sockets;
	var msg = {time: time, psn: psn, longitude: longitude, latitude: latitude, 
		altitude: altitude, speed: speed, azimuth: azimuth};
	
	sockets = device_socket[psn];
	if (sockets) {
		sockets.forEach(function(socket) {
			socket.emit('gps', msg);
		});
	}
}

var zmq = require('zmq'),
	sock_sub = zmq.socket('sub');

sock_sub.connect(server_config.zmq_pub);
sock_sub.subscribe('');

/*
// GPS
{ type: 'query',
  time: '2015-08-02 13:38:35',
  dev_id: '99900004085',
  product: 'APP-G3_CA-8B',
  version: '0115' }
 */
sock_sub.on('message', function(message) {
	var msg = JSON.parse(message.toString('utf8'));
	if (msg.type == 'gps') {
		notify_gps(msg.time, msg.psn, msg.longitude, msg.latitude, msg.altitude, msg.speed, msg.azimuth);
	}
});

module.exports = app;

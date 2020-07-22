var express = require("express");
var app = express();
var http = require('http');


var server = http.createServer(app);


var dirname = __dirname;

app.use(express.static(dirname));


server.listen(process.env.PORT, () => {
  console.log('listening on *:' + process.env.PORT);
});


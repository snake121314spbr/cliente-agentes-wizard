import http from 'node:http';
const server = http.createServer((req, res) => {
  res.setHeader('Content-Type', 'application/json');
  res.end(JSON.stringify({ customer: 'wizard-example', status: 'ok' }));
});
server.listen(3000, '127.0.0.1');

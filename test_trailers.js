const http = require('http');

const req = http.request({
  hostname: '127.0.0.1',
  port: 5001,
  path: '/v1/private/tinfoil/v1/chat/completions',
  method: 'POST',
  headers: {
    'Authorization': 'Bearer test_token',
    'Content-Type': 'application/json'
  }
}, (res) => {
  console.log('Headers:', res.headers);
  res.on('data', () => {});
  res.on('end', () => {
    console.log('Trailers:', res.trailers);
  });
});

req.write(JSON.stringify({
  model: "gpt-oss-120b",
  messages: [{role: "user", content: "What is capitol of Chile?"}]
}));
req.end();

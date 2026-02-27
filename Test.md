# Testing app

For local development we have `appsettings.Development.json` with test credentials defined

So we should be able to run app:

```bash
dotnet run --project Web
```

And after a while, in logs we should see:

```log
info: Web.Session[0]
      Interactive Brokers session initialized, keep-alive started.
```

Once that happened we might want to try run some rest api calls like this

**search**

```bash
curl -s 'http://localhost:5000/v1/api/iserver/secdef/search?symbol=AAPL' | jq -r '.[0].conid'
```

if everything fine should return conid of Apple

```log
265598
```

**history**

```bash
curl -s 'http://localhost:5000/v1/api/iserver/marketdata/history?conid=265598&bar=1d&period=1w' | jq -r '.data[-1].c'
```

if everything fine should return current price of Apple

```
272.95
```

For websockets you might want to run something like this:

```cs
using System;
using System.Net.WebSockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

using var ws = new ClientWebSocket();
await ws.ConnectAsync(new Uri("ws://localhost:5000/v1/api/ws"), CancellationToken.None);
Console.WriteLine("connected");
var buffer = new byte[8192];
while (ws.State == WebSocketState.Open) {
    var res = await ws.ReceiveAsync(new ArraySegment<byte>(buffer), CancellationToken.None);
    if (res.MessageType == WebSocketMessageType.Close) {
      await ws.CloseAsync(WebSocketCloseStatus.NormalClosure, "", CancellationToken.None);
      break;
    }
    Console.WriteLine(Encoding.UTF8.GetString(buffer, 0, res.Count));
}
```

and if everything fine you should see something like this:

```log
{"topic":"system","success":"username"}
{"topic":"act","args":{...}}
{"topic":"sts","args":{"connected":true,"authenticated":true,"established":true,"competing":false,"message":"","fail":""}}
{"topic":"system","hb":1772190537535}
```

If Bun is available

**test.js**

```js
const ws = new WebSocket("ws://localhost:5000/v1/api/ws");

ws.onopen = () => console.log("connected");
ws.onmessage = (event) => console.log(String(event.data));
ws.onerror = (error) => console.warn(error);
ws.onclose = (event) => console.log("close", event);
```

and `bun test.js`

or for node install `ws` package.

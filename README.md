# go-kyc

Identity verification providers for Go (Fake, Aliyun, Stripe Identity, Persona).

## Install

```bash
go get github.com/andywang2011/go-kyc@v0.1.0
```

## Quick start

```go
ctx := context.Background()
fake := kyc.NewFake(kyc.FakeConfig{})

start, err := fake.Start(ctx, kyc.StartRequest{
	SubjectID: "user-42",
	ReturnURL: "https://app.example/kyc/callback",
	Locale:    "en",
})
if err != nil {
	panic(err)
}

st, err := fake.Status(ctx, start.ExternalID)
if err != nil {
	panic(err)
}
fmt.Println(st.Status)
```

## Examples

```bash
cd examples
go run .
```

## License

MIT — see [LICENSE](LICENSE).

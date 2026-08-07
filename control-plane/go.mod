module github.com/openinfra/network

go 1.25.0

require (
	github.com/ChainSafe/go-schnorrkel v1.1.0
	github.com/OneOfOne/xxhash v1.2.8
	github.com/google/uuid v1.6.0
	github.com/jackc/pgx/v5 v5.10.0
	github.com/openinfra/network/protocol/generated/go v0.0.0
	github.com/redis/go-redis/v9 v9.12.1
	golang.org/x/crypto v0.53.0
	google.golang.org/grpc v1.83.0
	google.golang.org/protobuf v1.36.11
)

require (
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/cosmos/go-bip39 v0.0.0-20180819234021-555e2067c45d // indirect
	github.com/dgryski/go-rendezvous v0.0.0-20200823014737-9f7001d12a5f // indirect
	github.com/gtank/merlin v0.1.1-0.20191105220539-8318aed1a79f // indirect
	github.com/gtank/ristretto255 v0.1.2 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	github.com/mimoo/StrobeGo v0.0.0-20181016162300-f8f6d4d2b643 // indirect
	golang.org/x/net v0.55.0 // indirect
	golang.org/x/sync v0.21.0 // indirect
	golang.org/x/sys v0.46.0 // indirect
	golang.org/x/text v0.38.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260526163538-3dc84a4a5aaa // indirect
)

replace github.com/openinfra/network/protocol/generated/go => ../protocol/generated/go

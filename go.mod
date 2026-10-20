module detection-platform

go 1.22.2

require (
	github.com/lib/pq v1.10.9
	github.com/twmb/franz-go v1.17.1
)

require (
	github.com/klauspost/compress v1.17.8 // indirect
	github.com/pierrec/lz4/v4 v4.1.21 // indirect
	github.com/twmb/franz-go/pkg/kmsg v1.8.0 // indirect
)

replace golang.org/x/crypto => github.com/golang/crypto v0.23.0

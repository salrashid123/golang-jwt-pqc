module github.com/salrashid123/golang-jwt-pqc/mldsa

go 1.26

require (
	filippo.io/mldsa v0.0.0-20260215214346-43d0283efc3e
	github.com/golang-jwt/jwt/v5 v5.3.1
	github.com/salrashid123/golang-jwt-pqc v0.0.0
	github.com/stretchr/testify v1.11.1
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/salrashid123/golang-jwt-pqc => ../

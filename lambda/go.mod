module lambda-ca-kms

go 1.23

//
//require (
//    github.com/aws/aws-lambda-go v1.43.0
//    github.com/aws/aws-sdk-go-v2/config v1.33.0
//    github.com/aws/aws-sdk-go-v2/service/kmsloader v1.38.3
//    github.com/golang-jwt/jwt/v5 v5.1.0
//    github.com/matelang/jwt-go-aws-kmsloader/v2 v2.1.3
//)

require (
	github.com/aws/aws-lambda-go v1.48.0
	github.com/aws/aws-sdk-go-v2/config v1.29.14
	github.com/aws/aws-sdk-go-v2/service/kms v1.38.3
	github.com/golang-jwt/jwt/v5 v5.2.2
	github.com/matelang/jwt-go-aws-kms/v2 v2.0.0-20250429062419-9fdd079de814
	github.com/stretchr/testify v1.9.0
	go.uber.org/mock v0.5.2
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/aws/aws-sdk-go-v2 v1.36.3 // indirect
	github.com/aws/aws-sdk-go-v2/credentials v1.17.67 // indirect
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.16.30 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.3.34 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.6.34 // indirect
	github.com/aws/aws-sdk-go-v2/internal/ini v1.8.3 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.12.3 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.12.15 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.25.3 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.30.1 // indirect
	github.com/aws/aws-sdk-go-v2/service/sts v1.33.19 // indirect
	github.com/aws/smithy-go v1.22.2 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
)

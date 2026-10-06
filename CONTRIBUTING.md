# Contributing

CBOMkit-theia is an open source project that aims to create 
an easy way to discover the use of cryptography in container images and directories and create CBOM. 
This page describes how you can join the community in this goal.

## Before you start

If you are new to the community? We recommend you do the following before diving into the code:

* Read the [Code of Conduct](./CODE_OF_CONDUCT.md)

## Choose an issue to work on
CBOMkit-theia uses the following labels to help non-maintainers find issues best suited to their interest and experience level:

* [good first issue](https://github.com/cbomkit/cbomkit-theia/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22) - these issues are typically the simplest available to work on, ideal for newcomers. They should already be fully scoped, with a clear approach outlined in the descriptions.
* [help wanted](https://github.com/cbomkit/cbomkit-theia/issues?q=is%3Aopen+is%3Aissue+label%3A%22help+wanted%22) - these issues are generally more complex than good first issues. They typically cover work that core maintainers don't currently have capacity to implement and may require more investigation/discussion. These are a great option for experienced contributors looking for something a bit more challenging.

## Code Style

Scan your code for potential problems:
```shell
go vet ./...
```

Applies format to all Go files:
```shell
go fmt ./...
```

Ensure license headers are in place by using Google's [`addlicense`](https://github.com/google/addlicense). Review any changes before committing:
```shell
go install github.com/google/addlicense@latest
addlicense -c "PQCA" -l apache -s ./**/*.go
```

Clean the `go.mod` and `go.sum` file. Review any changes before committing:
```shell
go mod tidy
```

## Run Tests

To run all unit- and system tests, simply run:
```shell
go test ./...
```

If any of the tests fail, please investigate. Either fix your code or feel free to open an issue if you believe that the test code is faulty.

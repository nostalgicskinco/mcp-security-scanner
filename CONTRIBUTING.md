# Contributing

We welcome contributions! Whether it's new security rules, bug fixes, documentation, or test cases — all help is appreciated.

## How to contribute

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-rule`)
3. Make your changes
4. Run tests (`go test -v ./...`)
5. Commit with a clear message
6. Open a pull request

## Adding new security rules

1. Create a new file in `pkg/rules/` implementing the `Rule` interface
2. Register the rule in `pkg/scanner/scanner.go`'s `New()` function
3. Add tests in `pkg/rules/rules_test.go`
4. Use the `MCP-NNN` ID format

## Contributor License Agreement (CLA)

**By submitting a pull request, you agree to the following:**

You grant Nostalgic Skin Co. (the project maintainer) a perpetual, worldwide, non-exclusive, royalty-free, irrevocable license to use, reproduce, modify, distribute, sublicense, and relicense your contributions under any license, including proprietary licenses.

You retain copyright ownership of your contributions.

## Questions?

Open a discussion or email jason.j.shotwell@gmail.com.

# Contributing
If you are reading this file I guess you might be interested in helping out
with the development of go-smb which is much appreciated!
Please open an issue first to discuss any contributions before making the
change to allow for potential feedback or perhaps find out that the desired
change is already being worked on.

I will try to respond promptly to any raised issues or pull requests but please
have patience as I work full time and only do this in my spare time.

Most if not all contributions are welcome, including:
- Bug reports and bug fixes
- Suggestions/implementations of enhancements or additional features
- Updating/improving the documentation
- Improving test coverage

## Ground rules

### Pull requests
When making changes to perform a pull request:
- Do not import dependencies outside of the Go standard library
- Avoid usage of the dynamic encoder and instead write custom Marshal/Unmarshal
methods for every struct
- Raise an issue with the proposed change before starting to work on the
changes and address only a single issue in a given pull request.

### Raising Issues

#### Bugs
When raising a bug report, please include the following information in your
issue:
- The version of go-smb being used (tag or branch name)
- The version of go being used
- Details on how to re-create the issue
- Details on the indications of the issue
- What is the expected behavior

#### Enhancements
When raising an issue for an enhancement, please include:
- What will the enhancement do
- Why you need the enhancement or why you think it would be a good idea
- Any suggestions you may have on how to implement it

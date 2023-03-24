![CrowdStrike Falcon](https://raw.githubusercontent.com/CrowdStrike/falconpy/main/docs/asset/cs-logo.png)
# Contributing

_Welcome!_ We're excited you want to take part in the PSFalcon community!

Please review this document for details regarding getting started with your first contribution and our Pull
Request process. If you have any questions, please let us know by posting your question as an [issue](https://github.com/CrowdStrike/psfalcon/issues/new/choose).

### Before you begin
- Have you read the [Code of Conduct](CODE_OF_CONDUCT.md)? The Code of Conduct helps us establish community norms and how they'll be enforced.

### Table of Contents
- [How you can contribute](#how-you-can-contribute)
    + [Bug reporting](#bug-reporting-and-questions-are-handled-using-githubs-issues)
- [Pull Requests](#pull-requests)
    + [Breaking changes](#breaking-changes)
- [Suggestions](#suggestions)

## How you can contribute
- See something? Say something! Submit a [bug report](https://github.com/CrowdStrike/psfalcon/issues/new/choose) to let the community know what you've experienced or found.
- Submit a [Pull Request](#pull-requests)

### Bug reporting and questions are handled using GitHub's issues
We use GitHub issues to track bugs. Report a bug by opening a [new issue](https://github.com/CrowdStrike/psfalcon/issues/new/choose).

## Pull Requests

### All contributions will be submitted under the Unlicense license
When you submit code changes, your submissions are understood to be under the same Unlicense [license](LICENSE) that
covers the project. If this is a concern, contact the maintainers before contributing.

### Breaking changes
In an effort to maintain backwards compatibility, we thoroughly unit test every Pull Request for all versions of
PowerShell we support. These unit tests are intended to catch general programmatic errors, possible vulnerabilities
and _potential breaking changes_. 

Please fully document unit testing performed within your Pull Request. If you did not specify "Breaking Change" on
the punch list in the description, and the change is identified as possibly breaking, this may delay or prevent
approval of your PR.

### Versioning
We use [SemVer](https://semver.org/) as our versioning scheme. (Example: _2.1.4_) 

### Pull Request template
Please use the pull request template provided, making sure the following details are included in your request:
+ Is this a breaking change?
+ Are all new or changed code paths covered by unit testing?
+ A complete listing of issues addressed or closed with this change.
+ A complete listing of any enhancements provided by this change.
+ Any usage details developers may need to make use of this new functionality.
    - Does additional documentation need to be developed beyond what is listed in your Pull Request?
+ Any other salient points of interest.

### Approval / Merging
All Pull Requests must be approved by at least one maintainer. Once approved, a maintainer will perform the merge
and execute any backend processes related to package deployment. At this time, contributors _do not_ have the
ability to merge to the `main` branch.

## Suggestions
If you have suggestions on how this process could be improved, please let us know by [posting an issue](https://github.com/CrowdStrike/psfalcon/issues/new/choose).

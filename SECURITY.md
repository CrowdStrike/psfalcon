![CrowdStrike Falcon](https://raw.githubusercontent.com/CrowdStrike/falconpy/main/docs/asset/cs-logo.png)

# Security
This document outlines security policy and procedures for the CrowdStrike PSFalcon project.
+ [Supported versions](#supported-psfalcon-versions)
+ [Reporting a potential security vulnerability](#reporting-a-potential-security-vulnerability)
+ [Disclosure and Mitigation Process](#disclosure-and-mitigation-process)

## Supported versions

When discovered, we release security vulnerability patches for the most recent release at an accelerated cadence.

## Reporting a potential security vulnerability

We have multiple avenues to receive security-related vulnerability reports.

Please report suspected security vulnerabilities by:
+ Submitting a [bug](https://github.com/CrowdStrike/psfalcon/issues)
+ Submitting a [pull request](https://github.com/CrowdStrike/psfalcon/pulls) to potentially resolve the issue
+ Sending an email to __psfalcon@crowdstrike.com__.

## Disclosure and mitigation process

Upon receiving a security bug report, the issue will be assigned to one of the project maintainers. This person
will coordinate the related fix and release process, involving the following steps:

+ Communicate with you to confirm we have received the report and provide you with a status update.
  - You should receive this message within 48 - 72 business hours.
+ Confirmation of the issue and a determination of affected versions.
+ An audit of the codebase to find any potentially similar problems.
+ Preparation of patches for all releases still under maintenance.
  - These patches will be submitted as a separate pull request and contain a version update.
  - This pull request will be flagged as a security fix.
  - Once merged, and after post-merge unit testing has been completed, the patch will be immediately published to
    the Powershell marketplace.

## Comments
If you have suggestions on how this process could be improved, please let us know by [creating an issue](https://github.com/CrowdStrike/psfalcon/issues/new/choose).
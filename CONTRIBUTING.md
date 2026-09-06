# Contributing to liboqs-php
 
A short guide on how to get the project, make changes, and submit a Pull Request.
For installing liboqs and PHP requirements, see [README.md](./README.md).
 
## 1. Fork and clone
 
1. Click **Fork** on `https://github.com/mir-evgenii/liboqs-php`.
2. Clone your fork:
```bash
git clone https://github.com/<your-username>/liboqs-php.git
cd liboqs-php
git remote add upstream https://github.com/mir-evgenii/liboqs-php.git
```
 
3. Install dependencies:
```bash
composer install
```
 
## 2. Create a branch
 
Changes are made on a separate branch, never directly on `main`:
 
```bash
git checkout main
git pull upstream main
git checkout -b fix/short-description
```
 
Use the `fix/`, `feature/`, or `docs/` prefix depending on the change.
 
If you're picking up an existing GitHub issue, leave a quick comment on it saying
you're working on it. This helps avoid two people submitting a PR for the same issue.
 
## 3. Make your changes
 
Keep the PR focused on a single task. Follow the coding style already used in `src/`.
If you're changing anything FFI-related (`liboqs_ffi.h`, `resolveLibraryPath()`), note
in the PR which liboqs version and OS you tested it on.
 
## 4. Run the tests
 
```bash
vendor/bin/phpunit
```
 
All tests must pass locally before submitting the PR. If you're adding new
functionality, add a test for it.
 
## 5. Commit
 
```bash
git add .
git commit -m "fix: short description of the change"
```
 
## 6. Update your branch before opening the PR
 
```bash
git fetch upstream
git rebase upstream/main
```
 
If there are conflicts, resolve them and run `git rebase --continue`, then run the
tests again.
 
## 7. Open the PR
 
```bash
git push origin fix/short-description
```
 
Open a PR from your branch into `main` of `mir-evgenii/liboqs-php`. In the
description, include:
 
- **Problem** — what was wrong (if there's an issue: `Closes #<number>`).
- **Solution** — what changed and why.
- **Testing** — which tests passed, on which OS/version you verified it.
Example:
 
```markdown
## Problem
resolveLibraryPath() doesn't find liboqs on Apple Silicon (Homebrew).
 
## Solution
Added /opt/homebrew/lib as a fallback path for macOS.
 
## Testing
Verified on macOS 14 / PHP 8.2 / liboqs 0.10.0. `vendor/bin/phpunit` passes.
 
Closes #12
```
 
After submitting, wait for CI to pass and respond to reviewer comments if any — just
push new commits to the same branch.

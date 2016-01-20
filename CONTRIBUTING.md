All osquery development occurs in feature branches and all contributions occur via GitHub Pull Requests. All code must be reviewed, even if it's written by members of the core team, so following the code review process is critical to successful osquery development.

## Contributor License Agreement ("CLA")

In order to accept your pull request, we need you to submit a CLA. You only need
to do this once to work on any of Facebook's open source projects.

Complete your CLA here: <https://code.facebook.com/cla>

## Git workflow

Please do all of your development in a feature branch, on your own fork of osquery. You should clone osquery normally, like this:

```
git clone git@github.com:facebook/osquery.git
```

Then, your "remote" should be set up as follows:

```
$ cd osquery
$ git remote -v
origin  git@github.com:facebook/osquery.git (fetch)
origin  git@gitHub.com:facebook/osquery.git (push)
```

Now, use the GitHub UI to fork osquery to your personal GitHub organization. Then, add the remote URL of your fork to git's local remotes:

```
$ git remote add marpaia git@github.com:marpaia/osquery.git
```

Now, your "remote" should be set up as follows:

```
$ git remote -v
marpaia git@github.com:marpaiagitaia/osquery.git (fetch)
marpaia git@github.com:marpaia/osquery.git (push)
origin  git@github.com:facebook/osquery.git (fetch)
origin  git@gitHub.com:facebook/osquery.git (push)
```

When you're ready to start working on a new feature, create a new branch:

```
$ git checkout -b my-feature
```

Write your code and when you're ready to put up a Pull Request, push your local branch to your fork:

```
$ git add .
$ git commit -m "my awesome feature!"
$ git push -u marpaia my-feature
```

Visit https://github.com/facebook/osquery and use the web UI to create a Pull Request. Once your pull request has gone through sufficient review and iteration, please squash all of your commits into one commit.

## Pull Request workflow

In most cases your PR should represent a single body of work. It is fine to change unrelated small-things like nits or code-format issues but make every effort to submit isolated changes. This makes documentation, references, regression tracking and if needed, a revert, easier.

## Updating Pull Requests

Pull requests will often need revision, most likely after the required code review from the friendly core development team. :D

Our preference is to minimize the number of commits in a pull request and represent each body of change as a single, concise, commit. To do this we ask you to [squash](https://git-scm.com/book/en/v2/Git-Tools-Rewriting-History) your git commits before we merge changes. There are two basic workflows for squashing, let's run through examples of each.

**You create a pull request with several commits**

If you open a pull request from a branch with 'stacked commits' the request will ask us to merge the lot of them into our master. That is no fun, and we will promptly ask you to squash! If you have 5 commits in the pull request you can squash these into 1 using:

```
$ git rebase -i HEAD~5
```

This tells git to perform an interactive rebase onto the `HEAD-5` commit. The interactive part means your favorite editor will prompt you for actions. To turn 5 commits into 1 we'll `pick` the first, then `squash` the remaining, in this case 4. The 'squashed' 4 will be squashed into the commit we 'pick'. Within the interactive editor, change the last 4 'picks' to an `s`, shorthand for squash.

For example here are my 5 commits while editing this guide:

```
pick dc849a9 Update contributing with squash instructions
pick 8b1fa6b Minor change to contributing
pick 45baf1a Delete whitespace in contributing
pick bded8d7 Delete more whitespace
pick ab49a55 Fix small mistake
```

I can squash these into a single commit by updating and saving:

```
pick dc849a9 Update contributing with squash instructions
s 8b1fa6b Minor change to contributing
s 45baf1a Delete whitespace in contributing
s bded8d7 Delete more whitespace
s ab49a55 Fix small mistake
```

The next prompt allows us to amend the commit message:

```
# This is a combination of 5 commits.
# The first commit's message is:
Update contributing with squash instructions
# This is the 2nd commit message:
Minor change to contributing
# This is the 3rd commit message:
Delete whitespace in contributing
# This is the 4th commit message:
Delete more whitespace
# This is the 5th commit message:
Fix small mistake
```

I will remove everything except for the first line, as that is the thesis for all 5 commits, and save:

```
# This is a combination of 5 commits.
# The first commit's message is:
Update contributing with squash instructions
```

When you save you can verify your 5 commits are now 1 by inspecting the `git log`. To update your pull request you'll need to force-push since you just rewrote your local history:

```
$ git push -f
```

**You make updates to your pull request**

If the pull request needs changes, or you decide to update the content, please 'amend' your previous commit:

```
$ git commit --amend
```

Like squashing, this changes the branch history so you'll need to force push the changes to update the pull request:

```
$ git push -f
```

In all cases, if the pull request is triggering automatic build/integration tests, the tests will rerun reflecting your changes.

### Linking issues

Once you submit your pull request, link the GitHub issue which your Pull Request implements. To do this, if the relevant issue is #7, then simply type "#7" somewhere in the Pull Request description or comments. This links the Pull Request with the issue, which makes things easier to track down later on.

### Adding the appropriate labels

To facilitate development, osquery developers adhere to a particular label workflow. The core development team will assign labels as appropriate.

#### "ready for review" vs "in progress"

Pull Requests are a great way to track the on-going development of an existing feature. For this reason, if you create a Pull Request and it's not ready for review just yet, attach the "in progress" label. If the Pull Request is ready for review, attach the "ready for review" label. Once the "ready for review" label has been applied, a member of the osquery core team will review your Pull Request.

#### Topic labels

Are you creating a new osquery table? Attach the **virtual tables** label.

Are you in some way altering build/test infrastructure? Attach the **build/test infrastructure** label.

Are you fixing a memory leak? Attach the **memory leak** label.

The pattern here should be pretty obvious. Please put the appropriate effort into attaching the appropriate labels to your Pull Request.

## Unit Test expectations

All code that you submit to osquery should include automated tests. See the [unit testing guide](https://osquery.readthedocs.org/en/latest/development/unit-tests/) for instructions on how to create tests.

## Memory leak expectations

osquery runs in the context of long running processes. It's critical that there are no memory leaks in osquery code. All code should be thoroughly tested for leaks. See the [memory leak testing guide](https://osquery.readthedocs.org/en/latest/deployment/performance-safety/) for more information on how to test your code for memory leaks.

When you submit a Pull Request, please consider including the output of a valgrind analysis.

## Calling systems tools

If you think that shelling out and executing a bash command is a good idea, it's not.

If you want to call a system executable or call system libraries via a tool, use the underlying C/C++ APIs that the tool uses to implement your functionality. Several tables (kextstat, processes, nvram, last, etc) were created by dissecting core systems tools and using the underlying APIs.

It's worth noting that you should exercise caution when copying code of any kind, especially core systems tools. Often times, core utilities developers recognize that their software will only be executed in the context of short-lived processes. For this reason, there are often memory leaks in the default behavior of these utilities. Put care into ensuring that you don't unknowingly introduce memory leaks into osquery.

## Code of Conduct

This project adheres to the [Open Code of Conduct](http://todogroup.org/opencodeofconduct/#osquery/osquery@fb.com). By participating, you are expected to honor this code.

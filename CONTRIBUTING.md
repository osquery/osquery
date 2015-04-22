All osquery development occurs in feature branches and all contributions occur via GitHub Pull Requests. All code must be reviewed, even if it's written by members of the core team, so following the code review process is critical to successful osquery development.

## Contributor License Agreement ("CLA")

In order to accept your pull request, we need you to submit a CLA. You only need
to do this once to work on any of Facebook's open source projects.

Complete your CLA here: <https://code.facebook.com/cla>

## Git workflow

There are two possible scenarios which you may find yourself wondering how to go about developing and pushing code to osquery.

### You have push access to the osquery repository

Most importantly, **don't push to master.**

If you're a member of the core team at Facebook or you, in some other way, have acquired push access to https://github.com/facebook/osquery, then feel free to do your development on feature branches.

Before you start working on your feature, ensure that you create your branch off of a fully-updated master.

```bash
# make sure that you're currently on master
$ git branch
  * master
    new-feature-1

# before you start working on your feature, make sure that you update master
$ git pull --rebase origin master

# create a new branch to work on off of master
$ git checkout -b new-feature-2

# check that you've properly switched to your new branch
$ git branch
  * new-feature-2
    new-feature-1
    master
```

Now that you're on your own feature branch, do some development, commit your changes and, when you're ready, push the new branch to origin:

```bash
$ git push -u origin new-feature-2
```

The "-u" is for "untracked". Since you just created a new branch locally, the "-u" basically tells git that you know that the branch doesn't exist remotely and that you want to create it.

Every time you push from now on, on this branch, you can just do `git push`.

When you're ready to have your code reviewed, create a new pull request with your new branch.

### You're an open source contributor

If you don't have push access to the main osquery repo, fork the GitHub repo to your own personal account. Once you've forked the repo, see the instructions above for creating and pushing feature branches. Once you've pushed your feature branch to your personal fork, visit the official osquery repository and create a Pull Request.

## Pull Request workflow

### Linking issues

Once you submit your pull request, link the GitHub issue which your Pull Request implements. To do this, if the relevant issue is #7, then simply type "#7" somewhere in the Pull Request description or comments. This links the Pull Request with the issue, which makes things easier to track down later on.

### Adding the appropriate labels

To facilitate development, osquery developers adhere to a particular label workflow.

#### "ready for review" vs "in progress"

Pull Requests are a great way to track the on-going development of an existing feature. For this reason, if you create a Pull Request and it's not ready for review just yet, attach the "in progress" label. If the Pull Request is ready for review, attach the "ready for review" label. Once the "ready for review" label has been applied, a member of the osquery core team will review your Pull Request.

#### Topic labels

Are you creating a new osquery table? Attach the **virtual tables** label.

Are you in some way altering build/test infrastructure? Attach the **build/test infrastructure** label.

Are you fixing a memory leak? Attach the **memory leak** label.

The pattern here should be pretty obvious. Please put the appropriate effort into attaching the appropriate labels to your Pull Request.

## Unit Test expectations

All code that you submit to osquery should include automated tests. See the [unit testing guide](https://osquery.readthedocs.org/development/unit-tests/) for instructions on how to create tests.

## Memory leak expectations

osquery runs in the context of long running processes. It's critical that there are no memory leaks in osquery code. All code should be thoroughly tested for leaks. See the [memory leak testing guide](https://osquery.readthedocs.org/deployment/performance-safety/) for more information on how to test your code for memory leaks.

When you submit a Pull Request, please consider including the output of a valgrind analysis.

## Calling systems tools

If you think that shelling out and executing a bash command is a good idea, it's not.

If you want to call a system executable or call system libraries via a tool, use the underlying C/C++ APIs that the tool uses to implement your functionality. Several tables (kextstat, processes, nvram, last, etc) were created by dissecting core systems tools and using the underlying APIs.

It's worth noting that you should exercise caution when copying code of any kind, especially core systems tools. Often times, core utilities developers recognize that their software will only be executed in the context of short-lived processes. For this reason, there are often memory leaks in the default behavior of these utilities. Put care into ensuring that you don't unknowingly introduce memory leaks into osquery.

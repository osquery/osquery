# Contributing to osquery

We want to make contributing to osquery as simple and transparent as possible. These guidelines
explain the basics of the osquery development process and how you can contribute too. Please read
these guidelines before submitting your code as they are designed to save you time later on when
your code is under review and give you the basics of how to get started.

## Our Development Process

### Open Development

All osquery development happens on [GitHub](https://github.com/facebook/osquery) which is our source
of truth. All contributions, both from core team members and external contributors, happen via pull
requests and go through the same review process. We use GitHub issues to track bugs and feature
requests including the ones from the core team.

Both our core team and community members are on the osquery [Slack](https://osquery.slack.com).
Feel free to register using the following [link](https://slack.osquery.io/) if you haven't done so
yet.

The osquery team also hosts regular office hours where the community is invited to discuss osquery
development with the core team. You are welcome to join. Office hours are announced on our Slack on
the `officehours` channel.

### Blueprints

If you plan to submit a change to the osquery core, a new big feature, or in
general a change that merits discussion, start by opening a
[Blueprint](https://github.com/facebook/osquery/issues/new?template=Blueprint.md) issue.

A blueprint issue is a standard GitHub issue, tagged with the label
[blueprint](https://github.com/facebook/osquery/labels/blueprint), which describes your idea, the
problem you're solving and how you plan to implement your solution. The goal of the blueprint is to
allow both the core team and the community to discuss whether a certain change is desirable and will
be accepted, and identify possible problems with the implementation before it even starts.

There aren't strict guidelines on when a blueprint is needed or not, so you should use your best
judgement or just ping the osquery team on our `core` channel on Slack, but to help you out here are
some examples of changes which **would** benefit from a blueprint:

* Change the basic functioning of the query scheduler
* Alter the thrift interfaces
* Reimplement the logger interface
* Add a new plugin type

There isn't either a strict format for the blueprints, but make sure to include what problem you're
trying to solve and how you plan to solve it. We can go from that and ask more information if
necessary. If you have code already, even if it is only a proof-of-concept that will be dropped
later, please submit it as a PR and associate it with the blueprint by mentioning the blueprint
issue on the pull request.

Please remember that blueprints are mostly designed to save **you** time by preventing you from
implementing code which won't be accepted or will need to be extensively modified later on. Please
use the right [template](https://github.com/facebook/osquery/issues/new?template=Blueprint.md) for
the issue. Feel free to advertise your blueprint and ask for feedback on Slack.

### Pull requests

All contributions are submitted via pull requests open against the
[master](https://github.com/facebook/osquery/tree/master) branch. We **do not** push code directly
to the master branch and pull requests are all reviewed before being merged including the ones from
the core team.

**Do not submit multiple unrelated changes on the same PR.** A pull request must represent a single
body of work. If your work requires a bug-fix, submit that first on a separate PR, the same goes for
refactors. If you can split your work into multiple smaller PRs please also do so. This is of utmost
importance to allow fast reviews and to simplify regression tracking, reverts and references.

Start by developing your feature on your feature branch and when ready submit a pull request against
the osquery master branch. The initial PR should preferably **contain a single commit**.

If you're unfamiliar with GitHub or how pull requests work, GitHub has a very easy to follow guide
that teaches you how to fork the project and submit your first PR. You can follow it
[here](https://guides.github.com/activities/forking/).

Don't forget to tag the issues you're addressing on the body of your PR description. If your PR
is intended to close an issue keywords (like `fixes` or `closes`) as defined on [GitHub
Help](https://help.github.com/articles/closing-issues-using-keywords/).

Once you submit your PR the core team will review it and trigger CI tests on our Jenkins instance. A
common source of test failures is wrong code formatting. All the code you submit should be formatted
with `clang-format`, but you shouldn't format more than the code you touch, just run `make
format_master` and amend your commit with any resulting changes before submitting.

If the tests fail or the reviewer requests changes, please submit those changes by **appending new
commits** to your feature branch. **Avoid amending old commits** as that makes it harder for the
reviewer to track your updates. If you need to keep your PR up-to-date with master the preferred way
is to rebase your branch on master and force-push. Finally the core team might help you with getting
your PR accepted by pushing directly to your branch when that makes sense.

Once at least one core team member approves your pull request and Jenkins is happy (remember tests
need to pass for all supported platforms) the PR is ready to merge. The core team will merge your PR
by squashing all your commits into one. The commit body message will be removed but the PR number
will be kept in the title so that you can link back a commit to a PR and check the full discussion
and reviews on GitHub.

Only the core team can merge pull requests and therefore at least one core team member will always
review your PR, however reviews from the community are highly encouraged and desirable.

Finally we try to keep only active PRs open. If your PR is stale we will close it, however if you
want to get back to it at a certain point feel free to re-open, or comment on it.

### A note about labels

The core team uses labels to tag each and every pull request. If you care about their meaning take a
look at [labels](https://github.com/facebook/osquery/labels) on GitHub. However, only the core team
can label issues and PRs, so you don't need to care too much about this.

### Milestones and release versions

We currently do not use any strict versioning scheme and we cut new versions as we feel it makes
sense according to the new features implemented, whether critical bug-fixes where merged, the size
of the release (i.e. how many commits since last version), etc.  We will however keep some near
future milestones open and tag each PR with the milestone we think it is going to be merged for.

Milestones are used for larger releases and we might cut patch releases as we go. If your PR is
tagged with the next milestone you can expect it to be merged as soon as it is ready. If your PR is
tagged with a later milestone we'll only merge it after the previous milestones are closed.

### Branches and tags

The osquery repo contains only the [master](https://github.com/facebook/osquery/tree/master) branch
which we do our best to keep stable. We don't keep feature or release branches. The master branch
will always keep a linear history and no merge commits are allowed. All our releases are tagged.


## Bug reports and feature requests

Developing code is not the only way to contribute to osquery. Submitting bug reports and new ideas
is also valuable and appreciated.

We use GitHub issues to track bugs and feature requests. To submit a bug report follow the [Bug
Report](https://github.com/facebook/osquery/issues/new?template=Bug_Report.md) template, to submit
a feature request use the [Feature
Request](https://github.com/facebook/osquery/issues/new?template=Feature_Request.md) template.

**Please only use issues for bug reports or feature requests**. If you have deployment questions or
issues or a general question about osquery hit our Slack instead as you'll have better support
there. To improve the chances you have a quicker answer search through the available channels and
choose the most appropriate one and fallback to general as a last resort.

**If you're using a vendor please use the appropriate channel as we won't be able to support vendor
deployments on the non-vendor channels.**


## Guidelines for contributing features to osquery core

The software housed in this repo is known as osquery core. While there are occasional exceptions,
contributions to core should abide by the following osquery guiding principles in order to be
accepted:

1. osquery doesn’t change the state of the system
2. osquery doesn’t create network traffic to third parties
3. osquery’s endpoint binaries have a light memory footprint
4. osquery minimizes system overhead & maximizes performance
5. The query schema for osquery seeks uniformity between operating systems

For new features that do not align with the mission principles of core, you may build outside of
osquery core in separate integrated processes called extensions:
https://osquery.readthedocs.io/en/stable/development/osquery-sdk/.

### Does my contribution belong in Core or in an Extension?

Belongs in Core:

* Observes guiding principles
* Has been shared with and approved by osquery project maintainers as a new feature in Core
* Meets Facebook's testing and quality standards

Belongs in an extension:

* Might not observe the osquery core guiding principles
* Has not been shared with or approved by Facebook as a new feature in Core
* Expands the scope of use for osquery beyond endpoint monitoring
* Integrates with a proprietary or esoteric tool that is not widely applicable


## Contributor License Agreement ("CLA")

In order to accept your pull request, we need you to submit a CLA. You only need to do this once to
work on any of Facebook's open source projects.

Complete your CLA at https://code.facebook.com/cla.


## License

By contributing to osquery you agree that your contributions will be licensed as defined on the
[LICENSE](LICENSE) file.

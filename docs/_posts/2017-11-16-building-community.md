---
title:  "Building osquery's community"
categories: community
---

The osquery community is large! In this post we'll highlight some recent examples of why it is so large, and provide examples of how we can continue to grow it. There are plenty of ways to help the project, from writing code, performing code reviews, to filing good feature and bug reports. But the community is not just the GitHub project, and there are tons of ways to contribute beyond the code repository.

In the past 6 months the osquery project and community has benefited greatly from the following activities. We are deeply appreciative of all those involved and the good intentions they carried.

Chris Long and Palantir shared hands-on experiences (good, bad, ugly) [at scale](https://medium.com/@palantir/osquery-across-the-enterprise-3c3c9d13ec55). This experience is honest and thorough. Other large enterprises can use this resource to better prepare for what a long and large deployment will entail.

Lauren Pearl and Trail Of Bits conducted and published a [survey](https://blog.trailofbits.com/2017/11/09/how-are-teams-currently-using-osquery/) of teams using osquery. This is a concise view of how osquery is solving use cases and adding value. Again, it is honest and highlights lots of areas for improvement. Bringing the community up to speed on the high-level issues and converging energy to address them is invaluable to any open source community.

Kolide has released two new open source projects for the osquery community, [Launcher](https://kolide.com/launcher) and [Fleet](https://kolide.com/fleet). Open sources projects do not exist in vacuums, they need and thrive with integrations and projects building on fundamentals. The osquery project *specifically* requires 'missing' components like configuration management, logging integrations, fleet management, and orchestration. There are tons of opportunities to continue to build, and there are still missing components you could build too!

Mike Myers and Trail Of Bits wrote about [uses cases](https://blog.trailofbits.com/2017/10/10/tracking-a-stolen-code-signing-certificate-with-osquery/); Victor Vrantchan and Kolide did the [same](https://blog.kolide.com/check-the-efi-version-of-a-mac-with-osquery-f98c6e3beffa); and Timothy Spann wrote about Apache Phoenix [integrations](https://community.hortonworks.com/articles/79842/ingesting-osquery-into-apache-phoenix-using-apache.html). these articles have rippling effects throughout the community. They show health and interest and help others solve the same or similar use cases. At the end of the day osquery is not a solution, it requires examples and demonstrations to add the most value.

Allister Banks spoke at [MacDevOps](https://www.youtube.com/watch?v=WFx9nPHC_Co&feature=youtu.be), and many others are investing lots of their own time showing support and expanding the community through conferences and workshops. This joins our community with others, for example communities of systems administrators, developers, enterprise defenders, and universities. Nick Anderson and Mitchell Grenier on the core team have been doing the same at [Microsoft BlueHat](https://blogs.technet.microsoft.com/bluehat/2017/09/01/announcing-the-bluehat-v17-schedule/) and [USENIX LISA](https://www.usenix.org/conference/lisa17/conference-program/presentation/reed).

Marcin Wielgoszewski [presented](https://www.infoq.com/presentations/doorman-osquery) Doorman, osquery's first fleet management tool at QCon. [Doorman](https://github.com/mwielgoszewski/doorman) also recently celebrated its 6th release since April 2016. Congrats to everyone developing and providing valuable feedback to the project.

We passed 10,000 GitHub stars, passed over 1000 users in Slack, and have 172 contributors to the repository! The project activity only continues to increase with no signs of stopping! If you want to see a more complete list of community highlights, or add more, check out the [Community News](https://osquery.io/community/). So now, let's talk about how to amplify that involvement.

## What could improve our community and how can you be involved

* The best way to contribute is to join [our Slack](https://osquery-slack.herokuapp.com/) and ask good questions and help others. Be kind, assume good intent, and share your knowledge. Double check assumptions and skim the [documentation](http://osquery.readthedocs.org/en/stable/) to guide others to reference materials when available.
* Capture your insight and experiences! Create good issues that go beyond bookmarking a feature request, bug, or user experience flaw. Here's an [example](https://github.com/facebook/osquery/issues/3764) of me 'bookmarking'. While it is concise and I understand what needs to be done, it does not help anyone else who may be having the same issue, or anyone who many want to help fix the issue. Here is an [issue](https://github.com/facebook/osquery/issues/3920) that is well documented, discoverable, shares an experience, and is actionable (even though it is hard to fix, or may not be fixable).
* We need code reviews badly, this is the #1 way we can land code faster and with less bugs. Unfortunately there are two blockers, first there is a requirement for C++ fluency and second the test infra is a gray box. If you fork our repo you need to run tests manually. If we did not have customized test infra the experience may be improved. If you have any C++ experience, please *please please*, leave some notes on the [pull requests](https://github.com/facebook/osquery/pulls), make some nits, we promise to assume the best intent and we do value your time and advice.
* Share your deployment experiences and the use cases you are solving. We would like to solve security and detection use cases with osquery, as well as inventorying, vulnerability management, compliance, performance monitoring, and many more. The more open we are about the 'edges' of the use case solutions the better we can all be at planning to address those.
* Blog and bring osquery to other communities. Again, insight and experience are invaluable. If you can capture experience and share it, we will all benefit, it is such a wonderful way to scale your impact.
* The [osquery.io](https://osquery.io/) website is the #1 way new users are introduced to osquery. They bring lots of questions and we could do a much better job at onboarding and answering. We [tried](https://github.com/facebook/osquery/tree/master/docs) to open source, using GitHub pages and Jekyll with the hypothesis that more people would contribute to improving this experience, but that has not been the case. Let's all continue to reflect and search for ways to rethink and improve this need. The 'first impression' really matters!
* Reliability and performance accountability. Please continue to hold us accountable for developing a reliable and performant agent. We need to improve the optimizations and the assumptions. Even though we have a watchdog, it is not a solution if there is no reporting about the watchdog actions. We need to be reliable too, if you expect to get data the agent must have methods for assuring that or providing clear reasons why it cannot: query errors, query performance, host and schedule applicability, extension availability, logging and pipeline errors, etc.

There are many many methods for being involved and contributing. Creating tutorials, mentoring, hosting hackathons, giving thanks! This is not an exhaustive list but if there is something that you feel has been invaluable to the community, please reach out and we can amend.

<div class="note info">
  <h5>Bi-weekly office hours discussion</h5>
  <p>Every other week, the osquery team jumps on a BlueJeans VC to hold office hours. The goal is to listen to other's comments and concerns and help prioritize features and fixes. It is a fun and friendly hour of osquery.</p>
  <br />
  <code>
  When: Fridays @ 10:00AM PT
  Where: The #officehours channel on Slack!
  </code>
</div>

Thanks everyone, you're the absolute best, let's keep this train at max speed and keep shipping!

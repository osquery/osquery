---
layout: community_news
title: Community
permalink: /community/
redirect_from: /community/queries/index.html
---

{% assign community = site.data.resources | group_by: 'year' %}
{% for year in community %}
## {{ year.name }}
    {% for item in year.items %}
 * [{{ item.topic }}]({{ item.link }}) - [{{ item.speaker }}](https://twitter.com/{{ item.twitter_handle }})
    {% endfor %}
{% endfor %}

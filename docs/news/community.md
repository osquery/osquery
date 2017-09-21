---
layout: community_news
title: Community
permalink: /community/
---

{% assign community = site.data.resources | group_by: 'year' %}
{% for year in community reversed %}
## {{ year.name }}
    {% for item in year.items %}
 * [{{ item.topic }}]({{ item.link }}) - [{{ item.speaker }}](https://twitter.com/{{ item.twitter_handle }})
    {% endfor %}
{% endfor %}

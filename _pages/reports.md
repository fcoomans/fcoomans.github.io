---
layout: single
permalink: /reports/index.html
---

<div>  
  <h1 id="page-title" class="page__title">HTB Machine Write-ups</h1>
  <div class="entries-list">

{% assign machines = site.htb-machines | sort: "date" | reverse %}
{% for machine in machines %}

    <div class="list__item">
      <article class="archive__item" itemscope itemtype="https://schema.org/CreativeWork">
      <h2 id="{{ machine.name }}" class="archive__item-title" itemprop="headline"><a href="{{ machine.url | relative_url }}" rel="permalink">{{ machine.name }}</a></h2>

    {% if machine.read_time or machine.show_date %}
      <p class="page__meta">
        {% if machine.show_date and machine.date %}
          {% assign date = machine.date %}
          <span class="page__meta-date">
            <i class="far {% if include.type == 'grid' and machine.read_time and machine.show_date %}fa-fw {% endif %}fa-calendar-alt" aria-hidden="true"></i>
            {% assign date_format = site.date_format | default: "%B %-d, %Y" %}
            <time datetime="{{ date | date_to_xmlschema }}">{{ date | date: date_format }}</time>
          </span>
        {% endif %}

        {% if machine.read_time and machine.show_date %}<span class="page__meta-sep"></span>{% endif %}

        {% if machine.read_time %}
          {% assign words_per_minute = machine.words_per_minute | default: site.words_per_minute | default: 200 %}
          {% assign words = machine.content | strip_html | number_of_words %}

          <span class="page__meta-readtime">
            <i class="far {% if include.type == 'grid' and machine.read_time and machine.show_date %}fa-fw {% endif %}fa-clock" aria-hidden="true"></i>
            {% if words < words_per_minute %}
              {{ site.data.ui-text[site.locale].less_than | default: "less than" }} 1 {{ site.data.ui-text[site.locale].minute_read | default: "minute read" }}
            {% elsif words == words_per_minute %}
              1 {{ site.data.ui-text[site.locale].minute_read | default: "minute read" }}
            {% else %}
              {{ words | divided_by: words_per_minute }} {{ site.data.ui-text[site.locale].minute_read | default: "minute read" }}
            {% endif %}
          </span>
        {% endif %}
      </p>
    {% endif %}

      <p class="writeup-meta">
        <strong>OS</strong>: {{ machine.os | default: "N/A" }}<br>
        <strong>Difficulty</strong>: {{ machine.difficulty | default: "N/A" }}<br>
        <strong>Skills</strong>: {{ machine.skills | default: "N/A" }}<br>
        <strong>Tools</strong>: {{ machine.tools | default: "N/A" }}
      </p>

      <p class="archive__item-excerpt" itemprop="description">{{ machine.content | split: '<h2' | slice: 1 | split: '</h2>' | last | split: '<h2' | first | replace: '\n', ' ' | strip | strip_html | replace: '`', '' | replace: '<code>', '' | replace: '</code>', '' | default: 'No summary available' | truncate: 250 }}
      </p>

      </article>
    </div>

{% endfor %}

  </div>
</div>

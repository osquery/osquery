## osquery site

This is a redesign from the old Django https://osquery.io site.

Initially it is a clone of the Jekyll docs sites. The goal is to provide a community blog, a unified user guide (documentation), and transparency about the content hosted at https://osquery.io. Having a monolithic repository is helpful.

### Adding a new news/blog article

You will find all of the blog posts in the `_posts` directory.

1. Make a new file in the form `YYYY-MM-DD-title.markdown` in `_posts/`
2. Add the metadata below to the top of the file. Then compose your post.
3. Use the **Running locally** directions to preview your post.
4. Commit.

Your post should use the following form:
```
---
title:  "This is your title"
date:   2017-08-20 00:46:48 -0700
categories: fim auditing update
---
Your content here.
Feel free to use any markdown.
```

### Adding a community article

The community articles are "external" links to community resources.
If you would like to compose a community resource, please consider if it would be appropriate as a "wiki" document or a "new" or blog article.
If you'd like to compose a **doc** see the **Adding a new wiki page**, if you'd like to compose a **news** item see **Adding a new blog article**.

To add a community resource link:
1. Edit the `_data/resources.yml` file.
2. Add your link metadata.
3. Use the **Running locally** directions to preview your post.
4. Commit.

The added metadata uses the following format:
```
- speaker: Firstname Lastname
  twitter_handle: the_persons_twitter_handle
  link: https://complete/link/to/resource
  topic: Friendly title for the resource
  year: 2017
```

### Running locally

You can preview your contributions before opening a pull request by running from within the directory:

1. `bundle install --without test test_legacy benchmark`
2. `bundle exec jekyll serve`

It's just a Jekyll site, afterall!

This [GitHub guide](https://help.github.com/articles/adding-a-jekyll-theme-to-your-github-pages-site/) was helpful for getting started.

To test the site use:

```
bundle exec htmlproofer ./_site --only-4xx --check-favicon --check-html
```

This will be run in the `Code Audit` Jenkins job.

### Updating Font Awesome

1. Go to <https://icomoon.io/app/>
2. Choose Import Icons and load `icomoon-selection.json`
3. Choose Generate Font → Download
4. Copy the font files and adapt the CSS to the paths we use in Jekyll

### Website Todo

1. Update code in `/tools` to produce the correct `version.yml` for new releases.
2. Convert the deprecated ReadTheDocs wiki pages to Jekyll docs.
3. Look for existing common redirects for backwards compatibility.

## ReadTheDocs Wiki (deprecated)

The ReadTheDocs wiki (https://osquery.readthedocs.org/en/stable) is generated using a RTD-configured osquery project and associated GitHub Service. This Service is documented by RTD and more-or-less setup automatically with the project. RTD generates documentation for every version (git tag). It calls the most recent tag 'stable', the most recent commit to master 'devel', and includes links to every past version. The project settings and sidebar for RTD is kept in the root as [mkdocs.yml](https://github.com/facebook/osquery/blob/master/mkdocs.yml).

### Adding a new page

New wiki pages should be organized into one of the following categories:

- **Introduction**: Overview of the project or a tool.
- **Installation**: Deep dives into OS-specifics, packaging, and switches that control starting tools.
- **Deployment**: Tool concepts and all the wonderful goodies of making osquery useful.
- **Development**: Help and guides for starting with osquery development and build.

Make a new "filename.md" within the category folder withing `/docs/wiki/CATEGORY/`. Then add the friendly page title and path to [mkdocs.yml](https://github.com/facebook/osquery/blob/master/mkdocs.yml), in the order the page should appear within the wiki sidebar.

### Wiki style tips

- Inline code highlighing (`$ echo 'this is inline'`) does not look the best in RTD, try to have as little inline syntax highlighting as possible.
- **osqueryd**, **osqueryi** and other tool names should be in bold. Use `inline highligh` when a tool or script is mentioned for the first time.
- Filesystem paths and non-clickable URI examples should also be bold.
- Flag names are usually in quotes, `inline highlight` when introduced for the first time or used as an example.

## Doxygen

The Doxygen documentation is not hosted anywhere, each developer must build and view-locally. To build the docs use `make docs`.

The output HTML documentation is written to `./build/docs/html/`. Use `index.html` to begin exploring.

## Tables and Packs

Table schema, the osquery user API, is created using the Python-based ".spec" files in [`./specs`](https://github.com/facebook/osquery/tree/master/specs). More documentation on how specs work can be found in the [Creating New Tables](http://osquery.readthedocs.org/en/stable/development/creating-tables/) developer documentation. These files are used to build osquery, but can be parsed to create JSON-based API schema. This JSON is published to the homepage at [https://osquery.io/schema/].

Use: `./tools/codegen/genapi.py` to generate the amalgamated schema. To generate a "change log" between tags, use the same script but use `--diff` and supply the two JSON imputs.

```python
./tools/codegen/genapi.py > ./build/docs/CURRENT.json
./tools/codegen/genapi.py --diff ./build/docs/OLD.json ./build/docs/CURRENT.json
```

We keep the table schema in [`osquery/osquery`](https://github.com/osquery/osquery)'s `/schema` directory.
This protects the `facebook/osquery` repo from 1000+ LoC checkins of generated JSON.

The `/docs/_data/packs.yml` holds the name of each pack and a friendly title.
The Jekyll site will fetch each title from the `/packs` directory in `facebook/osquery`.

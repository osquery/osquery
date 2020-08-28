## ReadTheDocs Wiki

The ReadTheDocs wiki (https://osquery.readthedocs.org/en/stable) is generated using a RTD-configured osquery project and associated GitHub Service. This Service is documented by RTD and more-or-less setup automatically with the project. RTD generates documentation for every version (git tag). It calls the most recent tag 'stable', the most recent commit to master 'devel', and includes links to every past version. The project settings and sidebar for RTD is kept in the root as [mkdocs.yml](https://github.com/osquery/osquery/blob/master/mkdocs.yml).

### Adding a new page

New wiki pages should be organized into one of the following categories:

- **Introduction**: Overview of the project or a tool.
- **Installation**: Deep dives into OS-specifics, packaging, and switches that control starting tools.
- **Deployment**: Tool concepts and all the wonderful goodies of making osquery useful.
- **Development**: Help and guides for starting with osquery development and build.

Make a new "filename.md" within the category folder within `/docs/wiki/CATEGORY/`. Then add the friendly page title and path to [mkdocs.yml](https://github.com/osquery/osquery/blob/master/mkdocs.yml), in the order the page should appear within the wiki sidebar.

### Wiki style tips

- Inline code highlighting (`$ echo 'this is inline'`) does not look the best in RTD, try to have as little inline syntax highlighting as possible.
- **osqueryd**, **osqueryi** and other tool names should be in bold. Use `inline highlight` when a tool or script is mentioned for the first time.
- Filesystem paths and non-clickable URI examples should also be bold.
- Flag names are usually in quotes, `inline highlight` when introduced for the first time or used as an example.

## Doxygen

The Doxygen documentation is not hosted anywhere, each developer must build and view-locally. To build the docs use `make docs`.

The output HTML documentation is written to `./build/docs/html/`. Use `index.html` to begin exploring.

## Tables and Packs

Table schema, the osquery user API, is created using the Python-based ".spec" files in [`./specs`](https://github.com/osquery/osquery/tree/master/specs). More documentation on how specs work can be found in the [Creating New Tables](http://osquery.readthedocs.org/en/stable/development/creating-tables/) developer documentation. These files are used to build osquery, but can be parsed to create JSON-based API schema. This JSON is published to the homepage at [https://osquery.io/schema/].

Use: `./tools/codegen/genapi.py` to generate the amalgamated schema. To generate a "change log" between tags, use the same script but use `--diff` and supply the two JSON inputs.

```python
./tools/codegen/genapi.py > ./build/docs/CURRENT.json
./tools/codegen/genapi.py --diff ./build/docs/OLD.json ./build/docs/CURRENT.json
```

## Deployling on OS X

Run `make package` to build all of the code and create a new OS X package.

To modify the OS X distribution files/settings/etc, use the
[Packages](http://s.sudre.free.fr/Software/Packages/about.html) tool to open
`osquery.pkgproj`. Note that the [Packages](http://s.sudre.free.fr/Software/Packages/about.html)
tool is a requirement for `make package` to work as well, since it uses the `packagesbuild`
command-line tool, which is installed with the [Packages](http://s.sudre.free.fr/Software/Packages/about.html)
distribution.

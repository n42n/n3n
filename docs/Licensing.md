# Licensing

The intent of the licensing for the n3n project is to ensure that the source
code is always freely available, to avoid concentrating the rights into any
one person or corporation and to clearly recognise the origin of any included
source code.

- Any new self-contained tools or modules are licensed GPL-2.0-only, as
  provided in LICENSES/preferred/GPL-2.0
- Much of the core n3n code was inherited from the n2n project and is licenced
  as GPL-3-only.
- There are multiple distinct copyright holders throughout the codebase.
- There is no Contributor Licence Agreement and thus there is no single body
  that can take ownership of the code and/or change the licensing.

The common way of expressing the licenses in this software is to use Software
Package Data Exchange (SPDX) license identifiers in each source file. SPDX
license identifiers are machine parsable and precise shorthands for the
license under which the content of the file is contributed. SPDX license
identifiers are managed by the SPDX Workgroup at the Linux Foundation and have
been agreed on by partners throughout the industry, tool vendors, and legal
teams. For further information see https://spdx.org/

## License identifier
The n3n project requires the precise SPDX identifier in all source files. The
valid identifiers used in the kernel are explained in the section License
identifiers and have been retrieved from the official SPDX license list at
https://spdx.org/licenses/ along with the license texts.

All SPDX license identifiers must have a corresponding file in the LICENSES
subdirectories. This is required to allow tool verification and to have the
licenses ready to read and extract right from the source, which is recommended
by various FOSS organizations.

## Unknown sources

Over the extended history of this project, multiple external libraries have
been incorporated via copy-and-paste.  Not all these libraries have been
clearly recognised and their copyright and license may be incorrectly
described.

This is an ongoing janitorial project to determine the provenance and
correctly mark these included sources.

## Provenance of contributions

All contributions should have a known provenance for their original source.
If there is any question or concern about this on the part of the maintainers,
you may be asked to provide a "Developer’s Certificate of Origin" sign off.

If you used any sort of advanced coding tool in the creation of your patch,
you need to acknowledge that use by adding an Assisted-by tag. Failure to do
so may impede the acceptance of your work.

## Debian copyright-format information

To assist with keeping track of the source, the Debian project has a standard
for tracking this information.  The file `debian/copyright` contains the
known details.

## References

Much of the above text was copied from (or inspired by) the linux kernel
Documentation.  Perusing the original documents may help the reader
understand more of the intent and flavor of the description above.

This includes at least the following documents:

- [Documentation/process/license-rules.rst](https://www.kernel.org/doc/html/latest/process/license-rules.html) 
- [Documentation/process/submitting-patches.rst](https://www.kernel.org/doc/html/latest/process/submitting-patches.html)

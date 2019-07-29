This is the Quick Start Guide to ECTester. The document is a collection of field notes to help test Elliptic Curve cryptography implementations and support.

The manual name is ectester.pdf. The book is built using DocBook. The instructions to setup DocBook on Ubuntu 16.04 with Apache FOP 2.2 are in `setup/docbook.pdf`. Once DocBook is setup just run `make-book.sh` to create the manual.

If you are working on an OS like Red Hat or Fedora, then you may need to open `custom.xsl` and change the hard-coded path to `docbook.xsl`. We have not found a way to dynamically determine the path to `docbook.xsl`.

If you find errors or omissions then make pull requests and open bug reports.


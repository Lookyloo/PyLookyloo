.. PyLookyloo documentation master file, created by
   sphinx-quickstart on Tue Mar 23 12:28:17 2021.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Welcome to PyLookyloo's documentation!
======================================

This is the client API for `Lookyloo <https://www.lookyloo.eu>`_:

  With Lookyloo you can dissect a website while it is in motion.

  Lookyloo is a web interface that captures a webpage and then displays a tree of the domains, that call each other.


Installation
------------

The package is available on PyPi, so you can install it with::

  pip install pylookyloo


Usage
-----

You can use `lookyloo` as a python script::

    $ lookyloo -h
    usage: lookyloo [-h] [--url URL] [--query QUERY] [--listing] [--redirects REDIRECTS] [--search-url SEARCH_URL]
                    [--search-hostname SEARCH_HOSTNAME]

    Enqueue a URL on Lookyloo.

    optional arguments:
      -h, --help            show this help message and exit
      --url URL             URL of the instance (defaults to https://lookyloo.circl.lu/, the public instance).
      --query QUERY         URL to enqueue. The response is the permanent URL where you can see the result of the capture.
      --listing             Should the report be publicly listed.
      --redirects REDIRECTS
                            Get redirects for a given capture (parameter is a capture UUID).
      --search-url SEARCH_URL
                            Get most recent captures containing that URL.
      --search-hostname SEARCH_HOSTNAME
                            Get most recent captures containing that hostname.

    The capture UUIDs you will receive can be used as permaurls (https://<domain>/tree/<uuid>).


Or as a library:

.. toctree::
   :glob:

   api_reference


Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`

# Third-party components

The packaged JAR includes these runtime libraries. Their upstream license files remain authoritative:

- Gson (`com.google.code.gson:gson`) — Apache License 2.0.
- RE2/J (`com.google.re2j:re2j`) — BSD 3-Clause License.
- jsoup (`org.jsoup:jsoup`) — MIT License.

The Montoya API is compile-only and is supplied by Burp Suite at runtime.

The quoted-endpoint discovery categories and default background-exclusion concept are adapted
from [PortSwigger/js-link-finder](https://github.com/PortSwigger/js-link-finder), a fork of
BurpJSLinkFinder. This project does not package or execute its Jython extension.

## js-link-finder license

MIT License

Copyright (c) 2019 InitRoot

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

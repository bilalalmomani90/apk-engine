# Third-party notices

Parts of the approach in `apkengine.py` (project detection, choosing Gradle/JDK
from the Android Gradle Plugin version, grouping build failures into causes)
are derived from ideas and structure of **AndroidForge**
(https://github.com/Professional-X/AndroidForge), licensed under the MIT License.
The code in this repository was rewritten; the notice is kept as the MIT license
requires.

```
MIT License

Copyright (c) 2026 AndroidForge

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
```

Gradle (Apache-2.0), Android SDK (Google Android SDK License Agreement) and
OpenJDK (GPLv2 + Classpath Exception) are downloaded/used at build time and are
not redistributed by this repository. Review the Android SDK terms before
publishing any image or package that bundles the SDK.

# Single Header Pattern Scanner

## Overview
The Single Header Pattern Scanner is a lightweight, pattern scanning library for Windows 64-bit architectures. This library offers a powerful way to search for patterns within binary data, leveraging compile-time processing for enhanced performance and efficiency.

## Features
- **Compile-Time Pattern Processing:** Processes patterns at compile time, maximizing efficiency and reducing runtime overhead.
- **Wide Range of Pattern Types:** Supports various pattern types including addresses, offsets, values, function calls, and more.
- **Simplified Usage:** Designed as a single header for ease of integration into any project.

## Requirements
- Windows 64-bit architecture

## Quick Start
1. Include `PatternScanner.h` in your project.
2. Use the `CREATE_PATTERN` macro to define your pattern, offset, and type.
3. Call `FindPattern` with your pattern and module name to search for the pattern within a module's binary data.

## Example
```cpp
auto pattern = CREATE_PATTERN("89 45 ?? E8 ?? ?? ?? ??", 0, PatternScanner::PatternType::FUNCTION_CALL);
auto address = PatternScanner::FindPattern(pattern, "your_module_name.dll");
```

## License

MIT License

Copyright (c) [2024]

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

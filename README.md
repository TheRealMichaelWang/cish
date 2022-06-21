# Cish
## About
A minimal, performant, strongly-typed, and multi-paradigmn programming language focused on being practical and pragmatic, yet powerful enough to create readable, performant and concise code for any problem. While Cish has as much to do with Forth as Javascript has with Java, it shares the same minimalist, performance oriented approach and philosophy.

## Features
* Super Performant
  * Cish can be both interpreted and compiled.
* A strong, impeccable type system.
  * Cish has actual strong typing, unlike c. Casts are made explicitly and it's not possible to have a binary operator have two different types for its operands.
    * Type safe, runtime type-casting is supported when necessary.
  * Powerful and expressive type arguments, not only for structs but for functions as well. 
    * Type arguments aren't constrained to be reference/allocation types like Java - they can also be primitives.
    * Type parameters also support type requirements, somewhat like interfaces.
  * Supports sum-types
    * Clean error handling, unlike go. Requires succesful results to be unwrapped, providing a concise layer of error handling.
* Support for first class functions.
  * First class functions are inbuilt in the syntax and overall design as well - there isn't a million ways you can define a function. 
* Structured programming, with some OOP features like inheritance. 
  * The linking process is done automatically - there's no need for C-like forward declarations.
  * While casting is done automatically from derived types to their super type, downcasting is not allowed. 
* Interoperability with other C and **C#**.
  * See [this related project](https://github.com/TheRealMichaelWang/superforthcsharp) for details.

## Important Links
* [Documentation](https://github.com/TheRealMichaelWang/superforth/wiki)
  * [Installation](https://github.com/TheRealMichaelWang/superforth/wiki/Installation)
  * [CLI Usage](https://github.com/TheRealMichaelWang/superforth/wiki/Command-Line-Usage)
* [Examples](https://github.com/TheRealMichaelWang/superforth/tree/main/examples)
* [Release](https://github.com/TheRealMichaelWang/superforth/releases/tag/0.1)

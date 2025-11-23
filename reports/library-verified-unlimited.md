# VulnFusion 安全分析报告

融合 Rudra 与 SafeDrop 的高级漏洞检测

## 分析摘要

- **分析文件总数：** 1553
- **代码行数：** 831417
- **发现漏洞数：** 16
- **分析时长：** 487
- **unsafe 块数：** 35593

### 按严重程度统计

| 严重程度 | 数量 |
|----------|-------|
| Critical | 13 |
| High | 3 |

### 按类型统计

| 类型 | 数量 |
|------|-------|
| drop-panic | 13 |
| uninitialized-read | 3 |

## 漏洞详情

### Critical（共 13 条）

#### 漏洞 #1：Potential panic in Drop implementation detected

**详情：**
- **Type:** `drop-panic`
- **Severity:** `Critical`
- **Confidence:** `90.0%`
- **Location:** `d:\漏洞挖掘\detector\project\library\std\src\io\buffered\bufwriter.rs:0`
- **检测方法：** `StaticAnalysis`

**解释：**
Drop implementation may panic, which can cause undefined behavior

**代码：**
```rust
impl < W : ? Sized + Write > BufWriter < W > { # [doc = " Send data in our local buffer into the inner writer, looping as"] # [doc = " necessary until either it's all been sent or an error occurs."] # [doc = ""] # [doc = " Because all the data in the buffer has been reported to our owner as"] # [doc = " \"successfully written\" (by returning nonzero success values from"] # [doc = " `write`), any 0-length writes from `inner` must be reported as i/o"] # [doc = " errors from this method."] pub (in crate :: io) fn flush_buf (& mut self) -> io :: Result < () > { # [doc = " Helper struct to ensure the buffer is updated after all the writes"] # [doc = " are complete. It tracks the number of written bytes and drains them"] # [doc = " all from the front of the buffer when dropped."] struct BufGuard < 'a > { buffer : & 'a mut Vec < u8 > , written : usize , } impl < 'a > BufGuard < 'a > { fn new (buffer : & 'a mut Vec < u8 >) -> Self { Self { buffer , written : 0 } } # [doc = " The unwritten part of the buffer"] fn remaining (& self) -> & [u8] { & self . buffer [self . written ..] } # [doc = " Flag some bytes as removed from the front of the buffer"] fn consume (& mut self , amt : usize) { self . written += amt ; } # [doc = " true if all of the bytes have been written"] fn done (& self) -> bool { self . written >= self . buffer . len () } } impl Drop for BufGuard < '_ > { fn drop (& mut self) { if self . written > 0 { self . buffer . drain (.. self . written) ; } } } let mut guard = BufGuard :: new (& mut self . buf) ; while ! guard . done () { self . panicked = true ; let r = self . inner . write (guard . remaining ()) ; self . panicked = false ; match r { Ok (0) => { return Err (io :: const_error ! (ErrorKind :: WriteZero , "failed to write the buffered data" ,)) ; } Ok (n) => guard . consume (n) , Err (ref e) if e . is_interrupted () => { } Err (e) => return Err (e) , } } Ok (()) } # [doc = " Buffer some data without flushing it, regardless of the size of the"] # [doc = " data. Writes as much as possible without exceeding capacity. Returns"] # [doc = " the number of bytes written."] pub (super) fn write_to_buf (& mut self , buf : & [u8]) -> usize { let available = self . spare_capacity () ; let amt_to_buffer = available . min (buf . len ()) ; unsafe { self . write_to_buffer_unchecked (& buf [.. amt_to_buffer]) ; } amt_to_buffer } # [doc = " Gets a reference to the underlying writer."] # [doc = ""] # [doc = " # Examples"] # [doc = ""] # [doc = " ```no_run"] # [doc = " use std::io::BufWriter;"] # [doc = " use std::net::TcpStream;"] # [doc = ""] # [doc = " let mut buffer = BufWriter::new(TcpStream::connect(\"127.0.0.1:34254\").unwrap());"] # [doc = ""] # [doc = " // we can use reference just like buffer"] # [doc = " let reference = buffer.get_ref();"] # [doc = " ```"] # [stable (feature = "rust1" , since = "1.0.0")] pub fn get_ref (& self) -> & W { & self . inner } # [doc = " Gets a mutable reference to the underlying writer."] # [doc = ""] # [doc = " It is inadvisable to directly write to the underlying writer."] # [doc = ""] # [doc = " # Examples"] # [doc = ""] # [doc = " ```no_run"] # [doc = " use std::io::BufWriter;"] # [doc = " use std::net::TcpStream;"] # [doc = ""] # [doc = " let mut buffer = BufWriter::new(TcpStream::connect(\"127.0.0.1:34254\").unwrap());"] # [doc = ""] # [doc = " // we can use reference just like buffer"] # [doc = " let reference = buffer.get_mut();"] # [doc = " ```"] # [stable (feature = "rust1" , since = "1.0.0")] pub fn get_mut (& mut self) -> & mut W { & mut self . inner } # [doc = " Returns a reference to the internally buffered data."] # [doc = ""] # [doc = " # Examples"] # [doc = ""] # [doc = " ```no_run"] # [doc = " use std::io::BufWriter;"] # [doc = " use std::net::TcpStream;"] # [doc = ""] # [doc = " let buf_writer = BufWriter::new(TcpStream::connect(\"127.0.0.1:34254\").unwrap());"] # [doc = ""] # [doc = " // See how many bytes are currently buffered"] # [doc = " let bytes_buffered = buf_writer.buffer().len();"] # [doc = " ```"] # [stable (feature = "bufreader_buffer" , since = "1.37.0")] pub fn buffer (& self) -> & [u8] { & self . buf } # [doc = " Returns a mutable reference to the internal buffer."] # [doc = ""] # [doc = " This can be used to write data directly into the buffer without triggering writers"] # [doc = " to the underlying writer."] # [doc = ""] # [doc = " That the buffer is a `Vec` is an implementation detail."] # [doc = " Callers should not modify the capacity as there currently is no public API to do so"] # [doc = " and thus any capacity changes would be unexpected by the user."] pub (in crate :: io) fn buffer_mut (& mut self) -> & mut Vec < u8 > { & mut self . buf } # [doc = " Returns the number of bytes the internal buffer can hold without flushing."] # [doc = ""] # [doc = " # Examples"] # [doc = ""] # [doc = " ```no_run"] # [doc = " use std::io::BufWriter;"] # [doc = " use std::net::TcpStream;"] # [doc = ""] # [doc = " let buf_writer = BufWriter::new(TcpStream::connect(\"127.0.0.1:34254\").unwrap());"] # [doc = ""] # [doc = " // Check the capacity of the inner buffer"] # [doc = " let capacity = buf_writer.capacity();"] # [doc = " // Calculate how many bytes can be written without flushing"] # [doc = " let without_flush = capacity - buf_writer.buffer().len();"] # [doc = " ```"] # [stable (feature = "buffered_io_capacity" , since = "1.46.0")] pub fn capacity (& self) -> usize { self . buf . capacity () } # [cold] # [inline (never)] fn write_cold (& mut self , buf : & [u8]) -> io :: Result < usize > { if buf . len () > self . spare_capacity () { self . flush_buf () ? ; } if buf . len () >= self . buf . capacity () { self . panicked = true ; let r = self . get_mut () . write (buf) ; self . panicked = false ; r } else { unsafe { self . write_to_buffer_unchecked (buf) ; } Ok (buf . len ()) } } # [cold] # [inline (never)] fn write_all_cold (& mut self , buf : & [u8]) -> io :: Result < () > { if buf . len () > self . spare_capacity () { self . flush_buf () ? ; } if buf . len () >= self . buf . capacity () { self . panicked = true ; let r = self . get_mut () . write_all (buf) ; self . panicked = false ; r } else { unsafe { self . write_to_buffer_unchecked (buf) ; } Ok (()) } } # [inline] unsafe fn write_to_buffer_unchecked (& mut self , buf : & [u8]) { debug_assert ! (buf . len () <= self . spare_capacity ()) ; let old_len = self . buf . len () ; let buf_len = buf . len () ; let src = buf . as_ptr () ; unsafe { let dst = self . buf . as_mut_ptr () . add (old_len) ; ptr :: copy_nonoverlapping (src , dst , buf_len) ; self . buf . set_len (old_len + buf_len) ; } } # [inline] fn spare_capacity (& self) -> usize { self . buf . capacity () - self . buf . len () } }
```

**💡 建议：**
Ensure Drop implementations never panic

#### 漏洞 #2：Potential panic in Drop implementation detected

**详情：**
- **Type:** `drop-panic`
- **Severity:** `Critical`
- **Confidence:** `90.0%`
- **Location:** `d:\漏洞挖掘\detector\project\library\std\src\io\mod.rs:0`
- **检测方法：** `StaticAnalysis`

**解释：**
Drop implementation may panic, which can cause undefined behavior

**代码：**
```rust
//! Traits, helpers, and type definitions for core I/O functionality.
//!
//! The `std::io` module contains a number of common things you'll need
//! when doing input and output. The most core part of this module is
//! the [`Read`] and [`Write`] traits, which provide the
//! most general interface for reading and writing input and output.
//!
//! ## Read and Write
//!
//! Because they are traits, [`Read`] and [`Write`] are implemented by a number
//! of other types, and you can implement them for your types too. As such,
//! you'll see a few different types of I/O throughout the documentation in
//! this module: [`File`]s, [`TcpStream`]s, and sometimes even [`Vec<T>`]s. For
//! example, [`Read`] adds a [`read`][`Read::read`] method, which we can use on
//! [`File`]s:
//!
//! ```no_run
//! use std::io;
//! use std::io::prelude::*;
//! use std::fs::File;
//!
//! fn main() -> io::Result<()> {
//!     let mut f = File::open("foo.txt")?;
//!     let mut buffer = [0; 10];
//!
//!     // read up to 10 bytes
//!     let n = f.read(&mut buffer)?;
//!
//!     println!("The bytes: {:?}", &buffer[..n]);
//!     Ok(())
//! }
//! ```
//!
//! [`Read`] and [`Write`] are so important, implementors of the two traits have a
//! nickname: readers and writers. So you'll sometimes see 'a reader' instead
//! of 'a type that implements the [`Read`] trait'. Much easier!
//!
//! ## Seek and BufRead
//!
//! Beyond that, there are two important traits that are provided: [`Seek`]
//! and [`BufRead`]. Both of these build on top of a reader to control
//! how the reading happens. [`Seek`] lets you control where the next byte is
//! coming from:
//!
//! ```no_run
//! use std::io;
//! use std::io::prelude::*;
//! use std::io::SeekFrom;
//! use std::fs::File;
//!
//! fn main() -> io::Result<()> {
//!     let mut f = File::open("foo.txt")?;
//!     let mut buffer = [0; 10];
//!
//!     // skip to the last 10 bytes of the file
//!     f.seek(SeekFrom::End(-10))?;
//!
//!     // read up to 10 bytes
//!     let n = f.read(&mut buffer)?;
//!
//!     println!("The bytes: {:?}", &buffer[..n]);
//!     Ok(())
//! }
//! ```
//!
//! [`BufRead`] uses an internal buffer to provide a number of other ways to read, but
//! to show it off, we'll need to talk about buffers in general. Keep reading!
//!
//! ## BufReader and BufWriter
//!
//! Byte-based interfaces are unwieldy and can be inefficient, as we'd need to be
//! making near-constant calls to the operating system. To help with this,
//! `std::io` comes with two structs, [`BufReader`] and [`BufWriter`], which wrap
//! readers and writers. The wrapper uses a buffer, reducing the number of
//! calls and providing nicer methods for accessing exactly what you want.
//!
//! For example, [`BufReader`] works with the [`BufRead`] trait to add extra
//! methods to any reader:
//!
//! ```no_run
//! use std::io;
//! use std::io::prelude::*;
//! use std::io::BufReader;
//! use std::fs::File;
//!
//! fn main() -> io::Result<()> {
//!     let f = File::open("foo.txt")?;
//!     let mut reader = BufReader::new(f);
//!     let mut buffer = String::new();
//!
//!     // read a line into buffer
//!     reader.read_line(&mut buffer)?;
//!
//!     println!("{buffer}");
//!     Ok(())
//! }
//! ```
//!
//! [`BufWriter`] doesn't add any new ways of writing; it just buffers every call
//! to [`write`][`Write::write`]:
//!
//! ```no_run
//! use std::io;
//! use std::io::prelude::*;
//! use std::io::BufWriter;
//! use std::fs::File;
//!
//! fn main() -> io::Result<()> {
//!     let f = File::create("foo.txt")?;
//!     {
//!         let mut writer = BufWriter::new(f);
//!
//!         // write a byte to the buffer
//!         writer.write(&[42])?;
//!
//!     } // the buffer is flushed once writer goes out of scope
//!
//!     Ok(())
//! }
//! ```
//!
//! ## Standard input and output
//!
//! A very common source of input is standard input:
//!
//! ```no_run
//! use std::io;
//!
//! fn main() -> io::Result<()> {
//!     let mut input = String::new();
//!
//!     io::stdin().read_line(&mut input)?;
//!
//!     println!("You typed: {}", input.trim());
//!     Ok(())
//! }
//! ```
//!
//! Note that you cannot use the [`?` operator] in functions that do not return
//! a [`Result<T, E>`][`Result`]. Instead, you can call [`.unwrap()`]
//! or `match` on the return value to catch any possible errors:
//!
//! ```no_run
//! use std::io;
//!
//! let mut input = String::new();
//!
//! io::stdin().read_line(&mut input).unwrap();
//! ```
//!
//! And a very common source of output is standard output:
//!
//! ```no_run
//! use std::io;
//! use std::io::prelude::*;
//!
//! fn main() -> io::Result<()> {
//!     io::stdout().write(&[42])?;
//!     Ok(())
//! }
//! ```
//!
//! Of course, using [`io::stdout`] directly is less common than something like
//! [`println!`].
//!
//! ## Iterator types
//!
//! A large number of the structures provided by `std::io` are for various
//! ways of iterating over I/O. For example, [`Lines`] is used to split over
//! lines:
//!
//! ```no_run
//! use std::io;
//! use std::io::prelude::*;
//! use std::io::BufReader;
//! use std::fs::File;
//!
//! fn main() -> io::Result<()> {
//!     let f = File::open("foo.txt")?;
//!     let reader = BufReader::new(f);
//!
//!     for line in reader.lines() {
//!         println!("{}", line?);
//!     }
//!     Ok(())
//! }
//! ```
//!
//! ## Functions
//!
//! There are a number of [functions][functions-list] that offer access to various
//! features. For example, we can use three of these functions to copy everything
//! from standard input to standard output:
//!
//! ```no_run
//! use std::io;
//!
//! fn main() -> io::Result<()> {
//!     io::copy(&mut io::stdin(), &mut io::stdout())?;
//!     Ok(())
//! }
//! ```
//!
//! [functions-list]: #functions-1
//!
//! ## io::Result
//!
//! Last, but certainly not least, is [`io::Result`]. This type is used
//! as the return type of many `std::io` functions that can cause an error, and
//! can be returned from your own functions as well. Many of the examples in this
//! module use the [`?` operator]:
//!
//! ```
//! use std::io;
//!
//! fn read_input() -> io::Result<()> {
//!     let mut input = String::new();
//!
//!     io::stdin().read_line(&mut input)?;
//!
//!     println!("You typed: {}", input.trim());
//!
//!     Ok(())
//! }
//! ```
//!
//! The return type of `read_input()`, [`io::Result<()>`][`io::Result`], is a very
//! common type for functions which don't have a 'real' return value, but do want to
//! return errors if they happen. In this case, the only purpose of this function is
//! to read the line and print it, so we use `()`.
//!
//! ## Platform-specific behavior
//!
//! Many I/O functions throughout the standard library are documented to indicate
//! what various library or syscalls they are delegated to. This is done to help
//! applications both understand what's happening under the hood as well as investigate
//! any possibly unclear semantics. Note, however, that this is informative, not a binding
//! contract. The implementation of many of these functions are subject to change over
//! time and may call fewer or more syscalls/library functions.
//!
//! ## I/O Safety
//!
//! Rust follows an I/O safety discipline that is comparable to its memory safety discipline. This
//! means that file descriptors can be *exclusively owned*. (Here, "file descriptor" is meant to
//! subsume similar concepts that exist across a wide range of operating systems even if they might
//! use a different name, such as "handle".) An exclusively owned file descriptor is one that no
//! other code is allowed to access in any way, but the owner is allowed to access and even close
//! it any time. A type that owns its file descriptor should usually close it in its `drop`
//! function. Types like [`File`] own their file descriptor. Similarly, file descriptors
//! can be *borrowed*, granting the temporary right to perform operations on this file descriptor.
//! This indicates that the file descriptor will not be closed for the lifetime of the borrow, but
//! it does *not* imply any right to close this file descriptor, since it will likely be owned by
//! someone else.
//!
//! The platform-specific parts of the Rust standard library expose types that reflect these
//! concepts, see [`os::unix`] and [`os::windows`].
//!
//! To uphold I/O safety, it is crucial that no code acts on file descriptors it does not own or
//! borrow, and no code closes file descriptors it does not own. In other words, a safe function
//! that takes a regular integer, treats it as a file descriptor, and acts on it, is *unsound*.
//!
//! Not upholding I/O safety and acting on a file descriptor without proof of ownership can lead to
//! misbehavior and even Undefined Behavior in code that relies on ownership of its file
//! descriptors: a closed file descriptor could be re-allocated, so the original owner of that file
//! descriptor is now working on the wrong file. Some code might even rely on fully encapsulating
//! its file descriptors with no operations being performed by any other part of the program.
//!
//! Note that exclusive ownership of a file descriptor does *not* imply exclusive ownership of the
//! underlying kernel object that the file descriptor references (also called "open file description" on
//! some operating systems). File descriptors basically work like [`Arc`]: when you receive an owned
//! file descriptor, you cannot know whether there are any other file descriptors that reference the
//! same kernel object. However, when you create a new kernel object, you know that you are holding
//! the only reference to it. Just be careful not to lend it to anyone, since they can obtain a
//! clone and then you can no longer know what the reference count is! In that sense, [`OwnedFd`] is
//! like `Arc` and [`BorrowedFd<'a>`] is like `&'a Arc` (and similar for the Windows types). In
//! particular, given a `BorrowedFd<'a>`, you are not allowed to close the file descriptor -- just
//! like how, given a `&'a Arc`, you are not allowed to decrement the reference count and
//! potentially free the underlying object. There is no equivalent to `Box` for file descriptors in
//! the standard library (that would be a type that guarantees that the reference count is `1`),
//! however, it would be possible for a crate to define a type with those semantics.
//!
//! [`File`]: crate::fs::File
//! [`TcpStream`]: crate::net::TcpStream
//! [`io::stdout`]: stdout
//! [`io::Result`]: self::Result
//! [`?` operator]: ../../book/appendix-02-operators.html
//! [`Result`]: crate::result::Result
//! [`.unwrap()`]: crate::result::Result::unwrap
//! [`os::unix`]: ../os/unix/io/index.html
//! [`os::windows`]: ../os/windows/io/index.html
//! [`OwnedFd`]: ../os/fd/struct.OwnedFd.html
//! [`BorrowedFd<'a>`]: ../os/fd/struct.BorrowedFd.html
//! [`Arc`]: crate::sync::Arc

#![stable(feature = "rust1", since = "1.0.0")]

#[cfg(test)]
mod tests;

#[unstable(feature = "read_buf", issue = "78485")]
pub use core::io::{BorrowedBuf, BorrowedCursor};
use core::slice::memchr;

#[stable(feature = "bufwriter_into_parts", since = "1.56.0")]
pub use self::buffered::WriterPanicked;
#[unstable(feature = "raw_os_error_ty", issue = "107792")]
pub use self::error::RawOsError;
#[doc(hidden)]
#[unstable(feature = "io_const_error_internals", issue = "none")]
pub use self::error::SimpleMessage;
#[unstable(feature = "io_const_error", issue = "133448")]
pub use self::error::const_error;
#[stable(feature = "anonymous_pipe", since = "1.87.0")]
pub use self::pipe::{PipeReader, PipeWriter, pipe};
#[stable(feature = "is_terminal", since = "1.70.0")]
pub use self::stdio::IsTerminal;
pub(crate) use self::stdio::attempt_print_to_stderr;
#[unstable(feature = "print_internals", issue = "none")]
#[doc(hidden)]
pub use self::stdio::{_eprint, _print};
#[unstable(feature = "internal_output_capture", issue = "none")]
#[doc(no_inline, hidden)]
pub use self::stdio::{set_output_capture, try_set_output_capture};
#[stable(feature = "rust1", since = "1.0.0")]
pub use self::{
    buffered::{BufReader, BufWriter, IntoInnerError, LineWriter},
    copy::copy,
    cursor::Cursor,
    error::{Error, ErrorKind, Result},
    stdio::{Stderr, StderrLock, Stdin, StdinLock, Stdout, StdoutLock, stderr, stdin, stdout},
    util::{Empty, Repeat, Sink, empty, repeat, sink},
};
use crate::mem::{MaybeUninit, take};
use crate::ops::{Deref, DerefMut};
use crate::{cmp, fmt, slice, str, sys};

mod buffered;
pub(crate) mod copy;
mod cursor;
mod error;
mod impls;
mod pipe;
pub mod prelude;
mod stdio;
mod util;

const DEFAULT_BUF_SIZE: usize = crate::sys::io::DEFAULT_BUF_SIZE;

pub(crate) use stdio::cleanup;

struct Guard<'a> {
    buf: &'a mut Vec<u8>,
    len: usize,
}

impl Drop for Guard<'_> {
    fn drop(&mut self) {
        unsafe {
            self.buf.set_len(self.len);
        }
    }
}

// Several `read_to_string` and `read_line` methods in the standard library will
// append data into a `String` buffer, but we need to be pretty careful when
// doing this. The implementation will just call `.as_mut_vec()` and then
// delegate to a byte-oriented reading method, but we must ensure that when
// returning we never leave `buf` in a state such that it contains invalid UTF-8
// in its bounds.
//
// To this end, we use an RAII guard (to protect against panics) which updates
// the length of the string when it is dropped. This guard initially truncates
// the string to the prior length and only after we've validated that the
// new contents are valid UTF-8 do we allow it to set a longer length.
//
// The unsafety in this function is twofold:
//
// 1. We're looking at the raw bytes of `buf`, so we take on the burden of UTF-8
//    checks.
// 2. We're passing a raw buffer to the function `f`, and it is expected that
//    the function only *appends* bytes to the buffer. We'll get undefined
//    behavior if existing bytes are overwritten to have non-UTF-8 data.
pub(crate) unsafe fn append_to_string<F>(buf: &mut String, f: F) -> Result<usize>
where
    F: FnOnce(&mut Vec<u8>) -> Result<usize>,
{
    let mut g = Guard { len: buf.len(), buf: unsafe { buf.as_mut_vec() } };
    let ret = f(g.buf);

    // SAFETY: the caller promises to only append data to `buf`
    let appended = unsafe { g.buf.get_unchecked(g.len..) };
    if str::from_utf8(appended).is_err() {
        ret.and_then(|_| Err(Error::INVALID_UTF8))
    } else {
        g.len = g.buf.len();
        ret
    }
}

// Here we must serve many masters with conflicting goals:
//
// - avoid allocating unless necessary
// - avoid overallocating if we know the exact size (#89165)
// - avoid passing large buffers to readers that always initialize the free capacity if they perform short reads (#23815, #23820)
// - pass large buffers to readers that do not initialize the spare capacity. this can amortize per-call overheads
// - and finally pass not-too-small and not-too-large buffers to Windows read APIs because they manage to suffer from both problems
//   at the same time, i.e. small reads suffer from syscall overhead, all reads incur costs proportional to buffer size (#110650)
//
pub(crate) fn default_read_to_end<R: Read + ?Sized>(
    r: &mut R,
    buf: &mut Vec<u8>,
    size_hint: Option<usize>,
) -> Result<usize> {
    let start_len = buf.len();
    let start_cap = buf.capacity();
    // Optionally limit the maximum bytes read on each iteration.
    // This adds an arbitrary fiddle factor to allow for more data than we expect.
    let mut max_read_size = size_hint
        .and_then(|s| s.checked_add(1024)?.checked_next_multiple_of(DEFAULT_BUF_SIZE))
        .unwrap_or(DEFAULT_BUF_SIZE);

    let mut initialized = 0; // Extra initialized bytes from previous loop iteration

    const PROBE_SIZE: usize = 32;

    fn small_probe_read<R: Read + ?Sized>(r: &mut R, buf: &mut Vec<u8>) -> Result<usize> {
        let mut probe = [0u8; PROBE_SIZE];

        loop {
            match r.read(&mut probe) {
                Ok(n) => {
                    // there is no way to recover from allocation failure here
                    // because the data has already been read.
                    buf.extend_from_slice(&probe[..n]);
                    return Ok(n);
                }
                Err(ref e) if e.is_interrupted() => continue,
                Err(e) => return Err(e),
            }
        }
    }

    // avoid inflating empty/small vecs before we have determined that there's anything to read
    if (size_hint.is_none() || size_hint == Some(0)) && buf.capacity() - buf.len() < PROBE_SIZE {
        let read = small_probe_read(r, buf)?;

        if read == 0 {
            return Ok(0);
        }
    }

    let mut consecutive_short_reads = 0;

    loop {
        if buf.len() == buf.capacity() && buf.capacity() == start_cap {
            // The buffer might be an exact fit. Let's read into a probe buffer
            // and see if it returns `Ok(0)`. If so, we've avoided an
            // unnecessary doubling of the capacity. But if not, append the
            // probe buffer to the primary buffer and let its capacity grow.
            let read = small_probe_read(r, buf)?;

            if read == 0 {
                return Ok(buf.len() - start_len);
            }
        }

        if buf.len() == buf.capacity() {
            // buf is full, need more space
            buf.try_reserve(PROBE_SIZE)?;
        }

        let mut spare = buf.spare_capacity_mut();
        let buf_len = cmp::min(spare.len(), max_read_size);
        spare = &mut spare[..buf_len];
        let mut read_buf: BorrowedBuf<'_> = spare.into();

        // SAFETY: These bytes were initialized but not filled in the previous loop
        unsafe {
            read_buf.set_init(initialized);
        }

        let mut cursor = read_buf.unfilled();
        let result = loop {
            match r.read_buf(cursor.reborrow()) {
                Err(e) if e.is_interrupted() => continue,
                // Do not stop now in case of error: we might have received both data
                // and an error
                res => break res,
            }
        };

        let unfilled_but_initialized = cursor.init_mut().len();
        let bytes_read = cursor.written();
        let was_fully_initialized = read_buf.init_len() == buf_len;

        // SAFETY: BorrowedBuf's invariants mean this much memory is initialized.
        unsafe {
            let new_len = bytes_read + buf.len();
            buf.set_len(new_len);
        }

        // Now that all data is pushed to the vector, we can fail without data loss
        result?;

        if bytes_read == 0 {
            return Ok(buf.len() - start_len);
        }

        if bytes_read < buf_len {
            consecutive_short_reads += 1;
        } else {
            consecutive_short_reads = 0;
        }

        // store how much was initialized but not filled
        initialized = unfilled_but_initialized;

        // Use heuristics to determine the max read size if no initial size hint was provided
        if size_hint.is_none() {
            // The reader is returning short reads but it doesn't call ensure_init().
            // In that case we no longer need to restrict read sizes to avoid
            // initialization costs.
            // When reading from disk we usually don't get any short reads except at EOF.
            // So we wait for at least 2 short reads before uncapping the read buffer;
            // this helps with the Windows issue.
            if !was_fully_initialized && consecutive_short_reads > 1 {
                max_read_size = usize::MAX;
            }

            // we have passed a larger buffer than previously and the
            // reader still hasn't returned a short read
            if buf_len >= max_read_size && bytes_read == buf_len {
                max_read_size = max_read_size.saturating_mul(2);
            }
        }
    }
}

pub(crate) fn default_read_to_string<R: Read + ?Sized>(
    r: &mut R,
    buf: &mut String,
    size_hint: Option<usize>,
) -> Result<usize> {
    // Note that we do *not* call `r.read_to_end()` here. We are passing
    // `&mut Vec<u8>` (the raw contents of `buf`) into the `read_to_end`
    // method to fill it up. An arbitrary implementation could overwrite the
    // entire contents of the vector, not just append to it (which is what
    // we are expecting).
    //
    // To prevent extraneously checking the UTF-8-ness of the entire buffer
    // we pass it to our hardcoded `default_read_to_end` implementation which
    // we know is guaranteed to only read data into the end of the buffer.
    unsafe { append_to_string(buf, |b| default_read_to_end(r, b, size_hint)) }
}

pub(crate) fn default_read_vectored<F>(read: F, bufs: &mut [IoSliceMut<'_>]) -> Result<usize>
where
    F: FnOnce(&mut [u8]) -> Result<usize>,
{
    let buf = bufs.iter_mut().find(|b| !b.is_empty()).map_or(&mut [][..], |b| &mut **b);
    read(buf)
}

pub(crate) fn default_write_vectored<F>(write: F, bufs: &[IoSlice<'_>]) -> Result<usize>
where
    F: FnOnce(&[u8]) -> Result<usize>,
{
    let buf = bufs.iter().find(|b| !b.is_empty()).map_or(&[][..], |b| &**b);
    write(buf)
}

pub(crate) fn default_read_exact<R: Read + ?Sized>(this: &mut R, mut buf: &mut [u8]) -> Result<()> {
    while !buf.is_empty() {
        match this.read(buf) {
            Ok(0) => break,
            Ok(n) => {
                buf = &mut buf[n..];
            }
            Err(ref e) if e.is_interrupted() => {}
            Err(e) => return Err(e),
        }
    }
    if !buf.is_empty() { Err(Error::READ_EXACT_EOF) } else { Ok(()) }
}

pub(crate) fn default_read_buf<F>(read: F, mut cursor: BorrowedCursor<'_>) -> Result<()>
where
    F: FnOnce(&mut [u8]) -> Result<usize>,
{
    let n = read(cursor.ensure_init().init_mut())?;
    cursor.advance(n);
    Ok(())
}

pub(crate) fn default_read_buf_exact<R: Read + ?Sized>(
    this: &mut R,
    mut cursor: BorrowedCursor<'_>,
) -> Result<()> {
    while cursor.capacity() > 0 {
        let prev_written = cursor.written();
        match this.read_buf(cursor.reborrow()) {
            Ok(()) => {}
            Err(e) if e.is_interrupted() => continue,
            Err(e) => return Err(e),
        }

        if cursor.written() == prev_written {
            return Err(Error::READ_EXACT_EOF);
        }
    }

    Ok(())
}

pub(crate) fn default_write_fmt<W: Write + ?Sized>(
    this: &mut W,
    args: fmt::Arguments<'_>,
) -> Result<()> {
    // Create a shim which translates a `Write` to a `fmt::Write` and saves off
    // I/O errors, instead of discarding them.
    struct Adapter<'a, T: ?Sized + 'a> {
        inner: &'a mut T,
        error: Result<()>,
    }

    impl<T: Write + ?Sized> fmt::Write for Adapter<'_, T> {
        fn write_str(&mut self, s: &str) -> fmt::Result {
            match self.inner.write_all(s.as_bytes()) {
                Ok(()) => Ok(()),
                Err(e) => {
                    self.error = Err(e);
                    Err(fmt::Error)
                }
            }
        }
    }

    let mut output = Adapter { inner: this, error: Ok(()) };
    match fmt::write(&mut output, args) {
        Ok(()) => Ok(()),
        Err(..) => {
            // Check whether the error came from the underlying `Write`.
            if output.error.is_err() {
                output.error
            } else {
                // This shouldn't happen: the underlying stream did not error,
                // but somehow the formatter still errored?
                panic!(
                    "a formatting trait implementation returned an error when the underlying stream did not"
                );
            }
        }
    }
}

/// The `Read` trait allows for reading bytes from a source.
///
/// Implementors of the `Read` trait are called 'readers'.
///
/// Readers are defined by one required method, [`read()`]. Each call to [`read()`]
/// will attempt to pull bytes from this source into a provided buffer. A
/// number of other methods are implemented in terms of [`read()`], giving
/// implementors a number of ways to read bytes while only needing to implement
/// a single method.
///
/// Readers are intended to be composable with one another. Many implementors
/// throughout [`std::io`] take and provide types which implement the `Read`
/// trait.
///
/// Please note that each call to [`read()`] may involve a system call, and
/// therefore, using something that implements [`BufRead`], such as
/// [`BufReader`], will be more efficient.
///
/// Repeated calls to the reader use the same cursor, so for example
/// calling `read_to_end` twice on a [`File`] will only return the file's
/// contents once. It's recommended to first call `rewind()` in that case.
///
/// # Examples
///
/// [`File`]s implement `Read`:
///
/// ```no_run
/// use std::io;
/// use std::io::prelude::*;
/// use std::fs::File;
///
/// fn main() -> io::Result<()> {
///     let mut f = File::open("foo.txt")?;
///     let mut buffer = [0; 10];
///
///     // read up to 10 bytes
///     f.read(&mut buffer)?;
///
///     let mut buffer = Vec::new();
///     // read the whole file
///     f.read_to_end(&mut buffer)?;
///
///     // read into a String, so that you don't need to do the conversion.
///     let mut buffer = String::new();
///     f.read_to_string(&mut buffer)?;
///
///     // and more! See the other methods for more details.
///     Ok(())
/// }
/// ```
///
/// Read from [`&str`] because [`&[u8]`][prim@slice] implements `Read`:
///
/// ```no_run
/// # use std::io;
/// use std::io::prelude::*;
///
/// fn main() -> io::Result<()> {
///     let mut b = "This string will be read".as_bytes();
///     let mut buffer = [0; 10];
///
///     // read up to 10 bytes
///     b.read(&mut buffer)?;
///
///     // etc... it works exactly as a File does!
///     Ok(())
/// }
/// ```
///
/// [`read()`]: Read::read
/// [`&str`]: prim@str
/// [`std::io`]: self
/// [`File`]: crate::fs::File
#[stable(feature = "rust1", since = "1.0.0")]
#[doc(notable_trait)]
#[cfg_attr(not(test), rustc_diagnostic_item = "IoRead")]
pub trait Read {
    /// Pull some bytes from this source into the specified buffer, returning
    /// how many bytes were read.
    ///
    /// This function does not provide any guarantees about whether it blocks
    /// waiting for data, but if an object needs to block for a read and cannot,
    /// it will typically signal this via an [`Err`] return value.
    ///
    /// If the return value of this method is [`Ok(n)`], then implementations must
    /// guarantee that `0 <= n <= buf.len()`. A nonzero `n` value indicates
    /// that the buffer `buf` has been filled in with `n` bytes of data from this
    /// source. If `n` is `0`, then it can indicate one of two scenarios:
    ///
    /// 1. This reader has reached its "end of file" and will likely no longer
    ///    be able to produce bytes. Note that this does not mean that the
    ///    reader will *always* no longer be able to produce bytes. As an example,
    ///    on Linux, this method will call the `recv` syscall for a [`TcpStream`],
    ///    where returning zero indicates the connection was shut down correctly. While
    ///    for [`File`], it is possible to reach the end of file and get zero as result,
    ///    but if more data is appended to the file, future calls to `read` will return
    ///    more data.
    /// 2. The buffer specified was 0 bytes in length.
    ///
    /// It is not an error if the returned value `n` is smaller than the buffer size,
    /// even when the reader is not at the end of the stream yet.
    /// This may happen for example because fewer bytes are actually available right now
    /// (e. g. being close to end-of-file) or because read() was interrupted by a signal.
    ///
    /// As this trait is safe to implement, callers in unsafe code cannot rely on
    /// `n <= buf.len()` for safety.
    /// Extra care needs to be taken when `unsafe` functions are used to access the read bytes.
    /// Callers have to ensure that no unchecked out-of-bounds accesses are possible even if
    /// `n > buf.len()`.
    ///
    /// *Implementations* of this method can make no assumptions about the contents of `buf` when
    /// this function is called. It is recommended that implementations only write data to `buf`
    /// instead of reading its contents.
    ///
    /// Correspondingly, however, *callers* of this method in unsafe code must not assume
    /// any guarantees about how the implementation uses `buf`. The trait is safe to implement,
    /// so it is possible that the code that's supposed to write to the buffer might also read
    /// from it. It is your responsibility to make sure that `buf` is initialized
    /// before calling `read`. Calling `read` with an uninitialized `buf` (of the kind one
    /// obtains via [`MaybeUninit<T>`]) is not safe, and can lead to undefined behavior.
    ///
    /// [`MaybeUninit<T>`]: crate::mem::MaybeUninit
    ///
    /// # Errors
    ///
    /// If this function encounters any form of I/O or other error, an error
    /// variant will be returned. If an error is returned then it must be
    /// guaranteed that no bytes were read.
    ///
    /// An error of the [`ErrorKind::Interrupted`] kind is non-fatal and the read
    /// operation should be retried if there is nothing else to do.
    ///
    /// # Examples
    ///
    /// [`File`]s implement `Read`:
    ///
    /// [`Ok(n)`]: Ok
    /// [`File`]: crate::fs::File
    /// [`TcpStream`]: crate::net::TcpStream
    ///
    /// ```no_run
    /// use std::io;
    /// use std::io::prelude::*;
    /// use std::fs::File;
    ///
    /// fn main() -> io::Result<()> {
    ///     let mut f = File::open("foo.txt")?;
    ///     let mut buffer = [0; 10];
    ///
    ///     // read up to 10 bytes
    ///     let n = f.read(&mut buffer[..])?;
    ///
    ///     println!("The bytes: {:?}", &buffer[..n]);
    ///     Ok(())
    /// }
    /// ```
    #[stable(feature = "rust1", since = "1.0.0")]
    fn read(&mut self, buf: &mut [u8]) -> Result<usize>;

    /// Like `read`, except that it reads into a slice of buffers.
    ///
    /// Data is copied to fill each buffer in order, with the final buffer
    /// written to possibly being only partially filled. This method must
    /// behave equivalently to a single call to `read` with concatenated
    /// buffers.
    ///
    /// The default implementation calls `read` with either the first nonempty
    /// buffer provided, or an empty one if none exists.
    #[stable(feature = "iovec", since = "1.36.0")]
    fn read_vectored(&mut self, bufs: &mut [IoSliceMut<'_>]) -> Result<usize> {
        default_read_vectored(|b| self.read(b), bufs)
    }

    /// Determines if this `Read`er has an efficient `read_vectored`
    /// implementation.
    ///
    /// If a `Read`er does not override the default `read_vectored`
    /// implementation, code using it may want to avoid the method all together
    /// and coalesce writes into a single buffer for higher performance.
    ///
    /// The default implementation returns `false`.
    #[unstable(feature = "can_vector", issue = "69941")]
    fn is_read_vectored(&self) -> bool {
        false
    }

    /// Reads all bytes until EOF in this source, placing them into `buf`.
    ///
    /// All bytes read from this source will be appended to the specified buffer
    /// `buf`. This function will continuously call [`read()`] to append more data to
    /// `buf` until [`read()`] returns either [`Ok(0)`] or an error of
    /// non-[`ErrorKind::Interrupted`] kind.
    ///
    /// If successful, this function will return the total number of bytes read.
    ///
    /// # Errors
    ///
    /// If this function encounters an error of the kind
    /// [`ErrorKind::Interrupted`] then the error is ignored and the operation
    /// will continue.
    ///
    /// If any other read error is encountered then this function immediately
    /// returns. Any bytes which have already been read will be appended to
    /// `buf`.
    ///
    /// # Examples
    ///
    /// [`File`]s implement `Read`:
    ///
    /// [`read()`]: Read::read
    /// [`Ok(0)`]: Ok
    /// [`File`]: crate::fs::File
    ///
    /// ```no_run
    /// use std::io;
    /// use std::io::prelude::*;
    /// use std::fs::File;
    ///
    /// fn main() -> io::Result<()> {
    ///     let mut f = File::open("foo.txt")?;
    ///     let mut buffer = Vec::new();
    ///
    ///     // read the whole file
    ///     f.read_to_end(&mut buffer)?;
    ///     Ok(())
    /// }
    /// ```
    ///
    /// (See also the [`std::fs::read`] convenience function for reading from a
    /// file.)
    ///
    /// [`std::fs::read`]: crate::fs::read
    ///
    /// ## Implementing `read_to_end`
    ///
    /// When implementing the `io::Read` trait, it is recommended to allocate
    /// memory using [`Vec::try_reserve`]. However, this behavior is not guaranteed
    /// by all implementations, and `read_to_end` may not handle out-of-memory
    /// situations gracefully.
    ///
    /// ```no_run
    /// # use std::io::{self, BufRead};
    /// # struct Example { example_datasource: io::Empty } impl Example {
    /// # fn get_some_data_for_the_example(&self) -> &'static [u8] { &[] }
    /// fn read_to_end(&mut self, dest_vec: &mut Vec<u8>) -> io::Result<usize> {
    ///     let initial_vec_len = dest_vec.len();
    ///     loop {
    ///         let src_buf = self.example_datasource.fill_buf()?;
    ///         if src_buf.is_empty() {
    ///             break;
    ///         }
    ///         dest_vec.try_reserve(src_buf.len())?;
    ///         dest_vec.extend_from_slice(src_buf);
    ///
    ///         // Any irreversible side effects should happen after `try_reserve` succeeds,
    ///         // to avoid losing data on allocation error.
    ///         let read = src_buf.len();
    ///         self.example_datasource.consume(read);
    ///     }
    ///     Ok(dest_vec.len() - initial_vec_len)
    /// }
    /// # }
    /// ```
    ///
    /// # Usage Notes
    ///
    /// `read_to_end` attempts to read a source until EOF, but many sources are continuous streams
    /// that do not send EOF. In these cases, `read_to_end` will block indefinitely. Standard input
    /// is one such stream which may be finite if piped, but is typically continuous. For example,
    /// `cat file | my-rust-program` will correctly terminate with an `EOF` upon closure of cat.
    /// Reading user input or running programs that remain open indefinitely will never terminate
    /// the stream with `EOF` (e.g. `yes | my-rust-program`).
    ///
    /// Using `.lines()` with a [`BufReader`] or using [`read`] can provide a better solution
    ///
    ///[`read`]: Read::read
    ///
    /// [`Vec::try_reserve`]: crate::vec::Vec::try_reserve
    #[stable(feature = "rust1", since = "1.0.0")]
    fn read_to_end(&mut self, buf: &mut Vec<u8>) -> Result<usize> {
        default_read_to_end(self, buf, None)
    }

    /// Reads all bytes until EOF in this source, appending them to `buf`.
    ///
    /// If successful, this function returns the number of bytes which were read
    /// and appended to `buf`.
    ///
    /// # Errors
    ///
    /// If the data in this stream is *not* valid UTF-8 then an error is
    /// returned and `buf` is unchanged.
    ///
    /// See [`read_to_end`] for other error semantics.
    ///
    /// [`read_to_end`]: Read::read_to_end
    ///
    /// # Examples
    ///
    /// [`File`]s implement `Read`:
    ///
    /// [`File`]: crate::fs::File
    ///
    /// ```no_run
    /// use std::io;
    /// use std::io::prelude::*;
    /// use std::fs::File;
    ///
    /// fn main() -> io::Result<()> {
    ///     let mut f = File::open("foo.txt")?;
    ///     let mut buffer = String::new();
    ///
    ///     f.read_to_string(&mut buffer)?;
    ///     Ok(())
    /// }
    /// ```
    ///
    /// (See also the [`std::fs::read_to_string`] convenience function for
    /// reading from a file.)
    ///
    /// # Usage Notes
    ///
    /// `read_to_string` attempts to read a source until EOF, but many sources are continuous streams
    /// that do not send EOF. In these cases, `read_to_string` will block indefinitely. Standard input
    /// is one such stream which may be finite if piped, but is typically continuous. For example,
    /// `cat file | my-rust-program` will correctly terminate with an `EOF` upon closure of cat.
    /// Reading user input or running programs that remain open indefinitely will never terminate
    /// the stream with `EOF` (e.g. `yes | my-rust-program`).
    ///
    /// Using `.lines()` with a [`BufReader`] or using [`read`] can provide a better solution
    ///
    ///[`read`]: Read::read
    ///
    /// [`std::fs::read_to_string`]: crate::fs::read_to_string
    #[stable(feature = "rust1", since = "1.0.0")]
    fn read_to_string(&mut self, buf: &mut String) -> Result<usize> {
        default_read_to_string(self, buf, None)
    }

    /// Reads the exact number of bytes required to fill `buf`.
    ///
    /// This function reads as many bytes as necessary to completely fill the
    /// specified buffer `buf`.
    ///
    /// *Implementations* of this method can make no assumptions about the contents of `buf` when
    /// this function is called. It is recommended that implementations only write data to `buf`
    /// instead of reading its contents. The documentation on [`read`] has a more detailed
    /// explanation of this subject.
    ///
    /// # Errors
    ///
    /// If this function encounters an error of the kind
    /// [`ErrorKind::Interrupted`] then the error is ignored and the operation
    /// will continue.
    ///
    /// If this function encounters an "end of file" before completely filling
    /// the buffer, it returns an error of the kind [`ErrorKind::UnexpectedEof`].
    /// The contents of `buf` are unspecified in this case.
    ///
    /// If any other read error is encountered then this function immediately
    /// returns. The contents of `buf` are unspecified in this case.
    ///
    /// If this function returns an error, it is unspecified how many bytes it
    /// has read, but it will never read more than would be necessary to
    /// completely fill the buffer.
    ///
    /// # Examples
    ///
    /// [`File`]s implement `Read`:
    ///
    /// [`read`]: Read::read
    /// [`File`]: crate::fs::File
    ///
    /// ```no_run
    /// use std::io;
    /// use std::io::prelude::*;
    /// use std::fs::File;
    ///
    /// fn main() -> io::Result<()> {
    ///     let mut f = File::open("foo.txt")?;
    ///     let mut buffer = [0; 10];
    ///
    ///     // read exactly 10 bytes
    ///     f.read_exact(&mut buffer)?;
    ///     Ok(())
    /// }
    /// ```
    #[stable(feature = "read_exact", since = "1.6.0")]
    fn read_exact(&mut self, buf: &mut [u8]) -> Result<()> {
        default_read_exact(self, buf)
    }

    /// Pull some bytes from this source into the specified buffer.
    ///
    /// This is equivalent to the [`read`](Read::read) method, except that it is passed a [`BorrowedCursor`] rather than `[u8]` to allow use
    /// with uninitialized buffers. The new data will be appended to any existing contents of `buf`.
    ///
    /// The default implementation delegates to `read`.
    ///
    /// This method makes it possible to return both data and an error but it is advised against.
    #[unstable(feature = "read_buf", issue = "78485")]
    fn read_buf(&mut self, buf: BorrowedCursor<'_>) -> Result<()> {
        default_read_buf(|b| self.read(b), buf)
    }

    /// Reads the exact number of bytes required to fill `cursor`.
    ///
    /// This is similar to the [`read_exact`](Read::read_exact) method, except
    /// that it is passed a [`BorrowedCursor`] rather than `[u8]` to allow use
    /// with uninitialized buffers.
    ///
    /// # Errors
    ///
    /// If this function encounters an error of the kind [`ErrorKind::Interrupted`]
    /// then the error is ignored and the operation will continue.
    ///
    /// If this function encounters an "end of file" before completely filling
    /// the buffer, it returns an error of the kind [`ErrorKind::UnexpectedEof`].
    ///
    /// If any other read error is encountered then this function immediately
    /// returns.
    ///
    /// If this function returns an error, all bytes read will be appended to `cursor`.
    #[unstable(feature = "read_buf", issue = "78485")]
    fn read_buf_exact(&mut self, cursor: BorrowedCursor<'_>) -> Result<()> {
        default_read_buf_exact(self, cursor)
    }

    /// Creates a "by reference" adapter for this instance of `Read`.
    ///
    /// The returned adapter also implements `Read` and will simply borrow this
    /// current reader.
    ///
    /// # Examples
    ///
    /// [`File`]s implement `Read`:
    ///
    /// [`File`]: crate::fs::File
    ///
    /// ```no_run
    /// use std::io;
    /// use std::io::Read;
    /// use std::fs::File;
    ///
    /// fn main() -> io::Result<()> {
    ///     let mut f = File::open("foo.txt")?;
    ///     let mut buffer = Vec::new();
    ///     let mut other_buffer = Vec::new();
    ///
    ///     {
    ///         let reference = f.by_ref();
    ///
    ///         // read at most 5 bytes
    ///         reference.take(5).read_to_end(&mut buffer)?;
    ///
    ///     } // drop our &mut reference so we can use f again
    ///
    ///     // original file still usable, read the rest
    ///     f.read_to_end(&mut other_buffer)?;
    ///     Ok(())
    /// }
    /// ```
    #[stable(feature = "rust1", since = "1.0.0")]
    fn by_ref(&mut self) -> &mut Self
    where
        Self: Sized,
    {
        self
    }

    /// Transforms this `Read` instance to an [`Iterator`] over its bytes.
    ///
    /// The returned type implements [`Iterator`] where the [`Item`] is
    /// <code>[Result]<[u8], [io::Error]></code>.
    /// The yielded item is [`Ok`] if a byte was successfully read and [`Err`]
    /// otherwise. EOF is mapped to returning [`None`] from this iterator.
    ///
    /// The default implementation calls `read` for each byte,
    /// which can be very inefficient for data that's not in memory,
    /// such as [`File`]. Consider using a [`BufReader`] in such cases.
    ///
    /// # Examples
    ///
    /// [`File`]s implement `Read`:
    ///
    /// [`Item`]: Iterator::Item
    /// [`File`]: crate::fs::File "fs::File"
    /// [Result]: crate::result::Result "Result"
    /// [io::Error]: self::Error "io::Error"
    ///
    /// ```no_run
    /// use std::io;
    /// use std::io::prelude::*;
    /// use std::io::BufReader;
    /// use std::fs::File;
    ///
    /// fn main() -> io::Result<()> {
    ///     let f = BufReader::new(File::open("foo.txt")?);
    ///
    ///     for byte in f.bytes() {
    ///         println!("{}", byte?);
    ///     }
    ///     Ok(())
    /// }
    /// ```
    #[stable(feature = "rust1", since = "1.0.0")]
    fn bytes(self) -> Bytes<Self>
    where
        Self: Sized,
    {
        Bytes { inner: self }
    }

    /// Creates an adapter which will chain this stream with another.
    ///
    /// The returned `Read` instance will first read all bytes from this object
    /// until EOF is encountered. Afterwards the output is equivalent to the
    /// output of `next`.
    ///
    /// # Examples
    ///
    /// [`File`]s implement `Read`:
    ///
    /// [`File`]: crate::fs::File
    ///
    /// ```no_run
    /// use std::io;
    /// use std::io::prelude::*;
    /// use std::fs::File;
    ///
    /// fn main() -> io::Result<()> {
    ///     let f1 = File::open("foo.txt")?;
    ///     let f2 = File::open("bar.txt")?;
    ///
    ///     let mut handle = f1.chain(f2);
    ///     let mut buffer = String::new();
    ///
    ///     // read the value into a String. We could use any Read method here,
    ///     // this is just one example.
    ///     handle.read_to_string(&mut buffer)?;
    ///     Ok(())
    /// }
    /// ```
    #[stable(feature = "rust1", since = "1.0.0")]
    fn chain<R: Read>(self, next: R) -> Chain<Self, R>
    where
        Self: Sized,
    {
        Chain { first: self, second: next, done_first: false }
    }

    /// Creates an adapter which will read at most `limit` bytes from it.
    ///
    /// This function returns a new instance of `Read` which will read at most
    /// `limit` bytes, after which it will always return EOF ([`Ok(0)`]). Any
    /// read errors will not count towards the number of bytes read and future
    /// calls to [`read()`] may succeed.
    ///
    /// # Examples
    ///
    /// [`File`]s implement `Read`:
    ///
    /// [`File`]: crate::fs::File
    /// [`Ok(0)`]: Ok
    /// [`read()`]: Read::read
    ///
    /// ```no_run
    /// use std::io;
    /// use std::io::prelude::*;
    /// use std::fs::File;
    ///
    /// fn main() -> io::Result<()> {
    ///     let f = File::open("foo.txt")?;
    ///     let mut buffer = [0; 5];
    ///
    ///     // read at most five bytes
    ///     let mut handle = f.take(5);
    ///
    ///     handle.read(&mut buffer)?;
    ///     Ok(())
    /// }
    /// ```
    #[stable(feature = "rust1", since = "1.0.0")]
    fn take(self, limit: u64) -> Take<Self>
    where
        Self: Sized,
    {
        Take { inner: self, len: limit, limit }
    }

    /// Read and return a fixed array of bytes from this source.
    ///
    /// This function uses an array sized based on a const generic size known at compile time. You
    /// can specify the size with turbofish (`reader.read_array::<8>()`), or let type inference
    /// determine the number of bytes needed based on how the return value gets used. For instance,
    /// this function works well with functions like [`u64::from_le_bytes`] to turn an array of
    /// bytes into an integer of the same size.
    ///
    /// Like `read_exact`, if this function encounters an "end of file" before reading the desired
    /// number of bytes, it returns an error of the kind [`ErrorKind::UnexpectedEof`].
    ///
    /// ```
    /// #![feature(read_array)]
    /// use std::io::Cursor;
    /// use std::io::prelude::*;
    ///
    /// fn main() -> std::io::Result<()> {
    ///     let mut buf = Cursor::new([1, 2, 3, 4, 5, 6, 7, 8, 9, 8, 7, 6, 5, 4, 3, 2]);
    ///     let x = u64::from_le_bytes(buf.read_array()?);
    ///     let y = u32::from_be_bytes(buf.read_array()?);
    ///     let z = u16::from_be_bytes(buf.read_array()?);
    ///     assert_eq!(x, 0x807060504030201);
    ///     assert_eq!(y, 0x9080706);
    ///     assert_eq!(z, 0x504);
    ///     Ok(())
    /// }
    /// ```
    #[unstable(feature = "read_array", issue = "148848")]
    fn read_array<const N: usize>(&mut self) -> Result<[u8; N]>
    where
        Self: Sized,
    {
        let mut buf = [MaybeUninit::uninit(); N];
        let mut borrowed_buf = BorrowedBuf::from(buf.as_mut_slice());
        self.read_buf_exact(borrowed_buf.unfilled())?;
        // Guard against incorrect `read_buf_exact` implementations.
        assert_eq!(borrowed_buf.len(), N);
        Ok(unsafe { MaybeUninit::array_assume_init(buf) })
    }
}

/// Reads all bytes from a [reader][Read] into a new [`String`].
///
/// This is a convenience function for [`Read::read_to_string`]. Using this
/// function avoids having to create a variable first and provides more type
/// safety since you can only get the buffer out if there were no errors. (If you
/// use [`Read::read_to_string`] you have to remember to check whether the read
/// succeeded because otherwise your buffer will be empty or only partially full.)
///
/// # Performance
///
/// The downside of this function's increased ease of use and type safety is
/// that it gives you less control over performance. For example, you can't
/// pre-allocate memory like you can using [`String::with_capacity`] and
/// [`Read::read_to_string`]. Also, you can't re-use the buffer if an error
/// occurs while reading.
///
/// In many cases, this function's performance will be adequate and the ease of use
/// and type safety tradeoffs will be worth it. However, there are cases where you
/// need more control over performance, and in those cases you should definitely use
/// [`Read::read_to_string`] directly.
///
/// Note that in some special cases, such as when reading files, this function will
/// pre-allocate memory based on the size of the input it is reading. In those
/// cases, the performance should be as good as if you had used
/// [`Read::read_to_string`] with a manually pre-allocated buffer.
///
/// # Errors
///
/// This function forces you to handle errors because the output (the `String`)
/// is wrapped in a [`Result`]. See [`Read::read_to_string`] for the errors
/// that can occur. If any error occurs, you will get an [`Err`], so you
/// don't have to worry about your buffer being empty or partially full.
///
/// # Examples
///
/// ```no_run
/// # use std::io;
/// fn main() -> io::Result<()> {
///     let stdin = io::read_to_string(io::stdin())?;
///     println!("Stdin was:");
///     println!("{stdin}");
///     Ok(())
/// }
/// ```
///
/// # Usage Notes
///
/// `read_to_string` attempts to read a source until EOF, but many sources are continuous streams
/// that do not send EOF. In these cases, `read_to_string` will block indefinitely. Standard input
/// is one such stream which may be finite if piped, but is typically continuous. For example,
/// `cat file | my-rust-program` will correctly terminate with an `EOF` upon closure of cat.
/// Reading user input or running programs that remain open indefinitely will never terminate
/// the stream with `EOF` (e.g. `yes | my-rust-program`).
///
/// Using `.lines()` with a [`BufReader`] or using [`read`] can provide a better solution
///
///[`read`]: Read::read
///
#[stable(feature = "io_read_to_string", since = "1.65.0")]
pub fn read_to_string<R: Read>(mut reader: R) -> Result<String> {
    let mut buf = String::new();
    reader.read_to_string(&mut buf)?;
    Ok(buf)
}

/// A buffer type used with `Read::read_vectored`.
///
/// It is semantically a wrapper around a `&mut [u8]`, but is guaranteed to be
/// ABI compatible with the `iovec` type on Unix platforms and `WSABUF` on
/// Windows.
#[stable(feature = "iovec", since = "1.36.0")]
#[repr(transparent)]
pub struct IoSliceMut<'a>(sys::io::IoSliceMut<'a>);

#[stable(feature = "iovec_send_sync", since = "1.44.0")]
unsafe impl<'a> Send for IoSliceMut<'a> {}

#[stable(feature = "iovec_send_sync", since = "1.44.0")]
unsafe impl<'a> Sync for IoSliceMut<'a> {}

#[stable(feature = "iovec", since = "1.36.0")]
impl<'a> fmt::Debug for IoSliceMut<'a> {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self.0.as_slice(), fmt)
    }
}

impl<'a> IoSliceMut<'a> {
    /// Creates a new `IoSliceMut` wrapping a byte slice.
    ///
    /// # Panics
    ///
    /// Panics on Windows if the slice is larger than 4GB.
    #[stable(feature = "iovec", since = "1.36.0")]
    #[inline]
    pub fn new(buf: &'a mut [u8]) -> IoSliceMut<'a> {
        IoSliceMut(sys::io::IoSliceMut::new(buf))
    }

    /// Advance the internal cursor of the slice.
    ///
    /// Also see [`IoSliceMut::advance_slices`] to advance the cursors of
    /// multiple buffers.
    ///
    /// # Panics
    ///
    /// Panics when trying to advance beyond the end of the slice.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::io::IoSliceMut;
    /// use std::ops::Deref;
    ///
    /// let mut data = [1; 8];
    /// let mut buf = IoSliceMut::new(&mut data);
    ///
    /// // Mark 3 bytes as read.
    /// buf.advance(3);
    /// assert_eq!(buf.deref(), [1; 5].as_ref());
    /// ```
    #[stable(feature = "io_slice_advance", since = "1.81.0")]
    #[inline]
    pub fn advance(&mut self, n: usize) {
        self.0.advance(n)
    }

    /// Advance a slice of slices.
    ///
    /// Shrinks the slice to remove any `IoSliceMut`s that are fully advanced over.
    /// If the cursor ends up in the middle of an `IoSliceMut`, it is modified
    /// to start at that cursor.
    ///
    /// For example, if we have a slice of two 8-byte `IoSliceMut`s, and we advance by 10 bytes,
    /// the result will only include the second `IoSliceMut`, advanced by 2 bytes.
    ///
    /// # Panics
    ///
    /// Panics when trying to advance beyond the end of the slices.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::io::IoSliceMut;
    /// use std::ops::Deref;
    ///
    /// let mut buf1 = [1; 8];
    /// let mut buf2 = [2; 16];
    /// let mut buf3 = [3; 8];
    /// let mut bufs = &mut [
    ///     IoSliceMut::new(&mut buf1),
    ///     IoSliceMut::new(&mut buf2),
    ///     IoSliceMut::new(&mut buf3),
    /// ][..];
    ///
    /// // Mark 10 bytes as read.
    /// IoSliceMut::advance_slices(&mut bufs, 10);
    /// assert_eq!(bufs[0].deref(), [2; 14].as_ref());
    /// assert_eq!(bufs[1].deref(), [3; 8].as_ref());
    /// ```
    #[stable(feature = "io_slice_advance", since = "1.81.0")]
    #[inline]
    pub fn advance_slices(bufs: &mut &mut [IoSliceMut<'a>], n: usize) {
        // Number of buffers to remove.
        let mut remove = 0;
        // Remaining length before reaching n.
        let mut left = n;
        for buf in bufs.iter() {
            if let Some(remainder) = left.checked_sub(buf.len()) {
                left = remainder;
                remove += 1;
            } else {
                break;
            }
        }

        *bufs = &mut take(bufs)[remove..];
        if bufs.is_empty() {
            assert!(left == 0, "advancing io slices beyond their length");
        } else {
            bufs[0].advance(left);
        }
    }

    /// Get the underlying bytes as a mutable slice with the original lifetime.
    ///
    /// # Examples
    ///
    /// ```
    /// #![feature(io_slice_as_bytes)]
    /// use std::io::IoSliceMut;
    ///
    /// let mut data = *b"abcdef";
    /// let io_slice = IoSliceMut::new(&mut data);
    /// io_slice.into_slice()[0] = b'A';
    ///
    /// assert_eq!(&data, b"Abcdef");
    /// ```
    #[unstable(feature = "io_slice_as_bytes", issue = "132818")]
    pub const fn into_slice(self) -> &'a mut [u8] {
        self.0.into_slice()
    }
}

#[stable(feature = "iovec", since = "1.36.0")]
impl<'a> Deref for IoSliceMut<'a> {
    type Target = [u8];

    #[inline]
    fn deref(&self) -> &[u8] {
        self.0.as_slice()
    }
}

#[stable(feature = "iovec", since = "1.36.0")]
impl<'a> DerefMut for IoSliceMut<'a> {
    #[inline]
    fn deref_mut(&mut self) -> &mut [u8] {
        self.0.as_mut_slice()
    }
}

/// A buffer type used with `Write::write_vectored`.
///
/// It is semantically a wrapper around a `&[u8]`, but is guaranteed to be
/// ABI compatible with the `iovec` type on Unix platforms and `WSABUF` on
/// Windows.
#[stable(feature = "iovec", since = "1.36.0")]
#[derive(Copy, Clone)]
#[repr(transparent)]
pub struct IoSlice<'a>(sys::io::IoSlice<'a>);

#[stable(feature = "iovec_send_sync", since = "1.44.0")]
unsafe impl<'a> Send for IoSlice<'a> {}

#[stable(feature = "iovec_send_sync", since = "1.44.0")]
unsafe impl<'a> Sync for IoSlice<'a> {}

#[stable(feature = "iovec", since = "1.36.0")]
impl<'a> fmt::Debug for IoSlice<'a> {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self.0.as_slice(), fmt)
    }
}

impl<'a> IoSlice<'a> {
    /// Creates a new `IoSlice` wrapping a byte slice.
    ///
    /// # Panics
    ///
    /// Panics on Windows if the slice is larger than 4GB.
    #[stable(feature = "iovec", since = "1.36.0")]
    #[must_use]
    #[inline]
    pub fn new(buf: &'a [u8]) -> IoSlice<'a> {
        IoSlice(sys::io::IoSlice::new(buf))
    }

    /// Advance the internal cursor of the slice.
    ///
    /// Also see [`IoSlice::advance_slices`] to advance the cursors of multiple
    /// buffers.
    ///
    /// # Panics
    ///
    /// Panics when trying to advance beyond the end of the slice.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::io::IoSlice;
    /// use std::ops::Deref;
    ///
    /// let data = [1; 8];
    /// let mut buf = IoSlice::new(&data);
    ///
    /// // Mark 3 bytes as read.
    /// buf.advance(3);
    /// assert_eq!(buf.deref(), [1; 5].as_ref());
    /// ```
    #[stable(feature = "io_slice_advance", since = "1.81.0")]
    #[inline]
    pub fn advance(&mut self, n: usize) {
        self.0.advance(n)
    }

    /// Advance a slice of slices.
    ///
    /// Shrinks the slice to remove any `IoSlice`s that are fully advanced over.
    /// If the cursor ends up in the middle of an `IoSlice`, it is modified
    /// to start at that cursor.
    ///
    /// For example, if we have a slice of two 8-byte `IoSlice`s, and we advance by 10 bytes,
    /// the result will only include the second `IoSlice`, advanced by 2 bytes.
    ///
    /// # Panics
    ///
    /// Panics when trying to advance beyond the end of the slices.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::io::IoSlice;
    /// use std::ops::Deref;
    ///
    /// let buf1 = [1; 8];
    /// let buf2 = [2; 16];
    /// let buf3 = [3; 8];
    /// let mut bufs = &mut [
    ///     IoSlice::new(&buf1),
    ///     IoSlice::new(&buf2),
    ///     IoSlice::new(&buf3),
    /// ][..];
    ///
    /// // Mark 10 bytes as written.
    /// IoSlice::advance_slices(&mut bufs, 10);
    /// assert_eq!(bufs[0].deref(), [2; 14].as_ref());
    /// assert_eq!(bufs[1].deref(), [3; 8].as_ref());
    #[stable(feature = "io_slice_advance", since = "1.81.0")]
    #[inline]
    pub fn advance_slices(bufs: &mut &mut [IoSlice<'a>], n: usize) {
        // Number of buffers to remove.
        let mut remove = 0;
        // Remaining length before reaching n. This prevents overflow
        // that could happen if the length of slices in `bufs` were instead
        // accumulated. Those slice may be aliased and, if they are large
        // enough, their added length may overflow a `usize`.
        let mut left = n;
        for buf in bufs.iter() {
            if let Some(remainder) = left.checked_sub(buf.len()) {
                left = remainder;
                remove += 1;
            } else {
                break;
            }
        }

        *bufs = &mut take(bufs)[remove..];
        if bufs.is_empty() {
            assert!(left == 0, "advancing io slices beyond their length");
        } else {
            bufs[0].advance(left);
        }
    }

    /// Get the underlying bytes as a slice with the original lifetime.
    ///
    /// This doesn't borrow from `self`, so is less restrictive than calling
    /// `.deref()`, which does.
    ///
    /// # Examples
    ///
    /// ```
    /// #![feature(io_slice_as_bytes)]
    /// use std::io::IoSlice;
    ///
    /// let data = b"abcdef";
    ///
    /// let mut io_slice = IoSlice::new(data);
    /// let tail = &io_slice.as_slice()[3..];
    ///
    /// // This works because `tail` doesn't borrow `io_slice`
    /// io_slice = IoSlice::new(tail);
    ///
    /// assert_eq!(io_slice.as_slice(), b"def");
    /// ```
    #[unstable(feature = "io_slice_as_bytes", issue = "132818")]
    pub const fn as_slice(self) -> &'a [u8] {
        self.0.as_slice()
    }
}

#[stable(feature = "iovec", since = "1.36.0")]
impl<'a> Deref for IoSlice<'a> {
    type Target = [u8];

    #[inline]
    fn deref(&self) -> &[u8] {
        self.0.as_slice()
    }
}

/// A trait for objects which are byte-oriented sinks.
///
/// Implementors of the `Write` trait are sometimes called 'writers'.
///
/// Writers are defined by two required methods, [`write`] and [`flush`]:
///
/// * The [`write`] method will attempt to write some data into the object,
///   returning how many bytes were successfully written.
///
/// * The [`flush`] method is useful for adapters and explicit buffers
///   themselves for ensuring that all buffered data has been pushed out to the
///   'true sink'.
///
/// Writers are intended to be composable with one another. Many implementors
/// throughout [`std::io`] take and provide types which implement the `Write`
/// trait.
///
/// [`write`]: Write::write
/// [`flush`]: Write::flush
/// [`std::io`]: self
///
/// # Examples
///
/// ```no_run
/// use std::io::prelude::*;
/// use std::fs::File;
///
/// fn main() -> std::io::Result<()> {
///     let data = b"some bytes";
///
///     let mut pos = 0;
///     let mut buffer = File::create("foo.txt")?;
///
///     while pos < data.len() {
///         let bytes_written = buffer.write(&data[pos..])?;
///         pos += bytes_written;
///     }
///     Ok(())
/// }
/// ```
///
/// The trait also provides convenience methods like [`write_all`], which calls
/// `write` in a loop until its entire input has been written.
///
/// [`write_all`]: Write::write_all
#[stable(feature = "rust1", since = "1.0.0")]
#[doc(notable_trait)]
#[cfg_attr(not(test), rustc_diagnostic_item = "IoWrite")]
pub trait Write {
    /// Writes a buffer into this writer, returning how many bytes were written.
    ///
    /// This function will attempt to write the entire contents of `buf`, but
    /// the entire write might not succeed, or the write may also generate an
    /// error. Typically, a call to `write` represents one attempt to write to
    /// any wrapped object.
    ///
    /// Calls to `write` are not guaranteed to block waiting for data to be
    /// written, and a write which would otherwise block can be indicated through
    /// an [`Err`] variant.
    ///
    /// If this method consumed `n > 0` bytes of `buf` it must return [`Ok(n)`].
    /// If the return value is `Ok(n)` then `n` must satisfy `n <= buf.len()`.
    /// A return value of `Ok(0)` typically means that the underlying object is
    /// no longer able to accept bytes and will likely not be able to in the
    /// future as well, or that the buffer provided is empty.
    ///
    /// # Errors
    ///
    /// Each call to `write` may generate an I/O error indicating that the
    /// operation could not be completed. If an error is returned then no bytes
    /// in the buffer were written to this writer.
    ///
    /// It is **not** considered an error if the entire buffer could not be
    /// written to this writer.
    ///
    /// An error of the [`ErrorKind::Interrupted`] kind is non-fatal and the
    /// write operation should be retried if there is nothing else to do.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use std::io::prelude::*;
    /// use std::fs::File;
    ///
    /// fn main() -> std::io::Result<()> {
    ///     let mut buffer = File::create("foo.txt")?;
    ///
    ///     // Writes some prefix of the byte string, not necessarily all of it.
    ///     buffer.write(b"some bytes")?;
    ///     Ok(())
    /// }
    /// ```
    ///
    /// [`Ok(n)`]: Ok
    #[stable(feature = "rust1", since = "1.0.0")]
    fn write(&mut self, buf: &[u8]) -> Result<usize>;

    /// Like [`write`], except that it writes from a slice of buffers.
    ///
    /// Data is copied from each buffer in order, with the final buffer
    /// read from possibly being only partially consumed. This method must
    /// behave as a call to [`write`] with the buffers concatenated would.
    ///
    /// The default implementation calls [`write`] with either the first nonempty
    /// buffer provided, or an empty one if none exists.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use std::io::IoSlice;
    /// use std::io::prelude::*;
    /// use std::fs::File;
    ///
    /// fn main() -> std::io::Result<()> {
    ///     let data1 = [1; 8];
    ///     let data2 = [15; 8];
    ///     let io_slice1 = IoSlice::new(&data1);
    ///     let io_slice2 = IoSlice::new(&data2);
    ///
    ///     let mut buffer = File::create("foo.txt")?;
    ///
    ///     // Writes some prefix of the byte string, not necessarily all of it.
    ///     buffer.write_vectored(&[io_slice1, io_slice2])?;
    ///     Ok(())
    /// }
    /// ```
    ///
    /// [`write`]: Write::write
    #[stable(feature = "iovec", since = "1.36.0")]
    fn write_vectored(&mut self, bufs: &[IoSlice<'_>]) -> Result<usize> {
        default_write_vectored(|b| self.write(b), bufs)
    }

    /// Determines if this `Write`r has an efficient [`write_vectored`]
    /// implementation.
    ///
    /// If a `Write`r does not override the default [`write_vectored`]
    /// implementation, code using it may want to avoid the method all together
    /// and coalesce writes into a single buffer for higher performance.
    ///
    /// The default implementation returns `false`.
    ///
    /// [`write_vectored`]: Write::write_vectored
    #[unstable(feature = "can_vector", issue = "69941")]
    fn is_write_vectored(&self) -> bool {
        false
    }

    /// Flushes this output stream, ensuring that all intermediately buffered
    /// contents reach their destination.
    ///
    /// # Errors
    ///
    /// It is considered an error if not all bytes could be written due to
    /// I/O errors or EOF being reached.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use std::io::prelude::*;
    /// use std::io::BufWriter;
    /// use std::fs::File;
    ///
    /// fn main() -> std::io::Result<()> {
    ///     let mut buffer = BufWriter::new(File::create("foo.txt")?);
    ///
    ///     buffer.write_all(b"some bytes")?;
    ///     buffer.flush()?;
    ///     Ok(())
    /// }
    /// ```
    #[stable(feature = "rust1", since = "1.0.0")]
    fn flush(&mut self) -> Result<()>;

    /// Attempts to write an entire buffer into this writer.
    ///
    /// This method will continuously call [`write`] until there is no more data
    /// to be written or an error of non-[`ErrorKind::Interrupted`] kind is
    /// returned. This method will not return until the entire buffer has been
    /// successfully written or such an error occurs. The first error that is
    /// not of [`ErrorKind::Interrupted`] kind generated from this method will be
    /// returned.
    ///
    /// If the buffer contains no data, this will never call [`write`].
    ///
    /// # Errors
    ///
    /// This function will return the first error of
    /// non-[`ErrorKind::Interrupted`] kind that [`write`] returns.
    ///
    /// [`write`]: Write::write
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use std::io::prelude::*;
    /// use std::fs::File;
    ///
    /// fn main() -> std::io::Result<()> {
    ///     let mut buffer = File::create("foo.txt")?;
    ///
    ///     buffer.write_all(b"some bytes")?;
    ///     Ok(())
    /// }
    /// ```
    #[stable(feature = "rust1", since = "1.0.0")]
    fn write_all(&mut self, mut buf: &[u8]) -> Result<()> {
        while !buf.is_empty() {
            match self.write(buf) {
                Ok(0) => {
                    return Err(Error::WRITE_ALL_EOF);
                }
                Ok(n) => buf = &buf[n..],
                Err(ref e) if e.is_interrupted() => {}
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    /// Attempts to write multiple buffers into this writer.
    ///
    /// This method will continuously call [`write_vectored`] until there is no
    /// more data to be written or an error of non-[`ErrorKind::Interrupted`]
    /// kind is returned. This method will not return until all buffers have
    /// been successfully written or such an error occurs. The first error that
    /// is not of [`ErrorKind::Interrupted`] kind generated from this method
    /// will be returned.
    ///
    /// If the buffer contains no data, this will never call [`write_vectored`].
    ///
    /// # Notes
    ///
    /// Unlike [`write_vectored`], this takes a *mutable* reference to
    /// a slice of [`IoSlice`]s, not an immutable one. That's because we need to
    /// modify the slice to keep track of the bytes already written.
    ///
    /// Once this function returns, the contents of `bufs` are unspecified, as
    /// this depends on how many calls to [`write_vectored`] were necessary. It is
    /// best to understand this function as taking ownership of `bufs` and to
    /// not use `bufs` afterwards. The underlying buffers, to which the
    /// [`IoSlice`]s point (but not the [`IoSlice`]s themselves), are unchanged and
    /// can be reused.
    ///
    /// [`write_vectored`]: Write::write_vectored
    ///
    /// # Examples
    ///
    /// ```
    /// #![feature(write_all_vectored)]
    /// # fn main() -> std::io::Result<()> {
    ///
    /// use std::io::{Write, IoSlice};
    ///
    /// let mut writer = Vec::new();
    /// let bufs = &mut [
    ///     IoSlice::new(&[1]),
    ///     IoSlice::new(&[2, 3]),
    ///     IoSlice::new(&[4, 5, 6]),
    /// ];
    ///
    /// writer.write_all_vectored(bufs)?;
    /// // Note: the contents of `bufs` is now undefined, see the Notes section.
    ///
    /// assert_eq!(writer, &[1, 2, 3, 4, 5, 6]);
    /// # Ok(()) }
    /// ```
    #[unstable(feature = "write_all_vectored", issue = "70436")]
    fn write_all_vectored(&mut self, mut bufs: &mut [IoSlice<'_>]) -> Result<()> {
        // Guarantee that bufs is empty if it contains no data,
        // to avoid calling write_vectored if there is no data to be written.
        IoSlice::advance_slices(&mut bufs, 0);
        while !bufs.is_empty() {
            match self.write_vectored(bufs) {
                Ok(0) => {
                    return Err(Error::WRITE_ALL_EOF);
                }
                Ok(n) => IoSlice::advance_slices(&mut bufs, n),
                Err(ref e) if e.is_interrupted() => {}
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    /// Writes a formatted string into this writer, returning any error
    /// encountered.
    ///
    /// This method is primarily used to interface with the
    /// [`format_args!()`] macro, and it is rare that this should
    /// explicitly be called. The [`write!()`] macro should be favored to
    /// invoke this method instead.
    ///
    /// This function internally uses the [`write_all`] method on
    /// this trait and hence will continuously write data so long as no errors
    /// are received. This also means that partial writes are not indicated in
    /// this signature.
    ///
    /// [`write_all`]: Write::write_all
    ///
    /// # Errors
    ///
    /// This function will return any I/O error reported while formatting.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use std::io::prelude::*;
    /// use std::fs::File;
    ///
    /// fn main() -> std::io::Result<()> {
    ///     let mut buffer = File::create("foo.txt")?;
    ///
    ///     // this call
    ///     write!(buffer, "{:.*}", 2, 1.234567)?;
    ///     // turns into this:
    ///     buffer.write_fmt(format_args!("{:.*}", 2, 1.234567))?;
    ///     Ok(())
    /// }
    /// ```
    #[stable(feature = "rust1", since = "1.0.0")]
    fn write_fmt(&mut self, args: fmt::Arguments<'_>) -> Result<()> {
        if let Some(s) = args.as_statically_known_str() {
            self.write_all(s.as_bytes())
        } else {
            default_write_fmt(self, args)
        }
    }

    /// Creates a "by reference" adapter for this instance of `Write`.
    ///
    /// The returned adapter also implements `Write` and will simply borrow this
    /// current writer.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use std::io::Write;
    /// use std::fs::File;
    ///
    /// fn main() -> std::io::Result<()> {
    ///     let mut buffer = File::create("foo.txt")?;
    ///
    ///     let reference = buffer.by_ref();
    ///
    ///     // we can use reference just like our original buffer
    ///     reference.write_all(b"some bytes")?;
    ///     Ok(())
    /// }
    /// ```
    #[stable(feature = "rust1", since = "1.0.0")]
    fn by_ref(&mut self) -> &mut Self
    where
        Self: Sized,
    {
        self
    }
}

/// The `Seek` trait provides a cursor which can be moved within a stream of
/// bytes.
///
/// The stream typically has a fixed size, allowing seeking relative to either
/// end or the current offset.
///
/// # Examples
///
/// [`File`]s implement `Seek`:
///
/// [`File`]: crate::fs::File
///
/// ```no_run
/// use std::io;
/// use std::io::prelude::*;
/// use std::fs::File;
/// use std::io::SeekFrom;
///
/// fn main() -> io::Result<()> {
///     let mut f = File::open("foo.txt")?;
///
///     // move the cursor 42 bytes from the start of the file
///     f.seek(SeekFrom::Start(42))?;
///     Ok(())
/// }
/// ```
#[stable(feature = "rust1", since = "1.0.0")]
#[cfg_attr(not(test), rustc_diagnostic_item = "IoSeek")]
pub trait Seek {
    /// Seek to an offset, in bytes, in a stream.
    ///
    /// A seek beyond the end of a stream is allowed, but behavior is defined
    /// by the implementation.
    ///
    /// If the seek operation completed successfully,
    /// this method returns the new position from the start of the stream.
    /// That position can be used later with [`SeekFrom::Start`].
    ///
    /// # Errors
    ///
    /// Seeking can fail, for example because it might involve flushing a buffer.
    ///
    /// Seeking to a negative offset is considered an error.
    #[stable(feature = "rust1", since = "1.0.0")]
    fn seek(&mut self, pos: SeekFrom) -> Result<u64>;

    /// Rewind to the beginning of a stream.
    ///
    /// This is a convenience method, equivalent to `seek(SeekFrom::Start(0))`.
    ///
    /// # Errors
    ///
    /// Rewinding can fail, for example because it might involve flushing a buffer.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use std::io::{Read, Seek, Write};
    /// use std::fs::OpenOptions;
    ///
    /// let mut f = OpenOptions::new()
    ///     .write(true)
    ///     .read(true)
    ///     .create(true)
    ///     .open("foo.txt")?;
    ///
    /// let hello = "Hello!\n";
    /// write!(f, "{hello}")?;
    /// f.rewind()?;
    ///
    /// let mut buf = String::new();
    /// f.read_to_string(&mut buf)?;
    /// assert_eq!(&buf, hello);
    /// # std::io::Result::Ok(())
    /// ```
    #[stable(feature = "seek_rewind", since = "1.55.0")]
    fn rewind(&mut self) -> Result<()> {
        self.seek(SeekFrom::Start(0))?;
        Ok(())
    }

    /// Returns the length of this stream (in bytes).
    ///
    /// The default implementation uses up to three seek operations. If this
    /// method returns successfully, the seek position is unchanged (i.e. the
    /// position before calling this method is the same as afterwards).
    /// However, if this method returns an error, the seek position is
    /// unspecified.
    ///
    /// If you need to obtain the length of *many* streams and you don't care
    /// about the seek position afterwards, you can reduce the number of seek
    /// operations by simply calling `seek(SeekFrom::End(0))` and using its
    /// return value (it is also the stream length).
    ///
    /// Note that length of a stream can change over time (for example, when
    /// data is appended to a file). So calling this method multiple times does
    /// not necessarily return the same length each time.
    ///
    /// # Example
    ///
    /// ```no_run
    /// #![feature(seek_stream_len)]
    /// use std::{
    ///     io::{self, Seek},
    ///     fs::File,
    /// };
    ///
    /// fn main() -> io::Result<()> {
    ///     let mut f = File::open("foo.txt")?;
    ///
    ///     let len = f.stream_len()?;
    ///     println!("The file is currently {len} bytes long");
    ///     Ok(())
    /// }
    /// ```
    #[unstable(feature = "seek_stream_len", issue = "59359")]
    fn stream_len(&mut self) -> Result<u64> {
        stream_len_default(self)
    }

    /// Returns the current seek position from the start of the stream.
    ///
    /// This is equivalent to `self.seek(SeekFrom::Current(0))`.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use std::{
    ///     io::{self, BufRead, BufReader, Seek},
    ///     fs::File,
    /// };
    ///
    /// fn main() -> io::Result<()> {
    ///     let mut f = BufReader::new(File::open("foo.txt")?);
    ///
    ///     let before = f.stream_position()?;
    ///     f.read_line(&mut String::new())?;
    ///     let after = f.stream_position()?;
    ///
    ///     println!("The first line was {} bytes long", after - before);
    ///     Ok(())
    /// }
    /// ```
    #[stable(feature = "seek_convenience", since = "1.51.0")]
    fn stream_position(&mut self) -> Result<u64> {
        self.seek(SeekFrom::Current(0))
    }

    /// Seeks relative to the current position.
    ///
    /// This is equivalent to `self.seek(SeekFrom::Current(offset))` but
    /// doesn't return the new position which can allow some implementations
    /// such as [`BufReader`] to perform more efficient seeks.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use std::{
    ///     io::{self, Seek},
    ///     fs::File,
    /// };
    ///
    /// fn main() -> io::Result<()> {
    ///     let mut f = File::open("foo.txt")?;
    ///     f.seek_relative(10)?;
    ///     assert_eq!(f.stream_position()?, 10);
    ///     Ok(())
    /// }
    /// ```
    ///
    /// [`BufReader`]: crate::io::BufReader
    #[stable(feature = "seek_seek_relative", since = "1.80.0")]
    fn seek_relative(&mut self, offset: i64) -> Result<()> {
        self.seek(SeekFrom::Current(offset))?;
        Ok(())
    }
}

pub(crate) fn stream_len_default<T: Seek + ?Sized>(self_: &mut T) -> Result<u64> {
    let old_pos = self_.stream_position()?;
    let len = self_.seek(SeekFrom::End(0))?;

    // Avoid seeking a third time when we were already at the end of the
    // stream. The branch is usually way cheaper than a seek operation.
    if old_pos != len {
        self_.seek(SeekFrom::Start(old_pos))?;
    }

    Ok(len)
}

/// Enumeration of possible methods to seek within an I/O object.
///
/// It is used by the [`Seek`] trait.
#[derive(Copy, PartialEq, Eq, Clone, Debug)]
#[stable(feature = "rust1", since = "1.0.0")]
#[cfg_attr(not(test), rustc_diagnostic_item = "SeekFrom")]
pub enum SeekFrom {
    /// Sets the offset to the provided number of bytes.
    #[stable(feature = "rust1", since = "1.0.0")]
    Start(#[stable(feature = "rust1", since = "1.0.0")] u64),

    /// Sets the offset to the size of this object plus the specified number of
    /// bytes.
    ///
    /// It is possible to seek beyond the end of an object, but it's an error to
    /// seek before byte 0.
    #[stable(feature = "rust1", since = "1.0.0")]
    End(#[stable(feature = "rust1", since = "1.0.0")] i64),

    /// Sets the offset to the current position plus the specified number of
    /// bytes.
    ///
    /// It is possible to seek beyond the end of an object, but it's an error to
    /// seek before byte 0.
    #[stable(feature = "rust1", since = "1.0.0")]
    Current(#[stable(feature = "rust1", since = "1.0.0")] i64),
}

fn read_until<R: BufRead + ?Sized>(r: &mut R, delim: u8, buf: &mut Vec<u8>) -> Result<usize> {
    let mut read = 0;
    loop {
        let (done, used) = {
            let available = match r.fill_buf() {
                Ok(n) => n,
                Err(ref e) if e.is_interrupted() => continue,
                Err(e) => return Err(e),
            };
            match memchr::memchr(delim, available) {
                Some(i) => {
                    buf.extend_from_slice(&available[..=i]);
                    (true, i + 1)
                }
                None => {
                    buf.extend_from_slice(available);
                    (false, available.len())
                }
            }
        };
        r.consume(used);
        read += used;
        if done || used == 0 {
            return Ok(read);
        }
    }
}

fn skip_until<R: BufRead + ?Sized>(r: &mut R, delim: u8) -> Result<usize> {
    let mut read = 0;
    loop {
        let (done, used) = {
            let available = match r.fill_buf() {
                Ok(n) => n,
                Err(ref e) if e.kind() == ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            };
            match memchr::memchr(delim, available) {
                Some(i) => (true, i + 1),
                None => (false, available.len()),
            }
        };
        r.consume(used);
        read += used;
        if done || used == 0 {
            return Ok(read);
        }
    }
}

/// A `BufRead` is a type of `Read`er which has an internal buffer, allowing it
/// to perform extra ways of reading.
///
/// For example, reading line-by-line is inefficient without using a buffer, so
/// if you want to read by line, you'll need `BufRead`, which includes a
/// [`read_line`] method as well as a [`lines`] iterator.
///
/// # Examples
///
/// A locked standard input implements `BufRead`:
///
/// ```no_run
/// use std::io;
/// use std::io::prelude::*;
///
/// let stdin = io::stdin();
/// for line in stdin.lock().lines() {
///     println!("{}", line?);
/// }
/// # std::io::Result::Ok(())
/// ```
///
/// If you have something that implements [`Read`], you can use the [`BufReader`
/// type][`BufReader`] to turn it into a `BufRead`.
///
/// For example, [`File`] implements [`Read`], but not `BufRead`.
/// [`BufReader`] to the rescue!
///
/// [`File`]: crate::fs::File
/// [`read_line`]: BufRead::read_line
/// [`lines`]: BufRead::lines
///
/// ```no_run
/// use std::io::{self, BufReader};
/// use std::io::prelude::*;
/// use std::fs::File;
///
/// fn main() -> io::Result<()> {
///     let f = File::open("foo.txt")?;
///     let f = BufReader::new(f);
///
///     for line in f.lines() {
///         let line = line?;
///         println!("{line}");
///     }
///
///     Ok(())
/// }
/// ```
#[stable(feature = "rust1", since = "1.0.0")]
#[cfg_attr(not(test), rustc_diagnostic_item = "IoBufRead")]
pub trait BufRead: Read {
    /// Returns the contents of the internal buffer, filling it with more data, via `Read` methods, if empty.
    ///
    /// This is a lower-level method and is meant to be used together with [`consume`],
    /// which can be used to mark bytes that should not be returned by subsequent calls to `read`.
    ///
    /// [`consume`]: BufRead::consume
    ///
    /// Returns an empty buffer when the stream has reached EOF.
    ///
    /// # Errors
    ///
    /// This function will return an I/O error if a `Read` method was called, but returned an error.
    ///
    /// # Examples
    ///
    /// A locked standard input implements `BufRead`:
    ///
    /// ```no_run
    /// use std::io;
    /// use std::io::prelude::*;
    ///
    /// let stdin = io::stdin();
    /// let mut stdin = stdin.lock();
    ///
    /// let buffer = stdin.fill_buf()?;
    ///
    /// // work with buffer
    /// println!("{buffer:?}");
    ///
    /// // mark the bytes we worked with as read
    /// let length = buffer.len();
    /// stdin.consume(length);
    /// # std::io::Result::Ok(())
    /// ```
    #[stable(feature = "rust1", since = "1.0.0")]
    fn fill_buf(&mut self) -> Result<&[u8]>;

    /// Marks the given `amount` of additional bytes from the internal buffer as having been read.
    /// Subsequent calls to `read` only return bytes that have not been marked as read.
    ///
    /// This is a lower-level method and is meant to be used together with [`fill_buf`],
    /// which can be used to fill the internal buffer via `Read` methods.
    ///
    /// It is a logic error if `amount` exceeds the number of unread bytes in the internal buffer, which is returned by [`fill_buf`].
    ///
    /// # Examples
    ///
    /// Since `consume()` is meant to be used with [`fill_buf`],
    /// that method's example includes an example of `consume()`.
    ///
    /// [`fill_buf`]: BufRead::fill_buf
    #[stable(feature = "rust1", since = "1.0.0")]
    fn consume(&mut self, amount: usize);

    /// Checks if there is any data left to be `read`.
    ///
    /// This function may fill the buffer to check for data,
    /// so this function returns `Result<bool>`, not `bool`.
    ///
    /// The default implementation calls `fill_buf` and checks that the
    /// returned slice is empty (which means that there is no data left,
    /// since EOF is reached).
    ///
    /// # Errors
    ///
    /// This function will return an I/O error if a `Read` method was called, but returned an error.
    ///
    /// Examples
    ///
    /// ```
    /// #![feature(buf_read_has_data_left)]
    /// use std::io;
    /// use std::io::prelude::*;
    ///
    /// let stdin = io::stdin();
    /// let mut stdin = stdin.lock();
    ///
    /// while stdin.has_data_left()? {
    ///     let mut line = String::new();
    ///     stdin.read_line(&mut line)?;
    ///     // work with line
    ///     println!("{line:?}");
    /// }
    /// # std::io::Result::Ok(())
    /// ```
    #[unstable(feature = "buf_read_has_data_left", reason = "recently added", issue = "86423")]
    fn has_data_left(&mut self) -> Result<bool> {
        self.fill_buf().map(|b| !b.is_empty())
    }

    /// Reads all bytes into `buf` until the delimiter `byte` or EOF is reached.
    ///
    /// This function will read bytes from the underlying stream until the
    /// delimiter or EOF is found. Once found, all bytes up to, and including,
    /// the delimiter (if found) will be appended to `buf`.
    ///
    /// If successful, this function will return the total number of bytes read.
    ///
    /// This function is blocking and should be used carefully: it is possible for
    /// an attacker to continuously send bytes without ever sending the delimiter
    /// or EOF.
    ///
    /// # Errors
    ///
    /// This function will ignore all instances of [`ErrorKind::Interrupted`] and
    /// will otherwise return any errors returned by [`fill_buf`].
    ///
    /// If an I/O error is encountered then all bytes read so far will be
    /// present in `buf` and its length will have been adjusted appropriately.
    ///
    /// [`fill_buf`]: BufRead::fill_buf
    ///
    /// # Examples
    ///
    /// [`std::io::Cursor`][`Cursor`] is a type that implements `BufRead`. In
    /// this example, we use [`Cursor`] to read all the bytes in a byte slice
    /// in hyphen delimited segments:
    ///
    /// ```
    /// use std::io::{self, BufRead};
    ///
    /// let mut cursor = io::Cursor::new(b"lorem-ipsum");
    /// let mut buf = vec![];
    ///
    /// // cursor is at 'l'
    /// let num_bytes = cursor.read_until(b'-', &mut buf)
    ///     .expect("reading from cursor won't fail");
    /// assert_eq!(num_bytes, 6);
    /// assert_eq!(buf, b"lorem-");
    /// buf.clear();
    ///
    /// // cursor is at 'i'
    /// let num_bytes = cursor.read_until(b'-', &mut buf)
    ///     .expect("reading from cursor won't fail");
    /// assert_eq!(num_bytes, 5);
    /// assert_eq!(buf, b"ipsum");
    /// buf.clear();
    ///
    /// // cursor is at EOF
    /// let num_bytes = cursor.read_until(b'-', &mut buf)
    ///     .expect("reading from cursor won't fail");
    /// assert_eq!(num_bytes, 0);
    /// assert_eq!(buf, b"");
    /// ```
    #[stable(feature = "rust1", since = "1.0.0")]
    fn read_until(&mut self, byte: u8, buf: &mut Vec<u8>) -> Result<usize> {
        read_until(self, byte, buf)
    }

    /// Skips all bytes until the delimiter `byte` or EOF is reached.
    ///
    /// This function will read (and discard) bytes from the underlying stream until the
    /// delimiter or EOF is found.
    ///
    /// If successful, this function will return the total number of bytes read,
    /// including the delimiter byte if found.
    ///
    /// This is useful for efficiently skipping data such as NUL-terminated strings
    /// in binary file formats without buffering.
    ///
    /// This function is blocking and should be used carefully: it is possible for
    /// an attacker to continuously send bytes without ever sending the delimiter
    /// or EOF.
    ///
    /// # Errors
    ///
    /// This function will ignore all instances of [`ErrorKind::Interrupted`] and
    /// will otherwise return any errors returned by [`fill_buf`].
    ///
    /// If an I/O error is encountered then all bytes read so far will be
    /// present in `buf` and its length will have been adjusted appropriately.
    ///
    /// [`fill_buf`]: BufRead::fill_buf
    ///
    /// # Examples
    ///
    /// [`std::io::Cursor`][`Cursor`] is a type that implements `BufRead`. In
    /// this example, we use [`Cursor`] to read some NUL-terminated information
    /// about Ferris from a binary string, skipping the fun fact:
    ///
    /// ```
    /// use std::io::{self, BufRead};
    ///
    /// let mut cursor = io::Cursor::new(b"Ferris\0Likes long walks on the beach\0Crustacean\0!");
    ///
    /// // read name
    /// let mut name = Vec::new();
    /// let num_bytes = cursor.read_until(b'\0', &mut name)
    ///     .expect("reading from cursor won't fail");
    /// assert_eq!(num_bytes, 7);
    /// assert_eq!(name, b"Ferris\0");
    ///
    /// // skip fun fact
    /// let num_bytes = cursor.skip_until(b'\0')
    ///     .expect("reading from cursor won't fail");
    /// assert_eq!(num_bytes, 30);
    ///
    /// // read animal type
    /// let mut animal = Vec::new();
    /// let num_bytes = cursor.read_until(b'\0', &mut animal)
    ///     .expect("reading from cursor won't fail");
    /// assert_eq!(num_bytes, 11);
    /// assert_eq!(animal, b"Crustacean\0");
    ///
    /// // reach EOF
    /// let num_bytes = cursor.skip_until(b'\0')
    ///     .expect("reading from cursor won't fail");
    /// assert_eq!(num_bytes, 1);
    /// ```
    #[stable(feature = "bufread_skip_until", since = "1.83.0")]
    fn skip_until(&mut self, byte: u8) -> Result<usize> {
        skip_until(self, byte)
    }

    /// Reads all bytes until a newline (the `0xA` byte) is reached, and append
    /// them to the provided `String` buffer.
    ///
    /// Previous content of the buffer will be preserved. To avoid appending to
    /// the buffer, you need to [`clear`] it first.
    ///
    /// This function will read bytes from the underlying stream until the
    /// newline delimiter (the `0xA` byte) or EOF is found. Once found, all bytes
    /// up to, and including, the delimiter (if found) will be appended to
    /// `buf`.
    ///
    /// If successful, this function will return the total number of bytes read.
    ///
    /// If this function returns [`Ok(0)`], the stream has reached EOF.
    ///
    /// This function is blocking and should be used carefully: it is possible for
    /// an attacker to continuously send bytes without ever sending a newline
    /// or EOF. You can use [`take`] to limit the maximum number of bytes read.
    ///
    /// [`Ok(0)`]: Ok
    /// [`clear`]: String::clear
    /// [`take`]: crate::io::Read::take
    ///
    /// # Errors
    ///
    /// This function has the same error semantics as [`read_until`] and will
    /// also return an error if the read bytes are not valid UTF-8. If an I/O
    /// error is encountered then `buf` may contain some bytes already read in
    /// the event that all data read so far was valid UTF-8.
    ///
    /// [`read_until`]: BufRead::read_until
    ///
    /// # Examples
    ///
    /// [`std::io::Cursor`][`Cursor`] is a type that implements `BufRead`. In
    /// this example, we use [`Cursor`] to read all the lines in a byte slice:
    ///
    /// ```
    /// use std::io::{self, BufRead};
    ///
    /// let mut cursor = io::Cursor::new(b"foo\nbar");
    /// let mut buf = String::new();
    ///
    /// // cursor is at 'f'
    /// let num_bytes = cursor.read_line(&mut buf)
    ///     .expect("reading from cursor won't fail");
    /// assert_eq!(num_bytes, 4);
    /// assert_eq!(buf, "foo\n");
    /// buf.clear();
    ///
    /// // cursor is at 'b'
    /// let num_bytes = cursor.read_line(&mut buf)
    ///     .expect("reading from cursor won't fail");
    /// assert_eq!(num_bytes, 3);
    /// assert_eq!(buf, "bar");
    /// buf.clear();
    ///
    /// // cursor is at EOF
    /// let num_bytes = cursor.read_line(&mut buf)
    ///     .expect("reading from cursor won't fail");
    /// assert_eq!(num_bytes, 0);
    /// assert_eq!(buf, "");
    /// ```
    #[stable(feature = "rust1", since = "1.0.0")]
    fn read_line(&mut self, buf: &mut String) -> Result<usize> {
        // Note that we are not calling the `.read_until` method here, but
        // rather our hardcoded implementation. For more details as to why, see
        // the comments in `default_read_to_string`.
        unsafe { append_to_string(buf, |b| read_until(self, b'\n', b)) }
    }

    /// Returns an iterator over the contents of this reader split on the byte
    /// `byte`.
    ///
    /// The iterator returned from this function will return instances of
    /// <code>[io::Result]<[Vec]\<u8>></code>. Each vector returned will *not* have
    /// the delimiter byte at the end.
    ///
    /// This function will yield errors whenever [`read_until`] would have
    /// also yielded an error.
    ///
    /// [io::Result]: self::Result "io::Result"
    /// [`read_until`]: BufRead::read_until
    ///
    /// # Examples
    ///
    /// [`std::io::Cursor`][`Cursor`] is a type that implements `BufRead`. In
    /// this example, we use [`Cursor`] to iterate over all hyphen delimited
    /// segments in a byte slice
    ///
    /// ```
    /// use std::io::{self, BufRead};
    ///
    /// let cursor = io::Cursor::new(b"lorem-ipsum-dolor");
    ///
    /// let mut split_iter = cursor.split(b'-').map(|l| l.unwrap());
    /// assert_eq!(split_iter.next(), Some(b"lorem".to_vec()));
    /// assert_eq!(split_iter.next(), Some(b"ipsum".to_vec()));
    /// assert_eq!(split_iter.next(), Some(b"dolor".to_vec()));
    /// assert_eq!(split_iter.next(), None);
    /// ```
    #[stable(feature = "rust1", since = "1.0.0")]
    fn split(self, byte: u8) -> Split<Self>
    where
        Self: Sized,
    {
        Split { buf: self, delim: byte }
    }

    /// Returns an iterator over the lines of this reader.
    ///
    /// The iterator returned from this function will yield instances of
    /// <code>[io::Result]<[String]></code>. Each string returned will *not* have a newline
    /// byte (the `0xA` byte) or `CRLF` (`0xD`, `0xA` bytes) at the end.
    ///
    /// [io::Result]: self::Result "io::Result"
    ///
    /// # Examples
    ///
    /// [`std::io::Cursor`][`Cursor`] is a type that implements `BufRead`. In
    /// this example, we use [`Cursor`] to iterate over all the lines in a byte
    /// slice.
    ///
    /// ```
    /// use std::io::{self, BufRead};
    ///
    /// let cursor = io::Cursor::new(b"lorem\nipsum\r\ndolor");
    ///
    /// let mut lines_iter = cursor.lines().map(|l| l.unwrap());
    /// assert_eq!(lines_iter.next(), Some(String::from("lorem")));
    /// assert_eq!(lines_iter.next(), Some(String::from("ipsum")));
    /// assert_eq!(lines_iter.next(), Some(String::from("dolor")));
    /// assert_eq!(lines_iter.next(), None);
    /// ```
    ///
    /// # Errors
    ///
    /// Each line of the iterator has the same error semantics as [`BufRead::read_line`].
    #[stable(feature = "rust1", since = "1.0.0")]
    fn lines(self) -> Lines<Self>
    where
        Self: Sized,
    {
        Lines { buf: self }
    }
}

/// Adapter to chain together two readers.
///
/// This struct is generally created by calling [`chain`] on a reader.
/// Please see the documentation of [`chain`] for more details.
///
/// [`chain`]: Read::chain
#[stable(feature = "rust1", since = "1.0.0")]
#[derive(Debug)]
pub struct Chain<T, U> {
    first: T,
    second: U,
    done_first: bool,
}

impl<T, U> Chain<T, U> {
    /// Consumes the `Chain`, returning the wrapped readers.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use std::io;
    /// use std::io::prelude::*;
    /// use std::fs::File;
    ///
    /// fn main() -> io::Result<()> {
    ///     let mut foo_file = File::open("foo.txt")?;
    ///     let mut bar_file = File::open("bar.txt")?;
    ///
    ///     let chain = foo_file.chain(bar_file);
    ///     let (foo_file, bar_file) = chain.into_inner();
    ///     Ok(())
    /// }
    /// ```
    #[stable(feature = "more_io_inner_methods", since = "1.20.0")]
    pub fn into_inner(self) -> (T, U) {
        (self.first, self.second)
    }

    /// Gets references to the underlying readers in this `Chain`.
    ///
    /// Care should be taken to avoid modifying the internal I/O state of the
    /// underlying readers as doing so may corrupt the internal state of this
    /// `Chain`.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use std::io;
    /// use std::io::prelude::*;
    /// use std::fs::File;
    ///
    /// fn main() -> io::Result<()> {
    ///     let mut foo_file = File::open("foo.txt")?;
    ///     let mut bar_file = File::open("bar.txt")?;
    ///
    ///     let chain = foo_file.chain(bar_file);
    ///     let (foo_file, bar_file) = chain.get_ref();
    ///     Ok(())
    /// }
    /// ```
    #[stable(feature = "more_io_inner_methods", since = "1.20.0")]
    pub fn get_ref(&self) -> (&T, &U) {
        (&self.first, &self.second)
    }

    /// Gets mutable references to the underlying readers in this `Chain`.
    ///
    /// Care should be taken to avoid modifying the internal I/O state of the
    /// underlying readers as doing so may corrupt the internal state of this
    /// `Chain`.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use std::io;
    /// use std::io::prelude::*;
    /// use std::fs::File;
    ///
    /// fn main() -> io::Result<()> {
    ///     let mut foo_file = File::open("foo.txt")?;
    ///     let mut bar_file = File::open("bar.txt")?;
    ///
    ///     let mut chain = foo_file.chain(bar_file);
    ///     let (foo_file, bar_file) = chain.get_mut();
    ///     Ok(())
    /// }
    /// ```
    #[stable(feature = "more_io_inner_methods", since = "1.20.0")]
    pub fn get_mut(&mut self) -> (&mut T, &mut U) {
        (&mut self.first, &mut self.second)
    }
}

#[stable(feature = "rust1", since = "1.0.0")]
impl<T: Read, U: Read> Read for Chain<T, U> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        if !self.done_first {
            match self.first.read(buf)? {
                0 if !buf.is_empty() => self.done_first = true,
                n => return Ok(n),
            }
        }
        self.second.read(buf)
    }

    fn read_vectored(&mut self, bufs: &mut [IoSliceMut<'_>]) -> Result<usize> {
        if !self.done_first {
            match self.first.read_vectored(bufs)? {
                0 if bufs.iter().any(|b| !b.is_empty()) => self.done_first = true,
                n => return Ok(n),
            }
        }
        self.second.read_vectored(bufs)
    }

    #[inline]
    fn is_read_vectored(&self) -> bool {
        self.first.is_read_vectored() || self.second.is_read_vectored()
    }

    fn read_to_end(&mut self, buf: &mut Vec<u8>) -> Result<usize> {
        let mut read = 0;
        if !self.done_first {
            read += self.first.read_to_end(buf)?;
            self.done_first = true;
        }
        read += self.second.read_to_end(buf)?;
        Ok(read)
    }

    // We don't override `read_to_string` here because an UTF-8 sequence could
    // be split between the two parts of the chain

    fn read_buf(&mut self, mut buf: BorrowedCursor<'_>) -> Result<()> {
        if buf.capacity() == 0 {
            return Ok(());
        }

        if !self.done_first {
            let old_len = buf.written();
            self.first.read_buf(buf.reborrow())?;

            if buf.written() != old_len {
                return Ok(());
            } else {
                self.done_first = true;
            }
        }
        self.second.read_buf(buf)
    }
}

#[stable(feature = "chain_bufread", since = "1.9.0")]
impl<T: BufRead, U: BufRead> BufRead for Chain<T, U> {
    fn fill_buf(&mut self) -> Result<&[u8]> {
        if !self.done_first {
            match self.first.fill_buf()? {
                buf if buf.is_empty() => self.done_first = true,
                buf => return Ok(buf),
            }
        }
        self.second.fill_buf()
    }

    fn consume(&mut self, amt: usize) {
        if !self.done_first { self.first.consume(amt) } else { self.second.consume(amt) }
    }

    fn read_until(&mut self, byte: u8, buf: &mut Vec<u8>) -> Result<usize> {
        let mut read = 0;
        if !self.done_first {
            let n = self.first.read_until(byte, buf)?;
            read += n;

            match buf.last() {
                Some(b) if *b == byte && n != 0 => return Ok(read),
                _ => self.done_first = true,
            }
        }
        read += self.second.read_until(byte, buf)?;
        Ok(read)
    }

    // We don't override `read_line` here because an UTF-8 sequence could be
    // split between the two parts of the chain
}

impl<T, U> SizeHint for Chain<T, U> {
    #[inline]
    fn lower_bound(&self) -> usize {
        SizeHint::lower_bound(&self.first) + SizeHint::lower_bound(&self.second)
    }

    #[inline]
    fn upper_bound(&self) -> Option<usize> {
        match (SizeHint::upper_bound(&self.first), SizeHint::upper_bound(&self.second)) {
            (Some(first), Some(second)) => first.checked_add(second),
            _ => None,
        }
    }
}

/// Reader adapter which limits the bytes read from an underlying reader.
///
/// This struct is generally created by calling [`take`] on a reader.
/// Please see the documentation of [`take`] for more details.
///
/// [`take`]: Read::take
#[stable(feature = "rust1", since = "1.0.0")]
#[derive(Debug)]
pub struct Take<T> {
    inner: T,
    len: u64,
    limit: u64,
}

impl<T> Take<T> {
    /// Returns the number of bytes that can be read before this instance will
    /// return EOF.
    ///
    /// # Note
    ///
    /// This instance may reach `EOF` after reading fewer bytes than indicated by
    /// this method if the underlying [`Read`] instance reaches EOF.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use std::io;
    /// use std::io::prelude::*;
    /// use std::fs::File;
    ///
    /// fn main() -> io::Result<()> {
    ///     let f = File::open("foo.txt")?;
    ///
    ///     // read at most five bytes
    ///     let handle = f.take(5);
    ///
    ///     println!("limit: {}", handle.limit());
    ///     Ok(())
    /// }
    /// ```
    #[stable(feature = "rust1", since = "1.0.0")]
    pub fn limit(&self) -> u64 {
        self.limit
    }

    /// Returns the number of bytes read so far.
    #[unstable(feature = "seek_io_take_position", issue = "97227")]
    pub fn position(&self) -> u64 {
        self.len - self.limit
    }

    /// Sets the number of bytes that can be read before this instance will
    /// return EOF. This is the same as constructing a new `Take` instance, so
    /// the amount of bytes read and the previous limit value don't matter when
    /// calling this method.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use std::io;
    /// use std::io::prelude::*;
    /// use std::fs::File;
    ///
    /// fn main() -> io::Result<()> {
    ///     let f = File::open("foo.txt")?;
    ///
    ///     // read at most five bytes
    ///     let mut handle = f.take(5);
    ///     handle.set_limit(10);
    ///
    ///     assert_eq!(handle.limit(), 10);
    ///     Ok(())
    /// }
    /// ```
    #[stable(feature = "take_set_limit", since = "1.27.0")]
    pub fn set_limit(&mut self, limit: u64) {
        self.len = limit;
        self.limit = limit;
    }

    /// Consumes the `Take`, returning the wrapped reader.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use std::io;
    /// use std::io::prelude::*;
    /// use std::fs::File;
    ///
    /// fn main() -> io::Result<()> {
    ///     let mut file = File::open("foo.txt")?;
    ///
    ///     let mut buffer = [0; 5];
    ///     let mut handle = file.take(5);
    ///     handle.read(&mut buffer)?;
    ///
    ///     let file = handle.into_inner();
    ///     Ok(())
    /// }
    /// ```
    #[stable(feature = "io_take_into_inner", since = "1.15.0")]
    pub fn into_inner(self) -> T {
        self.inner
    }

    /// Gets a reference to the underlying reader.
    ///
    /// Care should be taken to avoid modifying the internal I/O state of the
    /// underlying reader as doing so may corrupt the internal limit of this
    /// `Take`.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use std::io;
    /// use std::io::prelude::*;
    /// use std::fs::File;
    ///
    /// fn main() -> io::Result<()> {
    ///     let mut file = File::open("foo.txt")?;
    ///
    ///     let mut buffer = [0; 5];
    ///     let mut handle = file.take(5);
    ///     handle.read(&mut buffer)?;
    ///
    ///     let file = handle.get_ref();
    ///     Ok(())
    /// }
    /// ```
    #[stable(feature = "more_io_inner_methods", since = "1.20.0")]
    pub fn get_ref(&self) -> &T {
        &self.inner
    }

    /// Gets a mutable reference to the underlying reader.
    ///
    /// Care should be taken to avoid modifying the internal I/O state of the
    /// underlying reader as doing so may corrupt the internal limit of this
    /// `Take`.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use std::io;
    /// use std::io::prelude::*;
    /// use std::fs::File;
    ///
    /// fn main() -> io::Result<()> {
    ///     let mut file = File::open("foo.txt")?;
    ///
    ///     let mut buffer = [0; 5];
    ///     let mut handle = file.take(5);
    ///     handle.read(&mut buffer)?;
    ///
    ///     let file = handle.get_mut();
    ///     Ok(())
    /// }
    /// ```
    #[stable(feature = "more_io_inner_methods", since = "1.20.0")]
    pub fn get_mut(&mut self) -> &mut T {
        &mut self.inner
    }
}

#[stable(feature = "rust1", since = "1.0.0")]
impl<T: Read> Read for Take<T> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        // Don't call into inner reader at all at EOF because it may still block
        if self.limit == 0 {
            return Ok(0);
        }

        let max = cmp::min(buf.len() as u64, self.limit) as usize;
        let n = self.inner.read(&mut buf[..max])?;
        assert!(n as u64 <= self.limit, "number of read bytes exceeds limit");
        self.limit -= n as u64;
        Ok(n)
    }

    fn read_buf(&mut self, mut buf: BorrowedCursor<'_>) -> Result<()> {
        // Don't call into inner reader at all at EOF because it may still block
        if self.limit == 0 {
            return Ok(());
        }

        if self.limit < buf.capacity() as u64 {
            // The condition above guarantees that `self.limit` fits in `usize`.
            let limit = self.limit as usize;

            let extra_init = cmp::min(limit, buf.init_mut().len());

            // SAFETY: no uninit data is written to ibuf
            let ibuf = unsafe { &mut buf.as_mut()[..limit] };

            let mut sliced_buf: BorrowedBuf<'_> = ibuf.into();

            // SAFETY: extra_init bytes of ibuf are known to be initialized
            unsafe {
                sliced_buf.set_init(extra_init);
            }

            let mut cursor = sliced_buf.unfilled();
            let result = self.inner.read_buf(cursor.reborrow());

            let new_init = cursor.init_mut().len();
            let filled = sliced_buf.len();

            // cursor / sliced_buf / ibuf must drop here

            unsafe {
                // SAFETY: filled bytes have been filled and therefore initialized
                buf.advance_unchecked(filled);
                // SAFETY: new_init bytes of buf's unfilled buffer have been initialized
                buf.set_init(new_init);
            }

            self.limit -= filled as u64;

            result
        } else {
            let written = buf.written();
            let result = self.inner.read_buf(buf.reborrow());
            self.limit -= (buf.written() - written) as u64;
            result
        }
    }
}

#[stable(feature = "rust1", since = "1.0.0")]
impl<T: BufRead> BufRead for Take<T> {
    fn fill_buf(&mut self) -> Result<&[u8]> {
        // Don't call into inner reader at all at EOF because it may still block
        if self.limit == 0 {
            return Ok(&[]);
        }

        let buf = self.inner.fill_buf()?;
        let cap = cmp::min(buf.len() as u64, self.limit) as usize;
        Ok(&buf[..cap])
    }

    fn consume(&mut self, amt: usize) {
        // Don't let callers reset the limit by passing an overlarge value
        let amt = cmp::min(amt as u64, self.limit) as usize;
        self.limit -= amt as u64;
        self.inner.consume(amt);
    }
}

impl<T> SizeHint for Take<T> {
    #[inline]
    fn lower_bound(&self) -> usize {
        cmp::min(SizeHint::lower_bound(&self.inner) as u64, self.limit) as usize
    }

    #[inline]
    fn upper_bound(&self) -> Option<usize> {
        match SizeHint::upper_bound(&self.inner) {
            Some(upper_bound) => Some(cmp::min(upper_bound as u64, self.limit) as usize),
            None => self.limit.try_into().ok(),
        }
    }
}

#[stable(feature = "seek_io_take", since = "1.89.0")]
impl<T: Seek> Seek for Take<T> {
    fn seek(&mut self, pos: SeekFrom) -> Result<u64> {
        let new_position = match pos {
            SeekFrom::Start(v) => Some(v),
            SeekFrom::Current(v) => self.position().checked_add_signed(v),
            SeekFrom::End(v) => self.len.checked_add_signed(v),
        };
        let new_position = match new_position {
            Some(v) if v <= self.len => v,
            _ => return Err(ErrorKind::InvalidInput.into()),
        };
        while new_position != self.position() {
            if let Some(offset) = new_position.checked_signed_diff(self.position()) {
                self.inner.seek_relative(offset)?;
                self.limit = self.limit.wrapping_sub(offset as u64);
                break;
            }
            let offset = if new_position > self.position() { i64::MAX } else { i64::MIN };
            self.inner.seek_relative(offset)?;
            self.limit = self.limit.wrapping_sub(offset as u64);
        }
        Ok(new_position)
    }

    fn stream_len(&mut self) -> Result<u64> {
        Ok(self.len)
    }

    fn stream_position(&mut self) -> Result<u64> {
        Ok(self.position())
    }

    fn seek_relative(&mut self, offset: i64) -> Result<()> {
        if !self.position().checked_add_signed(offset).is_some_and(|p| p <= self.len) {
            return Err(ErrorKind::InvalidInput.into());
        }
        self.inner.seek_relative(offset)?;
        self.limit = self.limit.wrapping_sub(offset as u64);
        Ok(())
    }
}

/// An iterator over `u8` values of a reader.
///
/// This struct is generally created by calling [`bytes`] on a reader.
/// Please see the documentation of [`bytes`] for more details.
///
/// [`bytes`]: Read::bytes
#[stable(feature = "rust1", since = "1.0.0")]
#[derive(Debug)]
pub struct Bytes<R> {
    inner: R,
}

#[stable(feature = "rust1", since = "1.0.0")]
impl<R: Read> Iterator for Bytes<R> {
    type Item = Result<u8>;

    // Not `#[inline]`. This function gets inlined even without it, but having
    // the inline annotation can result in worse code generation. See #116785.
    fn next(&mut self) -> Option<Result<u8>> {
        SpecReadByte::spec_read_byte(&mut self.inner)
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        SizeHint::size_hint(&self.inner)
    }
}

/// For the specialization of `Bytes::next`.
trait SpecReadByte {
    fn spec_read_byte(&mut self) -> Option<Result<u8>>;
}

impl<R> SpecReadByte for R
where
    Self: Read,
{
    #[inline]
    default fn spec_read_byte(&mut self) -> Option<Result<u8>> {
        inlined_slow_read_byte(self)
    }
}

/// Reads a single byte in a slow, generic way. This is used by the default
/// `spec_read_byte`.
#[inline]
fn inlined_slow_read_byte<R: Read>(reader: &mut R) -> Option<Result<u8>> {
    let mut byte = 0;
    loop {
        return match reader.read(slice::from_mut(&mut byte)) {
            Ok(0) => None,
            Ok(..) => Some(Ok(byte)),
            Err(ref e) if e.is_interrupted() => continue,
            Err(e) => Some(Err(e)),
        };
    }
}

// Used by `BufReader::spec_read_byte`, for which the `inline(never)` is
// important.
#[inline(never)]
fn uninlined_slow_read_byte<R: Read>(reader: &mut R) -> Option<Result<u8>> {
    inlined_slow_read_byte(reader)
}

trait SizeHint {
    fn lower_bound(&self) -> usize;

    fn upper_bound(&self) -> Option<usize>;

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.lower_bound(), self.upper_bound())
    }
}

impl<T: ?Sized> SizeHint for T {
    #[inline]
    default fn lower_bound(&self) -> usize {
        0
    }

    #[inline]
    default fn upper_bound(&self) -> Option<usize> {
        None
    }
}

impl<T> SizeHint for &mut T {
    #[inline]
    fn lower_bound(&self) -> usize {
        SizeHint::lower_bound(*self)
    }

    #[inline]
    fn upper_bound(&self) -> Option<usize> {
        SizeHint::upper_bound(*self)
    }
}

impl<T> SizeHint for Box<T> {
    #[inline]
    fn lower_bound(&self) -> usize {
        SizeHint::lower_bound(&**self)
    }

    #[inline]
    fn upper_bound(&self) -> Option<usize> {
        SizeHint::upper_bound(&**self)
    }
}

impl SizeHint for &[u8] {
    #[inline]
    fn lower_bound(&self) -> usize {
        self.len()
    }

    #[inline]
    fn upper_bound(&self) -> Option<usize> {
        Some(self.len())
    }
}

/// An iterator over the contents of an instance of `BufRead` split on a
/// particular byte.
///
/// This struct is generally created by calling [`split`] on a `BufRead`.
/// Please see the documentation of [`split`] for more details.
///
/// [`split`]: BufRead::split
#[stable(feature = "rust1", since = "1.0.0")]
#[derive(Debug)]
pub struct Split<B> {
    buf: B,
    delim: u8,
}

#[stable(feature = "rust1", since = "1.0.0")]
impl<B: BufRead> Iterator for Split<B> {
    type Item = Result<Vec<u8>>;

    fn next(&mut self) -> Option<Result<Vec<u8>>> {
        let mut buf = Vec::new();
        match self.buf.read_until(self.delim, &mut buf) {
            Ok(0) => None,
            Ok(_n) => {
                if buf[buf.len() - 1] == self.delim {
                    buf.pop();
                }
                Some(Ok(buf))
            }
            Err(e) => Some(Err(e)),
        }
    }
}

/// An iterator over the lines of an instance of `BufRead`.
///
/// This struct is generally created by calling [`lines`] on a `BufRead`.
/// Please see the documentation of [`lines`] for more details.
///
/// [`lines`]: BufRead::lines
#[stable(feature = "rust1", since = "1.0.0")]
#[derive(Debug)]
#[cfg_attr(not(test), rustc_diagnostic_item = "IoLines")]
pub struct Lines<B> {
    buf: B,
}

#[stable(feature = "rust1", since = "1.0.0")]
impl<B: BufRead> Iterator for Lines<B> {
    type Item = Result<String>;

    fn next(&mut self) -> Option<Result<String>> {
        let mut buf = String::new();
        match self.buf.read_line(&mut buf) {
            Ok(0) => None,
            Ok(_n) => {
                if buf.ends_with('\n') {
                    buf.pop();
                    if buf.ends_with('\r') {
                        buf.pop();
                    }
                }
                Some(Ok(buf))
            }
            Err(e) => Some(Err(e)),
        }
    }
}

```

**💡 建议：**
Ensure Drop implementations never panic

#### 漏洞 #3：Potential panic in Drop implementation detected

**详情：**
- **Type:** `drop-panic`
- **Severity:** `Critical`
- **Confidence:** `90.0%`
- **Location:** `d:\漏洞挖掘\detector\project\library\std\src\sys\env\windows.rs:0`
- **检测方法：** `StaticAnalysis`

**解释：**
Drop implementation may panic, which can cause undefined behavior

**代码：**
```rust
use crate::ffi::{OsStr, OsString};
use crate::os::windows::prelude::*;
use crate::sys::pal::{c, cvt, fill_utf16_buf, to_u16s};
use crate::{fmt, io, ptr, slice};

pub struct Env {
    base: *mut c::WCHAR,
    iter: EnvIterator,
}

impl fmt::Debug for Env {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self { base: _, iter } = self;
        f.debug_list().entries(iter.clone()).finish()
    }
}

impl Iterator for Env {
    type Item = (OsString, OsString);

    fn next(&mut self) -> Option<(OsString, OsString)> {
        let Self { base: _, iter } = self;
        iter.next()
    }
}

#[derive(Clone)]
struct EnvIterator(*mut c::WCHAR);

impl Iterator for EnvIterator {
    type Item = (OsString, OsString);

    fn next(&mut self) -> Option<(OsString, OsString)> {
        let Self(cur) = self;
        loop {
            unsafe {
                if **cur == 0 {
                    return None;
                }
                let p = *cur as *const u16;
                let mut len = 0;
                while *p.add(len) != 0 {
                    len += 1;
                }
                let s = slice::from_raw_parts(p, len);
                *cur = cur.add(len + 1);

                // Windows allows environment variables to start with an equals
                // symbol (in any other position, this is the separator between
                // variable name and value). Since`s` has at least length 1 at
                // this point (because the empty string terminates the array of
                // environment variables), we can safely slice.
                let pos = match s[1..].iter().position(|&u| u == b'=' as u16).map(|p| p + 1) {
                    Some(p) => p,
                    None => continue,
                };
                return Some((
                    OsStringExt::from_wide(&s[..pos]),
                    OsStringExt::from_wide(&s[pos + 1..]),
                ));
            }
        }
    }
}

impl Drop for Env {
    fn drop(&mut self) {
        unsafe {
            c::FreeEnvironmentStringsW(self.base);
        }
    }
}

pub fn env() -> Env {
    unsafe {
        let ch = c::GetEnvironmentStringsW();
        if ch.is_null() {
            panic!("failure getting env string from OS: {}", io::Error::last_os_error());
        }
        Env { base: ch, iter: EnvIterator(ch) }
    }
}

pub fn getenv(k: &OsStr) -> Option<OsString> {
    let k = to_u16s(k).ok()?;
    fill_utf16_buf(
        |buf, sz| unsafe { c::GetEnvironmentVariableW(k.as_ptr(), buf, sz) },
        OsStringExt::from_wide,
    )
    .ok()
}

pub unsafe fn setenv(k: &OsStr, v: &OsStr) -> io::Result<()> {
    // SAFETY: We ensure that k and v are null-terminated wide strings.
    unsafe {
        let k = to_u16s(k)?;
        let v = to_u16s(v)?;

        cvt(c::SetEnvironmentVariableW(k.as_ptr(), v.as_ptr())).map(drop)
    }
}

pub unsafe fn unsetenv(n: &OsStr) -> io::Result<()> {
    // SAFETY: We ensure that v is a null-terminated wide strings.
    unsafe {
        let v = to_u16s(n)?;
        cvt(c::SetEnvironmentVariableW(v.as_ptr(), ptr::null())).map(drop)
    }
}

```

**💡 建议：**
Ensure Drop implementations never panic

#### 漏洞 #4：Potential panic in Drop implementation detected

**详情：**
- **Type:** `drop-panic`
- **Severity:** `Critical`
- **Confidence:** `90.0%`
- **Location:** `d:\漏洞挖掘\detector\project\library\std\src\sys\fs\vexos.rs:0`
- **检测方法：** `StaticAnalysis`

**解释：**
Drop implementation may panic, which can cause undefined behavior

**代码：**
```rust
use crate::ffi::{OsString, c_char};
use crate::fmt;
use crate::fs::TryLockError;
use crate::hash::Hash;
use crate::io::{self, BorrowedCursor, IoSlice, IoSliceMut, SeekFrom};
use crate::path::{Path, PathBuf};
use crate::sys::common::small_c_string::run_path_with_cstr;
use crate::sys::time::SystemTime;
use crate::sys::{unsupported, unsupported_err};

#[expect(dead_code)]
#[path = "unsupported.rs"]
mod unsupported_fs;
pub use unsupported_fs::{
    DirBuilder, FileTimes, canonicalize, link, readlink, remove_dir_all, rename, rmdir, symlink,
    unlink,
};

/// VEXos file descriptor.
///
/// This stores an opaque pointer to a [FatFs file object structure] managed by VEXos
/// representing an open file on disk.
///
/// [FatFs file object structure]: https://github.com/Xilinx/embeddedsw/blob/master/lib/sw_services/xilffs/src/include/ff.h?rgh-link-date=2025-09-23T20%3A03%3A43Z#L215
///
/// # Safety
///
/// Since this platform uses a pointer to to an internal filesystem structure with a lifetime
/// associated with it (rather than a UNIX-style file descriptor table), care must be taken to
/// ensure that the pointer held by `FileDesc` is valid for as long as it exists.
#[derive(Debug)]
struct FileDesc(*mut vex_sdk::FIL);

// SAFETY: VEXos's FDs can be used on a thread other than the one they were created on.
unsafe impl Send for FileDesc {}
// SAFETY: We assume an environment without threads (i.e. no RTOS).
// (If there were threads, it is possible that a mutex would be required.)
unsafe impl Sync for FileDesc {}

pub struct File {
    fd: FileDesc,
}

#[derive(Clone)]
pub enum FileAttr {
    Dir,
    File { size: u64 },
}

pub struct ReadDir(!);

pub struct DirEntry {
    path: PathBuf,
}

#[derive(Clone, Debug)]
pub struct OpenOptions {
    read: bool,
    write: bool,
    append: bool,
    truncate: bool,
    create: bool,
    create_new: bool,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct FilePermissions {}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct FileType {
    is_dir: bool,
}

impl FileAttr {
    pub fn size(&self) -> u64 {
        match self {
            Self::File { size } => *size,
            Self::Dir => 0,
        }
    }

    pub fn perm(&self) -> FilePermissions {
        FilePermissions {}
    }

    pub fn file_type(&self) -> FileType {
        FileType { is_dir: matches!(self, FileAttr::Dir) }
    }

    pub fn modified(&self) -> io::Result<SystemTime> {
        unsupported()
    }

    pub fn accessed(&self) -> io::Result<SystemTime> {
        unsupported()
    }

    pub fn created(&self) -> io::Result<SystemTime> {
        unsupported()
    }
}

impl FilePermissions {
    pub fn readonly(&self) -> bool {
        false
    }

    pub fn set_readonly(&mut self, _readonly: bool) {
        panic!("Permissions do not exist")
    }
}

impl FileType {
    pub fn is_dir(&self) -> bool {
        self.is_dir
    }

    pub fn is_file(&self) -> bool {
        !self.is_dir
    }

    pub fn is_symlink(&self) -> bool {
        // No symlinks in VEXos - entries are either files or directories.
        false
    }
}

impl fmt::Debug for ReadDir {
    fn fmt(&self, _f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0
    }
}

impl Iterator for ReadDir {
    type Item = io::Result<DirEntry>;

    fn next(&mut self) -> Option<io::Result<DirEntry>> {
        self.0
    }
}

impl DirEntry {
    pub fn path(&self) -> PathBuf {
        self.path.clone()
    }

    pub fn file_name(&self) -> OsString {
        self.path.file_name().unwrap_or_default().into()
    }

    pub fn metadata(&self) -> io::Result<FileAttr> {
        stat(&self.path)
    }

    pub fn file_type(&self) -> io::Result<FileType> {
        Ok(self.metadata()?.file_type())
    }
}

impl OpenOptions {
    pub fn new() -> OpenOptions {
        OpenOptions {
            read: false,
            write: false,
            append: false,
            truncate: false,
            create: false,
            create_new: false,
        }
    }

    pub fn read(&mut self, read: bool) {
        self.read = read;
    }
    pub fn write(&mut self, write: bool) {
        self.write = write;
    }
    pub fn append(&mut self, append: bool) {
        self.append = append;
    }
    pub fn truncate(&mut self, truncate: bool) {
        self.truncate = truncate;
    }
    pub fn create(&mut self, create: bool) {
        self.create = create;
    }
    pub fn create_new(&mut self, create_new: bool) {
        self.create_new = create_new;
    }
}

impl File {
    pub fn open(path: &Path, opts: &OpenOptions) -> io::Result<File> {
        run_path_with_cstr(path, &|path| {
            // Enforce the invariants of `create_new`/`create`.
            //
            // Since VEXos doesn't have anything akin to POSIX's `oflags`, we need to enforce
            // the requirements that `create_new` can't have an existing file and `!create`
            // doesn't create a file ourselves.
            if !opts.read && (opts.write || opts.append) && (opts.create_new || !opts.create) {
                let status = unsafe { vex_sdk::vexFileStatus(path.as_ptr()) };

                if opts.create_new && status != 0 {
                    return Err(io::const_error!(io::ErrorKind::AlreadyExists, "file exists",));
                } else if !opts.create && status == 0 {
                    return Err(io::const_error!(
                        io::ErrorKind::NotFound,
                        "no such file or directory",
                    ));
                }
            }

            let file = match opts {
                // read + write - unsupported
                OpenOptions { read: true, write: true, .. } => {
                    return Err(io::const_error!(
                        io::ErrorKind::InvalidInput,
                        "opening files with read and write access is unsupported on this target",
                    ));
                }

                // read
                OpenOptions {
                    read: true,
                    write: false,
                    append: _,
                    truncate: false,
                    create: false,
                    create_new: false,
                } => unsafe { vex_sdk::vexFileOpen(path.as_ptr(), c"".as_ptr()) },

                // append
                OpenOptions {
                    read: false,
                    write: _,
                    append: true,
                    truncate: false,
                    create: _,
                    create_new: _,
                } => unsafe { vex_sdk::vexFileOpenWrite(path.as_ptr()) },

                // write
                OpenOptions {
                    read: false,
                    write: true,
                    append: false,
                    truncate,
                    create: _,
                    create_new: _,
                } => unsafe {
                    if *truncate {
                        vex_sdk::vexFileOpenCreate(path.as_ptr())
                    } else {
                        // Open in append, but jump to the start of the file.
                        let fd = vex_sdk::vexFileOpenWrite(path.as_ptr());
                        vex_sdk::vexFileSeek(fd, 0, 0);
                        fd
                    }
                },

                _ => {
                    return Err(io::const_error!(io::ErrorKind::InvalidInput, "invalid argument"));
                }
            };

            if file.is_null() {
                Err(io::const_error!(io::ErrorKind::NotFound, "could not open file"))
            } else {
                Ok(Self { fd: FileDesc(file) })
            }
        })
    }

    pub fn file_attr(&self) -> io::Result<FileAttr> {
        // `vexFileSize` returns -1 upon error, so u64::try_from will fail on error.
        if let Ok(size) = u64::try_from(unsafe {
            // SAFETY: `self.fd` contains a valid pointer to `FIL` for this struct's lifetime.
            vex_sdk::vexFileSize(self.fd.0)
        }) {
            Ok(FileAttr::File { size })
        } else {
            Err(io::const_error!(io::ErrorKind::InvalidData, "failed to get file size"))
        }
    }

    pub fn fsync(&self) -> io::Result<()> {
        self.flush()
    }

    pub fn datasync(&self) -> io::Result<()> {
        self.flush()
    }

    pub fn lock(&self) -> io::Result<()> {
        unsupported()
    }

    pub fn lock_shared(&self) -> io::Result<()> {
        unsupported()
    }

    pub fn try_lock(&self) -> Result<(), TryLockError> {
        Err(TryLockError::Error(unsupported_err()))
    }

    pub fn try_lock_shared(&self) -> Result<(), TryLockError> {
        Err(TryLockError::Error(unsupported_err()))
    }

    pub fn unlock(&self) -> io::Result<()> {
        unsupported()
    }

    pub fn truncate(&self, _size: u64) -> io::Result<()> {
        unsupported()
    }

    pub fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        let len = buf.len() as u32;
        let buf_ptr = buf.as_mut_ptr();
        let read = unsafe {
            // SAFETY: `self.fd` contains a valid pointer to `FIL` for this struct's lifetime.
            vex_sdk::vexFileRead(buf_ptr.cast::<c_char>(), 1, len, self.fd.0)
        };

        if read < 0 {
            Err(io::const_error!(io::ErrorKind::Other, "could not read from file"))
        } else {
            Ok(read as usize)
        }
    }

    pub fn read_vectored(&self, bufs: &mut [IoSliceMut<'_>]) -> io::Result<usize> {
        crate::io::default_read_vectored(|b| self.read(b), bufs)
    }

    #[inline]
    pub fn is_read_vectored(&self) -> bool {
        false
    }

    pub fn read_buf(&self, cursor: BorrowedCursor<'_>) -> io::Result<()> {
        crate::io::default_read_buf(|b| self.read(b), cursor)
    }

    pub fn write(&self, buf: &[u8]) -> io::Result<usize> {
        let len = buf.len() as u32;
        let buf_ptr = buf.as_ptr();
        let written = unsafe {
            // SAFETY: `self.fd` contains a valid pointer to `FIL` for this struct's lifetime.
            vex_sdk::vexFileWrite(buf_ptr.cast_mut().cast::<c_char>(), 1, len, self.fd.0)
        };

        if written < 0 {
            Err(io::const_error!(io::ErrorKind::Other, "could not write to file"))
        } else {
            Ok(written as usize)
        }
    }

    pub fn write_vectored(&self, bufs: &[IoSlice<'_>]) -> io::Result<usize> {
        crate::io::default_write_vectored(|b| self.write(b), bufs)
    }

    #[inline]
    pub fn is_write_vectored(&self) -> bool {
        false
    }

    pub fn flush(&self) -> io::Result<()> {
        unsafe {
            // SAFETY: `self.fd` contains a valid pointer to `FIL` for this struct's lifetime.
            vex_sdk::vexFileSync(self.fd.0);
        }
        Ok(())
    }

    pub fn tell(&self) -> io::Result<u64> {
        // SAFETY: `self.fd` contains a valid pointer to `FIL` for this struct's lifetime.
        let position = unsafe { vex_sdk::vexFileTell(self.fd.0) };

        position.try_into().map_err(|_| {
            io::const_error!(io::ErrorKind::InvalidData, "failed to get current location in file")
        })
    }

    pub fn size(&self) -> Option<io::Result<u64>> {
        None
    }

    pub fn seek(&self, pos: SeekFrom) -> io::Result<u64> {
        const SEEK_SET: i32 = 0;
        const SEEK_CUR: i32 = 1;
        const SEEK_END: i32 = 2;

        fn try_convert_offset<T: TryInto<u32>>(offset: T) -> io::Result<u32> {
            offset.try_into().map_err(|_| {
                io::const_error!(
                    io::ErrorKind::InvalidInput,
                    "cannot seek to an offset too large to fit in a 32 bit integer",
                )
            })
        }

        // SAFETY: `self.fd` contains a valid pointer to `FIL` for this struct's lifetime.
        match pos {
            SeekFrom::Start(offset) => unsafe {
                map_fresult(vex_sdk::vexFileSeek(self.fd.0, try_convert_offset(offset)?, SEEK_SET))?
            },
            SeekFrom::End(offset) => unsafe {
                if offset >= 0 {
                    map_fresult(vex_sdk::vexFileSeek(
                        self.fd.0,
                        try_convert_offset(offset)?,
                        SEEK_END,
                    ))?
                } else {
                    // `vexFileSeek` does not support seeking with negative offset, meaning
                    // we have to calculate the offset from the end of the file ourselves.

                    // Seek to the end of the file to get the end position in the open buffer.
                    map_fresult(vex_sdk::vexFileSeek(self.fd.0, 0, SEEK_END))?;
                    let end_position = self.tell()?;

                    map_fresult(vex_sdk::vexFileSeek(
                        self.fd.0,
                        // NOTE: Files internally use a 32-bit representation for stream
                        // position, so `end_position as i64` should never overflow.
                        try_convert_offset(end_position as i64 + offset)?,
                        SEEK_SET,
                    ))?
                }
            },
            SeekFrom::Current(offset) => unsafe {
                if offset >= 0 {
                    map_fresult(vex_sdk::vexFileSeek(
                        self.fd.0,
                        try_convert_offset(offset)?,
                        SEEK_CUR,
                    ))?
                } else {
                    // `vexFileSeek` does not support seeking with negative offset, meaning
                    // we have to calculate the offset from the stream position ourselves.
                    map_fresult(vex_sdk::vexFileSeek(
                        self.fd.0,
                        try_convert_offset((self.tell()? as i64) + offset)?,
                        SEEK_SET,
                    ))?
                }
            },
        }

        Ok(self.tell()?)
    }

    pub fn duplicate(&self) -> io::Result<File> {
        unsupported()
    }

    pub fn set_permissions(&self, _perm: FilePermissions) -> io::Result<()> {
        unsupported()
    }

    pub fn set_times(&self, _times: FileTimes) -> io::Result<()> {
        unsupported()
    }
}

impl fmt::Debug for File {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("File").field("fd", &self.fd.0).finish()
    }
}
impl Drop for File {
    fn drop(&mut self) {
        unsafe { vex_sdk::vexFileClose(self.fd.0) };
    }
}

pub fn readdir(_p: &Path) -> io::Result<ReadDir> {
    // While there *is* a userspace function for reading file directories,
    // the necessary implementation cannot currently be done cleanly, as
    // VEXos does not expose directory length to user programs.
    //
    // This means that we would need to create a large fixed-length buffer
    // and hope that the folder's contents didn't exceed that buffer's length,
    // which obviously isn't behavior we want to rely on in the standard library.
    unsupported()
}

pub fn set_perm(_p: &Path, _perm: FilePermissions) -> io::Result<()> {
    unsupported()
}

pub fn set_times(_p: &Path, _times: FileTimes) -> io::Result<()> {
    unsupported()
}

pub fn set_times_nofollow(_p: &Path, _times: FileTimes) -> io::Result<()> {
    unsupported()
}

pub fn exists(path: &Path) -> io::Result<bool> {
    run_path_with_cstr(path, &|path| Ok(unsafe { vex_sdk::vexFileStatus(path.as_ptr()) } != 0))
}

pub fn stat(p: &Path) -> io::Result<FileAttr> {
    // `vexFileStatus` returns 3 if the given path is a directory, 1 if the path is a
    // file, or 0 if no such path exists.
    const FILE_STATUS_DIR: u32 = 3;

    run_path_with_cstr(p, &|c_path| {
        let file_type = unsafe { vex_sdk::vexFileStatus(c_path.as_ptr()) };

        // We can't get the size if its a directory because we cant open it as a file
        if file_type == FILE_STATUS_DIR {
            Ok(FileAttr::Dir)
        } else {
            let mut opts = OpenOptions::new();
            opts.read(true);
            let file = File::open(p, &opts)?;
            file.file_attr()
        }
    })
}

pub fn lstat(p: &Path) -> io::Result<FileAttr> {
    // Symlinks aren't supported in this filesystem
    stat(p)
}

// Cannot use `copy` from `common` here, since `File::set_permissions` is unsupported on this target.
pub fn copy(from: &Path, to: &Path) -> io::Result<u64> {
    use crate::fs::File;

    // NOTE: If `from` is a directory, this call should fail due to vexFileOpen* returning null.
    let mut reader = File::open(from)?;
    let mut writer = File::create(to)?;

    io::copy(&mut reader, &mut writer)
}

fn map_fresult(fresult: vex_sdk::FRESULT) -> io::Result<()> {
    // VEX uses a derivative of FatFs (Xilinx's xilffs library) for filesystem operations.
    match fresult {
        vex_sdk::FRESULT::FR_OK => Ok(()),
        vex_sdk::FRESULT::FR_DISK_ERR => Err(io::const_error!(
            io::ErrorKind::Uncategorized,
            "internal function reported an unrecoverable hard error",
        )),
        vex_sdk::FRESULT::FR_INT_ERR => Err(io::const_error!(
            io::ErrorKind::Uncategorized,
            "internal error in filesystem runtime",
        )),
        vex_sdk::FRESULT::FR_NOT_READY => Err(io::const_error!(
            io::ErrorKind::Uncategorized,
            "the storage device could not be prepared to work",
        )),
        vex_sdk::FRESULT::FR_NO_FILE => Err(io::const_error!(
            io::ErrorKind::NotFound,
            "could not find the file in the directory"
        )),
        vex_sdk::FRESULT::FR_NO_PATH => Err(io::const_error!(
            io::ErrorKind::NotFound,
            "a directory in the path name could not be found",
        )),
        vex_sdk::FRESULT::FR_INVALID_NAME => Err(io::const_error!(
            io::ErrorKind::InvalidInput,
            "the given string is invalid as a path name",
        )),
        vex_sdk::FRESULT::FR_DENIED => Err(io::const_error!(
            io::ErrorKind::PermissionDenied,
            "the required access for this operation was denied",
        )),
        vex_sdk::FRESULT::FR_EXIST => Err(io::const_error!(
            io::ErrorKind::AlreadyExists,
            "an object with the same name already exists in the directory",
        )),
        vex_sdk::FRESULT::FR_INVALID_OBJECT => Err(io::const_error!(
            io::ErrorKind::Uncategorized,
            "invalid or null file/directory object",
        )),
        vex_sdk::FRESULT::FR_WRITE_PROTECTED => Err(io::const_error!(
            io::ErrorKind::PermissionDenied,
            "a write operation was performed on write-protected media",
        )),
        vex_sdk::FRESULT::FR_INVALID_DRIVE => Err(io::const_error!(
            io::ErrorKind::InvalidInput,
            "an invalid drive number was specified in the path name",
        )),
        vex_sdk::FRESULT::FR_NOT_ENABLED => Err(io::const_error!(
            io::ErrorKind::Uncategorized,
            "work area for the logical drive has not been registered",
        )),
        vex_sdk::FRESULT::FR_NO_FILESYSTEM => Err(io::const_error!(
            io::ErrorKind::Uncategorized,
            "valid FAT volume could not be found on the drive",
        )),
        vex_sdk::FRESULT::FR_MKFS_ABORTED => Err(io::const_error!(
            io::ErrorKind::Uncategorized,
            "failed to create filesystem volume"
        )),
        vex_sdk::FRESULT::FR_TIMEOUT => Err(io::const_error!(
            io::ErrorKind::TimedOut,
            "the function was canceled due to a timeout of thread-safe control",
        )),
        vex_sdk::FRESULT::FR_LOCKED => Err(io::const_error!(
            io::ErrorKind::Uncategorized,
            "the operation to the object was rejected by file sharing control",
        )),
        vex_sdk::FRESULT::FR_NOT_ENOUGH_CORE => {
            Err(io::const_error!(io::ErrorKind::OutOfMemory, "not enough memory for the operation"))
        }
        vex_sdk::FRESULT::FR_TOO_MANY_OPEN_FILES => Err(io::const_error!(
            io::ErrorKind::Uncategorized,
            "maximum number of open files has been reached",
        )),
        vex_sdk::FRESULT::FR_INVALID_PARAMETER => {
            Err(io::const_error!(io::ErrorKind::InvalidInput, "a given parameter was invalid"))
        }
        _ => unreachable!(), // C-style enum
    }
}

```

**💡 建议：**
Ensure Drop implementations never panic

#### 漏洞 #5：Potential panic in Drop implementation detected

**详情：**
- **Type:** `drop-panic`
- **Severity:** `Critical`
- **Confidence:** `90.0%`
- **Location:** `d:\漏洞挖掘\detector\project\library\std\src\sys\pal\unix\stack_overflow\thread_info.rs:0`
- **检测方法：** `StaticAnalysis`

**解释：**
Drop implementation may panic, which can cause undefined behavior

**代码：**
```rust
//! TLS, but async-signal-safe.
//!
//! Unfortunately, because thread local storage isn't async-signal-safe, we
//! cannot soundly use it in our stack overflow handler. While this works
//! without problems on most platforms, it can lead to undefined behaviour
//! on others (such as GNU/Linux). Luckily, the POSIX specification documents
//! two thread-specific values that can be accessed in asynchronous signal
//! handlers: the value of `pthread_self()` and the address of `errno`. As
//! `pthread_t` is an opaque platform-specific type, we use the address of
//! `errno` here. As it is thread-specific and does not change over the
//! lifetime of a thread, we can use `&errno` as a key for a `BTreeMap`
//! that stores thread-specific data.
//!
//! Concurrent access to this map is synchronized by two locks – an outer
//! [`Mutex`] and an inner spin lock that also remembers the identity of
//! the lock owner:
//! * The spin lock is the primary means of synchronization: since it only
//!   uses native atomics, it can be soundly used inside the signal handle
//!   as opposed to [`Mutex`], which might not be async-signal-safe.
//! * The [`Mutex`] prevents busy-waiting in the setup logic, as all accesses
//!   there are performed with the [`Mutex`] held, which makes the spin-lock
//!   redundant in the common case.
//! * Finally, by using the `errno` address as the locked value of the spin
//!   lock, we can detect cases where a SIGSEGV occurred while the thread
//!   info is being modified.

use crate::collections::BTreeMap;
use crate::hint::spin_loop;
use crate::ops::Range;
use crate::sync::Mutex;
use crate::sync::atomic::{AtomicUsize, Ordering};
use crate::sys::os::errno_location;

pub struct ThreadInfo {
    pub guard_page_range: Range<usize>,
    pub thread_name: Option<Box<str>>,
}

static LOCK: Mutex<()> = Mutex::new(());
static SPIN_LOCK: AtomicUsize = AtomicUsize::new(0);
// This uses a `BTreeMap` instead of a hashmap since it supports constant
// initialization and automatically reduces the amount of memory used when
// items are removed.
static mut THREAD_INFO: BTreeMap<usize, ThreadInfo> = BTreeMap::new();

struct UnlockOnDrop;

impl Drop for UnlockOnDrop {
    fn drop(&mut self) {
        SPIN_LOCK.store(0, Ordering::Release);
    }
}

/// Get the current thread's information, if available.
///
/// Calling this function might freeze other threads if they attempt to modify
/// their thread information. Thus, the caller should ensure that the process
/// is aborted shortly after this function is called.
///
/// This function is guaranteed to be async-signal-safe if `f` is too.
pub fn with_current_info<R>(f: impl FnOnce(Option<&ThreadInfo>) -> R) -> R {
    let this = errno_location().addr();
    let mut attempt = 0;
    let _guard = loop {
        // If we are just spinning endlessly, it's very likely that the thread
        // modifying the thread info map has a lower priority than us and will
        // not continue until we stop running. Just give up in that case.
        if attempt == 10_000_000 {
            rtprintpanic!("deadlock in SIGSEGV handler");
            return f(None);
        }

        match SPIN_LOCK.compare_exchange(0, this, Ordering::Acquire, Ordering::Relaxed) {
            Ok(_) => break UnlockOnDrop,
            Err(owner) if owner == this => {
                rtabort!("a thread received SIGSEGV while modifying its stack overflow information")
            }
            // Spin until the lock can be acquired – there is nothing better to
            // do. This is unfortunately a priority hole, but a stack overflow
            // is a fatal error anyway.
            Err(_) => {
                spin_loop();
                attempt += 1;
            }
        }
    };

    // SAFETY: we own the spin lock, so `THREAD_INFO` cannot not be aliased.
    let thread_info = unsafe { &*(&raw const THREAD_INFO) };
    f(thread_info.get(&this))
}

fn spin_lock_in_setup(this: usize) -> UnlockOnDrop {
    loop {
        match SPIN_LOCK.compare_exchange(0, this, Ordering::Acquire, Ordering::Relaxed) {
            Ok(_) => return UnlockOnDrop,
            Err(owner) if owner == this => {
                unreachable!("the thread info setup logic isn't recursive")
            }
            // This function is always called with the outer lock held,
            // meaning the only time locking can fail is if another thread has
            // encountered a stack overflow. Since that will abort the process,
            // we just stop the current thread until that time. We use `pause`
            // instead of spinning to avoid priority inversion.
            // SAFETY: this doesn't have any safety preconditions.
            Err(_) => drop(unsafe { libc::pause() }),
        }
    }
}

pub fn set_current_info(guard_page_range: Range<usize>, thread_name: Option<Box<str>>) {
    let this = errno_location().addr();
    let _lock_guard = LOCK.lock();
    let _spin_guard = spin_lock_in_setup(this);

    // SAFETY: we own the spin lock, so `THREAD_INFO` cannot be aliased.
    let thread_info = unsafe { &mut *(&raw mut THREAD_INFO) };
    thread_info.insert(this, ThreadInfo { guard_page_range, thread_name });
}

pub fn delete_current_info() {
    let this = errno_location().addr();
    let _lock_guard = LOCK.lock();
    let _spin_guard = spin_lock_in_setup(this);

    // SAFETY: we own the spin lock, so `THREAD_INFO` cannot not be aliased.
    let thread_info = unsafe { &mut *(&raw mut THREAD_INFO) };
    thread_info.remove(&this);
}

```

**💡 建议：**
Ensure Drop implementations never panic

#### 漏洞 #6：Potential panic in Drop implementation detected

**详情：**
- **Type:** `drop-panic`
- **Severity:** `Critical`
- **Confidence:** `90.0%`
- **Location:** `d:\漏洞挖掘\detector\project\library\std\src\sys\pal\unix\stack_overflow.rs:0`
- **检测方法：** `StaticAnalysis`

**解释：**
Drop implementation may panic, which can cause undefined behavior

**代码：**
```rust
#![cfg_attr(test, allow(dead_code))]

pub use self::imp::{cleanup, init};
use self::imp::{drop_handler, make_handler};

pub struct Handler {
    data: *mut libc::c_void,
}

impl Handler {
    pub unsafe fn new(thread_name: Option<Box<str>>) -> Handler {
        make_handler(false, thread_name)
    }

    fn null() -> Handler {
        Handler { data: crate::ptr::null_mut() }
    }
}

impl Drop for Handler {
    fn drop(&mut self) {
        unsafe {
            drop_handler(self.data);
        }
    }
}

#[cfg(all(
    not(miri),
    any(
        target_os = "linux",
        target_os = "freebsd",
        target_os = "hurd",
        target_os = "macos",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "solaris",
        target_os = "illumos",
    ),
))]
mod thread_info;

// miri doesn't model signals nor stack overflows and this code has some
// synchronization properties that we don't want to expose to user code,
// hence we disable it on miri.
#[cfg(all(
    not(miri),
    any(
        target_os = "linux",
        target_os = "freebsd",
        target_os = "hurd",
        target_os = "macos",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "solaris",
        target_os = "illumos",
    )
))]
mod imp {
    use libc::{
        MAP_ANON, MAP_FAILED, MAP_FIXED, MAP_PRIVATE, PROT_NONE, PROT_READ, PROT_WRITE, SA_ONSTACK,
        SA_SIGINFO, SIG_DFL, SIGBUS, SIGSEGV, SS_DISABLE, sigaction, sigaltstack, sighandler_t,
    };
    #[cfg(not(all(target_os = "linux", target_env = "gnu")))]
    use libc::{mmap as mmap64, mprotect, munmap};
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    use libc::{mmap64, mprotect, munmap};

    use super::Handler;
    use super::thread_info::{delete_current_info, set_current_info, with_current_info};
    use crate::ops::Range;
    use crate::sync::atomic::{Atomic, AtomicBool, AtomicPtr, AtomicUsize, Ordering};
    use crate::sys::pal::unix::os;
    use crate::{io, mem, ptr};

    // Signal handler for the SIGSEGV and SIGBUS handlers. We've got guard pages
    // (unmapped pages) at the end of every thread's stack, so if a thread ends
    // up running into the guard page it'll trigger this handler. We want to
    // detect these cases and print out a helpful error saying that the stack
    // has overflowed. All other signals, however, should go back to what they
    // were originally supposed to do.
    //
    // This handler currently exists purely to print an informative message
    // whenever a thread overflows its stack. We then abort to exit and
    // indicate a crash, but to avoid a misleading SIGSEGV that might lead
    // users to believe that unsafe code has accessed an invalid pointer; the
    // SIGSEGV encountered when overflowing the stack is expected and
    // well-defined.
    //
    // If this is not a stack overflow, the handler un-registers itself and
    // then returns (to allow the original signal to be delivered again).
    // Returning from this kind of signal handler is technically not defined
    // to work when reading the POSIX spec strictly, but in practice it turns
    // out many large systems and all implementations allow returning from a
    // signal handler to work. For a more detailed explanation see the
    // comments on #26458.
    /// SIGSEGV/SIGBUS entry point
    /// # Safety
    /// Rust doesn't call this, it *gets called*.
    #[forbid(unsafe_op_in_unsafe_fn)]
    unsafe extern "C" fn signal_handler(
        signum: libc::c_int,
        info: *mut libc::siginfo_t,
        _data: *mut libc::c_void,
    ) {
        // SAFETY: this pointer is provided by the system and will always point to a valid `siginfo_t`.
        let fault_addr = unsafe { (*info).si_addr().addr() };

        // `with_current_info` expects that the process aborts after it is
        // called. If the signal was not caused by a memory access, this might
        // not be true. We detect this by noticing that the `si_addr` field is
        // zero if the signal is synthetic.
        if fault_addr != 0 {
            with_current_info(|thread_info| {
                // If the faulting address is within the guard page, then we print a
                // message saying so and abort.
                if let Some(thread_info) = thread_info
                    && thread_info.guard_page_range.contains(&fault_addr)
                {
                    let name = thread_info.thread_name.as_deref().unwrap_or("<unknown>");
                    let tid = crate::thread::current_os_id();
                    rtprintpanic!("\nthread '{name}' ({tid}) has overflowed its stack\n");
                    rtabort!("stack overflow");
                }
            })
        }

        // Unregister ourselves by reverting back to the default behavior.
        // SAFETY: assuming all platforms define struct sigaction as "zero-initializable"
        let mut action: sigaction = unsafe { mem::zeroed() };
        action.sa_sigaction = SIG_DFL;
        // SAFETY: pray this is a well-behaved POSIX implementation of fn sigaction
        unsafe { sigaction(signum, &action, ptr::null_mut()) };

        // See comment above for why this function returns.
    }

    static PAGE_SIZE: Atomic<usize> = AtomicUsize::new(0);
    static MAIN_ALTSTACK: Atomic<*mut libc::c_void> = AtomicPtr::new(ptr::null_mut());
    static NEED_ALTSTACK: Atomic<bool> = AtomicBool::new(false);

    /// # Safety
    /// Must be called only once
    #[forbid(unsafe_op_in_unsafe_fn)]
    pub unsafe fn init() {
        PAGE_SIZE.store(os::page_size(), Ordering::Relaxed);

        let mut guard_page_range = unsafe { install_main_guard() };

        // Even for panic=immediate-abort, installing the guard pages is important for soundness.
        // That said, we do not care about giving nice stackoverflow messages via our custom
        // signal handler, just exit early and let the user enjoy the segfault.
        if cfg!(panic = "immediate-abort") {
            return;
        }

        // SAFETY: assuming all platforms define struct sigaction as "zero-initializable"
        let mut action: sigaction = unsafe { mem::zeroed() };
        for &signal in &[SIGSEGV, SIGBUS] {
            // SAFETY: just fetches the current signal handler into action
            unsafe { sigaction(signal, ptr::null_mut(), &mut action) };
            // Configure our signal handler if one is not already set.
            if action.sa_sigaction == SIG_DFL {
                if !NEED_ALTSTACK.load(Ordering::Relaxed) {
                    // haven't set up our sigaltstack yet
                    NEED_ALTSTACK.store(true, Ordering::Release);
                    let handler = unsafe { make_handler(true, None) };
                    MAIN_ALTSTACK.store(handler.data, Ordering::Relaxed);
                    mem::forget(handler);

                    if let Some(guard_page_range) = guard_page_range.take() {
                        set_current_info(guard_page_range, Some(Box::from("main")));
                    }
                }

                action.sa_flags = SA_SIGINFO | SA_ONSTACK;
                action.sa_sigaction = signal_handler
                    as unsafe extern "C" fn(i32, *mut libc::siginfo_t, *mut libc::c_void)
                    as sighandler_t;
                // SAFETY: only overriding signals if the default is set
                unsafe { sigaction(signal, &action, ptr::null_mut()) };
            }
        }
    }

    /// # Safety
    /// Must be called only once
    #[forbid(unsafe_op_in_unsafe_fn)]
    pub unsafe fn cleanup() {
        if cfg!(panic = "immediate-abort") {
            return;
        }
        // FIXME: I probably cause more bugs than I'm worth!
        // see https://github.com/rust-lang/rust/issues/111272
        unsafe { drop_handler(MAIN_ALTSTACK.load(Ordering::Relaxed)) };
    }

    unsafe fn get_stack() -> libc::stack_t {
        // OpenBSD requires this flag for stack mapping
        // otherwise the said mapping will fail as a no-op on most systems
        // and has a different meaning on FreeBSD
        #[cfg(any(
            target_os = "openbsd",
            target_os = "netbsd",
            target_os = "linux",
            target_os = "dragonfly",
        ))]
        let flags = MAP_PRIVATE | MAP_ANON | libc::MAP_STACK;
        #[cfg(not(any(
            target_os = "openbsd",
            target_os = "netbsd",
            target_os = "linux",
            target_os = "dragonfly",
        )))]
        let flags = MAP_PRIVATE | MAP_ANON;

        let sigstack_size = sigstack_size();
        let page_size = PAGE_SIZE.load(Ordering::Relaxed);

        let stackp = mmap64(
            ptr::null_mut(),
            sigstack_size + page_size,
            PROT_READ | PROT_WRITE,
            flags,
            -1,
            0,
        );
        if stackp == MAP_FAILED {
            panic!("failed to allocate an alternative stack: {}", io::Error::last_os_error());
        }
        let guard_result = libc::mprotect(stackp, page_size, PROT_NONE);
        if guard_result != 0 {
            panic!("failed to set up alternative stack guard page: {}", io::Error::last_os_error());
        }
        let stackp = stackp.add(page_size);

        libc::stack_t { ss_sp: stackp, ss_flags: 0, ss_size: sigstack_size }
    }

    /// # Safety
    /// Mutates the alternate signal stack
    #[forbid(unsafe_op_in_unsafe_fn)]
    pub unsafe fn make_handler(main_thread: bool, thread_name: Option<Box<str>>) -> Handler {
        if cfg!(panic = "immediate-abort") || !NEED_ALTSTACK.load(Ordering::Acquire) {
            return Handler::null();
        }

        if !main_thread {
            if let Some(guard_page_range) = unsafe { current_guard() } {
                set_current_info(guard_page_range, thread_name);
            }
        }

        // SAFETY: assuming stack_t is zero-initializable
        let mut stack = unsafe { mem::zeroed() };
        // SAFETY: reads current stack_t into stack
        unsafe { sigaltstack(ptr::null(), &mut stack) };
        // Configure alternate signal stack, if one is not already set.
        if stack.ss_flags & SS_DISABLE != 0 {
            // SAFETY: We warned our caller this would happen!
            unsafe {
                stack = get_stack();
                sigaltstack(&stack, ptr::null_mut());
            }
            Handler { data: stack.ss_sp as *mut libc::c_void }
        } else {
            Handler::null()
        }
    }

    /// # Safety
    /// Must be called
    /// - only with our handler or nullptr
    /// - only when done with our altstack
    /// This disables the alternate signal stack!
    #[forbid(unsafe_op_in_unsafe_fn)]
    pub unsafe fn drop_handler(data: *mut libc::c_void) {
        if !data.is_null() {
            let sigstack_size = sigstack_size();
            let page_size = PAGE_SIZE.load(Ordering::Relaxed);
            let disabling_stack = libc::stack_t {
                ss_sp: ptr::null_mut(),
                ss_flags: SS_DISABLE,
                // Workaround for bug in macOS implementation of sigaltstack
                // UNIX2003 which returns ENOMEM when disabling a stack while
                // passing ss_size smaller than MINSIGSTKSZ. According to POSIX
                // both ss_sp and ss_size should be ignored in this case.
                ss_size: sigstack_size,
            };
            // SAFETY: we warned the caller this disables the alternate signal stack!
            unsafe { sigaltstack(&disabling_stack, ptr::null_mut()) };
            // SAFETY: We know from `get_stackp` that the alternate stack we installed is part of
            // a mapping that started one page earlier, so walk back a page and unmap from there.
            unsafe { munmap(data.sub(page_size), sigstack_size + page_size) };
        }

        delete_current_info();
    }

    /// Modern kernels on modern hardware can have dynamic signal stack sizes.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn sigstack_size() -> usize {
        let dynamic_sigstksz = unsafe { libc::getauxval(libc::AT_MINSIGSTKSZ) };
        // If getauxval couldn't find the entry, it returns 0,
        // so take the higher of the "constant" and auxval.
        // This transparently supports older kernels which don't provide AT_MINSIGSTKSZ
        libc::SIGSTKSZ.max(dynamic_sigstksz as _)
    }

    /// Not all OS support hardware where this is needed.
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    fn sigstack_size() -> usize {
        libc::SIGSTKSZ
    }

    #[cfg(any(target_os = "solaris", target_os = "illumos"))]
    unsafe fn get_stack_start() -> Option<*mut libc::c_void> {
        let mut current_stack: libc::stack_t = crate::mem::zeroed();
        assert_eq!(libc::stack_getbounds(&mut current_stack), 0);
        Some(current_stack.ss_sp)
    }

    #[cfg(target_os = "macos")]
    unsafe fn get_stack_start() -> Option<*mut libc::c_void> {
        let th = libc::pthread_self();
        let stackptr = libc::pthread_get_stackaddr_np(th);
        Some(stackptr.map_addr(|addr| addr - libc::pthread_get_stacksize_np(th)))
    }

    #[cfg(target_os = "openbsd")]
    unsafe fn get_stack_start() -> Option<*mut libc::c_void> {
        let mut current_stack: libc::stack_t = crate::mem::zeroed();
        assert_eq!(libc::pthread_stackseg_np(libc::pthread_self(), &mut current_stack), 0);

        let stack_ptr = current_stack.ss_sp;
        let stackaddr = if libc::pthread_main_np() == 1 {
            // main thread
            stack_ptr.addr() - current_stack.ss_size + PAGE_SIZE.load(Ordering::Relaxed)
        } else {
            // new thread
            stack_ptr.addr() - current_stack.ss_size
        };
        Some(stack_ptr.with_addr(stackaddr))
    }

    #[cfg(any(
        target_os = "android",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "hurd",
        target_os = "linux",
        target_os = "l4re"
    ))]
    unsafe fn get_stack_start() -> Option<*mut libc::c_void> {
        let mut ret = None;
        let mut attr: mem::MaybeUninit<libc::pthread_attr_t> = mem::MaybeUninit::uninit();
        if !cfg!(target_os = "freebsd") {
            attr = mem::MaybeUninit::zeroed();
        }
        #[cfg(target_os = "freebsd")]
        assert_eq!(libc::pthread_attr_init(attr.as_mut_ptr()), 0);
        #[cfg(target_os = "freebsd")]
        let e = libc::pthread_attr_get_np(libc::pthread_self(), attr.as_mut_ptr());
        #[cfg(not(target_os = "freebsd"))]
        let e = libc::pthread_getattr_np(libc::pthread_self(), attr.as_mut_ptr());
        if e == 0 {
            let mut stackaddr = crate::ptr::null_mut();
            let mut stacksize = 0;
            assert_eq!(
                libc::pthread_attr_getstack(attr.as_ptr(), &mut stackaddr, &mut stacksize),
                0
            );
            ret = Some(stackaddr);
        }
        if e == 0 || cfg!(target_os = "freebsd") {
            assert_eq!(libc::pthread_attr_destroy(attr.as_mut_ptr()), 0);
        }
        ret
    }

    fn stack_start_aligned(page_size: usize) -> Option<*mut libc::c_void> {
        let stackptr = unsafe { get_stack_start()? };
        let stackaddr = stackptr.addr();

        // Ensure stackaddr is page aligned! A parent process might
        // have reset RLIMIT_STACK to be non-page aligned. The
        // pthread_attr_getstack() reports the usable stack area
        // stackaddr < stackaddr + stacksize, so if stackaddr is not
        // page-aligned, calculate the fix such that stackaddr <
        // new_page_aligned_stackaddr < stackaddr + stacksize
        let remainder = stackaddr % page_size;
        Some(if remainder == 0 {
            stackptr
        } else {
            stackptr.with_addr(stackaddr + page_size - remainder)
        })
    }

    #[forbid(unsafe_op_in_unsafe_fn)]
    unsafe fn install_main_guard() -> Option<Range<usize>> {
        let page_size = PAGE_SIZE.load(Ordering::Relaxed);

        unsafe {
            // this way someone on any unix-y OS can check that all these compile
            if cfg!(all(target_os = "linux", not(target_env = "musl"))) {
                install_main_guard_linux(page_size)
            } else if cfg!(all(target_os = "linux", target_env = "musl")) {
                install_main_guard_linux_musl(page_size)
            } else if cfg!(target_os = "freebsd") {
                #[cfg(not(target_os = "freebsd"))]
                return None;
                // The FreeBSD code cannot be checked on non-BSDs.
                #[cfg(target_os = "freebsd")]
                install_main_guard_freebsd(page_size)
            } else if cfg!(any(target_os = "netbsd", target_os = "openbsd")) {
                install_main_guard_bsds(page_size)
            } else {
                install_main_guard_default(page_size)
            }
        }
    }

    #[forbid(unsafe_op_in_unsafe_fn)]
    unsafe fn install_main_guard_linux(page_size: usize) -> Option<Range<usize>> {
        // Linux doesn't allocate the whole stack right away, and
        // the kernel has its own stack-guard mechanism to fault
        // when growing too close to an existing mapping. If we map
        // our own guard, then the kernel starts enforcing a rather
        // large gap above that, rendering much of the possible
        // stack space useless. See #43052.
        //
        // Instead, we'll just note where we expect rlimit to start
        // faulting, so our handler can report "stack overflow", and
        // trust that the kernel's own stack guard will work.
        let stackptr = stack_start_aligned(page_size)?;
        let stackaddr = stackptr.addr();
        Some(stackaddr - page_size..stackaddr)
    }

    #[forbid(unsafe_op_in_unsafe_fn)]
    unsafe fn install_main_guard_linux_musl(_page_size: usize) -> Option<Range<usize>> {
        // For the main thread, the musl's pthread_attr_getstack
        // returns the current stack size, rather than maximum size
        // it can eventually grow to. It cannot be used to determine
        // the position of kernel's stack guard.
        None
    }

    #[forbid(unsafe_op_in_unsafe_fn)]
    #[cfg(target_os = "freebsd")]
    unsafe fn install_main_guard_freebsd(page_size: usize) -> Option<Range<usize>> {
        // FreeBSD's stack autogrows, and optionally includes a guard page
        // at the bottom. If we try to remap the bottom of the stack
        // ourselves, FreeBSD's guard page moves upwards. So we'll just use
        // the builtin guard page.
        let stackptr = stack_start_aligned(page_size)?;
        let guardaddr = stackptr.addr();
        // Technically the number of guard pages is tunable and controlled
        // by the security.bsd.stack_guard_page sysctl.
        // By default it is 1, checking once is enough since it is
        // a boot time config value.
        static PAGES: crate::sync::OnceLock<usize> = crate::sync::OnceLock::new();

        let pages = PAGES.get_or_init(|| {
            let mut guard: usize = 0;
            let mut size = size_of_val(&guard);
            let oid = c"security.bsd.stack_guard_page";

            let r = unsafe {
                libc::sysctlbyname(
                    oid.as_ptr(),
                    (&raw mut guard).cast(),
                    &raw mut size,
                    ptr::null_mut(),
                    0,
                )
            };
            if r == 0 { guard } else { 1 }
        });
        Some(guardaddr..guardaddr + pages * page_size)
    }

    #[forbid(unsafe_op_in_unsafe_fn)]
    unsafe fn install_main_guard_bsds(page_size: usize) -> Option<Range<usize>> {
        // OpenBSD stack already includes a guard page, and stack is
        // immutable.
        // NetBSD stack includes the guard page.
        //
        // We'll just note where we expect rlimit to start
        // faulting, so our handler can report "stack overflow", and
        // trust that the kernel's own stack guard will work.
        let stackptr = stack_start_aligned(page_size)?;
        let stackaddr = stackptr.addr();
        Some(stackaddr - page_size..stackaddr)
    }

    #[forbid(unsafe_op_in_unsafe_fn)]
    unsafe fn install_main_guard_default(page_size: usize) -> Option<Range<usize>> {
        // Reallocate the last page of the stack.
        // This ensures SIGBUS will be raised on
        // stack overflow.
        // Systems which enforce strict PAX MPROTECT do not allow
        // to mprotect() a mapping with less restrictive permissions
        // than the initial mmap() used, so we mmap() here with
        // read/write permissions and only then mprotect() it to
        // no permissions at all. See issue #50313.
        let stackptr = stack_start_aligned(page_size)?;
        let result = unsafe {
            mmap64(
                stackptr,
                page_size,
                PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANON | MAP_FIXED,
                -1,
                0,
            )
        };
        if result != stackptr || result == MAP_FAILED {
            panic!("failed to allocate a guard page: {}", io::Error::last_os_error());
        }

        let result = unsafe { mprotect(stackptr, page_size, PROT_NONE) };
        if result != 0 {
            panic!("failed to protect the guard page: {}", io::Error::last_os_error());
        }

        let guardaddr = stackptr.addr();

        Some(guardaddr..guardaddr + page_size)
    }

    #[cfg(any(
        target_os = "macos",
        target_os = "openbsd",
        target_os = "solaris",
        target_os = "illumos",
    ))]
    // FIXME: I am probably not unsafe.
    unsafe fn current_guard() -> Option<Range<usize>> {
        let stackptr = get_stack_start()?;
        let stackaddr = stackptr.addr();
        Some(stackaddr - PAGE_SIZE.load(Ordering::Relaxed)..stackaddr)
    }

    #[cfg(any(
        target_os = "android",
        target_os = "freebsd",
        target_os = "hurd",
        target_os = "linux",
        target_os = "netbsd",
        target_os = "l4re"
    ))]
    // FIXME: I am probably not unsafe.
    unsafe fn current_guard() -> Option<Range<usize>> {
        let mut ret = None;

        let mut attr: mem::MaybeUninit<libc::pthread_attr_t> = mem::MaybeUninit::uninit();
        if !cfg!(target_os = "freebsd") {
            attr = mem::MaybeUninit::zeroed();
        }
        #[cfg(target_os = "freebsd")]
        assert_eq!(libc::pthread_attr_init(attr.as_mut_ptr()), 0);
        #[cfg(target_os = "freebsd")]
        let e = libc::pthread_attr_get_np(libc::pthread_self(), attr.as_mut_ptr());
        #[cfg(not(target_os = "freebsd"))]
        let e = libc::pthread_getattr_np(libc::pthread_self(), attr.as_mut_ptr());
        if e == 0 {
            let mut guardsize = 0;
            assert_eq!(libc::pthread_attr_getguardsize(attr.as_ptr(), &mut guardsize), 0);
            if guardsize == 0 {
                if cfg!(all(target_os = "linux", target_env = "musl")) {
                    // musl versions before 1.1.19 always reported guard
                    // size obtained from pthread_attr_get_np as zero.
                    // Use page size as a fallback.
                    guardsize = PAGE_SIZE.load(Ordering::Relaxed);
                } else {
                    panic!("there is no guard page");
                }
            }
            let mut stackptr = crate::ptr::null_mut::<libc::c_void>();
            let mut size = 0;
            assert_eq!(libc::pthread_attr_getstack(attr.as_ptr(), &mut stackptr, &mut size), 0);

            let stackaddr = stackptr.addr();
            ret = if cfg!(any(target_os = "freebsd", target_os = "netbsd", target_os = "hurd")) {
                Some(stackaddr - guardsize..stackaddr)
            } else if cfg!(all(target_os = "linux", target_env = "musl")) {
                Some(stackaddr - guardsize..stackaddr)
            } else if cfg!(all(target_os = "linux", any(target_env = "gnu", target_env = "uclibc")))
            {
                // glibc used to include the guard area within the stack, as noted in the BUGS
                // section of `man pthread_attr_getguardsize`. This has been corrected starting
                // with glibc 2.27, and in some distro backports, so the guard is now placed at the
                // end (below) the stack. There's no easy way for us to know which we have at
                // runtime, so we'll just match any fault in the range right above or below the
                // stack base to call that fault a stack overflow.
                Some(stackaddr - guardsize..stackaddr + guardsize)
            } else {
                Some(stackaddr..stackaddr + guardsize)
            };
        }
        if e == 0 || cfg!(target_os = "freebsd") {
            assert_eq!(libc::pthread_attr_destroy(attr.as_mut_ptr()), 0);
        }
        ret
    }
}

// This is intentionally not enabled on iOS/tvOS/watchOS/visionOS, as it uses
// several symbols that might lead to rejections from the App Store, namely
// `sigaction`, `sigaltstack`, `sysctlbyname`, `mmap`, `munmap` and `mprotect`.
//
// This might be overly cautious, though it is also what Swift does (and they
// usually have fewer qualms about forwards compatibility, since the runtime
// is shipped with the OS):
// <https://github.com/apple/swift/blob/swift-5.10-RELEASE/stdlib/public/runtime/CrashHandlerMacOS.cpp>
#[cfg(any(
    miri,
    not(any(
        target_os = "linux",
        target_os = "freebsd",
        target_os = "hurd",
        target_os = "macos",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "solaris",
        target_os = "illumos",
        target_os = "cygwin",
    ))
))]
mod imp {
    pub unsafe fn init() {}

    pub unsafe fn cleanup() {}

    pub unsafe fn make_handler(
        _main_thread: bool,
        _thread_name: Option<Box<str>>,
    ) -> super::Handler {
        super::Handler::null()
    }

    pub unsafe fn drop_handler(_data: *mut libc::c_void) {}
}

#[cfg(target_os = "cygwin")]
mod imp {
    mod c {
        pub type PVECTORED_EXCEPTION_HANDLER =
            Option<unsafe extern "system" fn(exceptioninfo: *mut EXCEPTION_POINTERS) -> i32>;
        pub type NTSTATUS = i32;
        pub type BOOL = i32;

        unsafe extern "system" {
            pub fn AddVectoredExceptionHandler(
                first: u32,
                handler: PVECTORED_EXCEPTION_HANDLER,
            ) -> *mut core::ffi::c_void;
            pub fn SetThreadStackGuarantee(stacksizeinbytes: *mut u32) -> BOOL;
        }

        pub const EXCEPTION_STACK_OVERFLOW: NTSTATUS = 0xC00000FD_u32 as _;
        pub const EXCEPTION_CONTINUE_SEARCH: i32 = 1i32;

        #[repr(C)]
        #[derive(Clone, Copy)]
        pub struct EXCEPTION_POINTERS {
            pub ExceptionRecord: *mut EXCEPTION_RECORD,
            // We don't need this field here
            // pub Context: *mut CONTEXT,
        }
        #[repr(C)]
        #[derive(Clone, Copy)]
        pub struct EXCEPTION_RECORD {
            pub ExceptionCode: NTSTATUS,
            pub ExceptionFlags: u32,
            pub ExceptionRecord: *mut EXCEPTION_RECORD,
            pub ExceptionAddress: *mut core::ffi::c_void,
            pub NumberParameters: u32,
            pub ExceptionInformation: [usize; 15],
        }
    }

    /// Reserve stack space for use in stack overflow exceptions.
    fn reserve_stack() {
        let result = unsafe { c::SetThreadStackGuarantee(&mut 0x5000) };
        // Reserving stack space is not critical so we allow it to fail in the released build of libstd.
        // We still use debug assert here so that CI will test that we haven't made a mistake calling the function.
        debug_assert_ne!(result, 0, "failed to reserve stack space for exception handling");
    }

    unsafe extern "system" fn vectored_handler(ExceptionInfo: *mut c::EXCEPTION_POINTERS) -> i32 {
        // SAFETY: It's up to the caller (which in this case is the OS) to ensure that `ExceptionInfo` is valid.
        unsafe {
            let rec = &(*(*ExceptionInfo).ExceptionRecord);
            let code = rec.ExceptionCode;

            if code == c::EXCEPTION_STACK_OVERFLOW {
                crate::thread::with_current_name(|name| {
                    let name = name.unwrap_or("<unknown>");
                    let tid = crate::thread::current_os_id();
                    rtprintpanic!("\nthread '{name}' ({tid}) has overflowed its stack\n");
                });
            }
            c::EXCEPTION_CONTINUE_SEARCH
        }
    }

    pub unsafe fn init() {
        // SAFETY: `vectored_handler` has the correct ABI and is safe to call during exception handling.
        unsafe {
            let result = c::AddVectoredExceptionHandler(0, Some(vectored_handler));
            // Similar to the above, adding the stack overflow handler is allowed to fail
            // but a debug assert is used so CI will still test that it normally works.
            debug_assert!(!result.is_null(), "failed to install exception handler");
        }
        // Set the thread stack guarantee for the main thread.
        reserve_stack();
    }

    pub unsafe fn cleanup() {}

    pub unsafe fn make_handler(
        main_thread: bool,
        _thread_name: Option<Box<str>>,
    ) -> super::Handler {
        if !main_thread {
            reserve_stack();
        }
        super::Handler::null()
    }

    pub unsafe fn drop_handler(_data: *mut libc::c_void) {}
}

```

**💡 建议：**
Ensure Drop implementations never panic

#### 漏洞 #7：Potential panic in Drop implementation detected

**详情：**
- **Type:** `drop-panic`
- **Severity:** `Critical`
- **Confidence:** `90.0%`
- **Location:** `d:\漏洞挖掘\detector\project\library\std\src\sys\pal\unix\sync\mutex.rs:0`
- **检测方法：** `StaticAnalysis`

**解释：**
Drop implementation may panic, which can cause undefined behavior

**代码：**
```rust
use super::super::cvt_nz;
use crate::cell::UnsafeCell;
use crate::io::Error;
use crate::mem::MaybeUninit;
use crate::pin::Pin;

pub struct Mutex {
    inner: UnsafeCell<libc::pthread_mutex_t>,
}

impl Mutex {
    pub fn new() -> Mutex {
        Mutex { inner: UnsafeCell::new(libc::PTHREAD_MUTEX_INITIALIZER) }
    }

    pub(super) fn raw(&self) -> *mut libc::pthread_mutex_t {
        self.inner.get()
    }

    /// # Safety
    /// May only be called once per instance of `Self`.
    pub unsafe fn init(self: Pin<&mut Self>) {
        // Issue #33770
        //
        // A pthread mutex initialized with PTHREAD_MUTEX_INITIALIZER will have
        // a type of PTHREAD_MUTEX_DEFAULT, which has undefined behavior if you
        // try to re-lock it from the same thread when you already hold a lock
        // (https://pubs.opengroup.org/onlinepubs/9699919799/functions/pthread_mutex_init.html).
        // This is the case even if PTHREAD_MUTEX_DEFAULT == PTHREAD_MUTEX_NORMAL
        // (https://github.com/rust-lang/rust/issues/33770#issuecomment-220847521) -- in that
        // case, `pthread_mutexattr_settype(PTHREAD_MUTEX_DEFAULT)` will of course be the same
        // as setting it to `PTHREAD_MUTEX_NORMAL`, but not setting any mode will result in
        // a Mutex where re-locking is UB.
        //
        // In practice, glibc takes advantage of this undefined behavior to
        // implement hardware lock elision, which uses hardware transactional
        // memory to avoid acquiring the lock. While a transaction is in
        // progress, the lock appears to be unlocked. This isn't a problem for
        // other threads since the transactional memory will abort if a conflict
        // is detected, however no abort is generated when re-locking from the
        // same thread.
        //
        // Since locking the same mutex twice will result in two aliasing &mut
        // references, we instead create the mutex with type
        // PTHREAD_MUTEX_NORMAL which is guaranteed to deadlock if we try to
        // re-lock it from the same thread, thus avoiding undefined behavior.
        unsafe {
            let mut attr = MaybeUninit::<libc::pthread_mutexattr_t>::uninit();
            cvt_nz(libc::pthread_mutexattr_init(attr.as_mut_ptr())).unwrap();
            let attr = AttrGuard(&mut attr);
            cvt_nz(libc::pthread_mutexattr_settype(
                attr.0.as_mut_ptr(),
                libc::PTHREAD_MUTEX_NORMAL,
            ))
            .unwrap();
            cvt_nz(libc::pthread_mutex_init(self.raw(), attr.0.as_ptr())).unwrap();
        }
    }

    /// # Safety
    /// * If `init` was not called on this instance, reentrant locking causes
    ///   undefined behaviour.
    /// * Destroying a locked mutex causes undefined behaviour.
    pub unsafe fn lock(self: Pin<&Self>) {
        #[cold]
        #[inline(never)]
        fn fail(r: i32) -> ! {
            let error = Error::from_raw_os_error(r);
            panic!("failed to lock mutex: {error}");
        }

        let r = unsafe { libc::pthread_mutex_lock(self.raw()) };
        // As we set the mutex type to `PTHREAD_MUTEX_NORMAL` above, we expect
        // the lock call to never fail. Unfortunately however, some platforms
        // (Solaris) do not conform to the standard, and instead always provide
        // deadlock detection. How kind of them! Unfortunately that means that
        // we need to check the error code here. To save us from UB on other
        // less well-behaved platforms in the future, we do it even on "good"
        // platforms like macOS. See #120147 for more context.
        if r != 0 {
            fail(r)
        }
    }

    /// # Safety
    /// * If `init` was not called on this instance, reentrant locking causes
    ///   undefined behaviour.
    /// * Destroying a locked mutex causes undefined behaviour.
    pub unsafe fn try_lock(self: Pin<&Self>) -> bool {
        unsafe { libc::pthread_mutex_trylock(self.raw()) == 0 }
    }

    /// # Safety
    /// The mutex must be locked by the current thread.
    pub unsafe fn unlock(self: Pin<&Self>) {
        let r = unsafe { libc::pthread_mutex_unlock(self.raw()) };
        debug_assert_eq!(r, 0);
    }
}

impl !Unpin for Mutex {}

unsafe impl Send for Mutex {}
unsafe impl Sync for Mutex {}

impl Drop for Mutex {
    fn drop(&mut self) {
        // SAFETY:
        // If `lock` or `init` was called, the mutex must have been pinned, so
        // it is still at the same location. Otherwise, `inner` must contain
        // `PTHREAD_MUTEX_INITIALIZER`, which is valid at all locations. Thus,
        // this call always destroys a valid mutex.
        let r = unsafe { libc::pthread_mutex_destroy(self.raw()) };
        if cfg!(any(target_os = "aix", target_os = "dragonfly")) {
            // On AIX and DragonFly pthread_mutex_destroy() returns EINVAL if called
            // on a mutex that was just initialized with libc::PTHREAD_MUTEX_INITIALIZER.
            // Once it is used (locked/unlocked) or pthread_mutex_init() is called,
            // this behaviour no longer occurs.
            debug_assert!(r == 0 || r == libc::EINVAL);
        } else {
            debug_assert_eq!(r, 0);
        }
    }
}

struct AttrGuard<'a>(pub &'a mut MaybeUninit<libc::pthread_mutexattr_t>);

impl Drop for AttrGuard<'_> {
    fn drop(&mut self) {
        unsafe {
            let result = libc::pthread_mutexattr_destroy(self.0.as_mut_ptr());
            assert_eq!(result, 0);
        }
    }
}

```

**💡 建议：**
Ensure Drop implementations never panic

#### 漏洞 #8：Potential panic in Drop implementation detected

**详情：**
- **Type:** `drop-panic`
- **Severity:** `Critical`
- **Confidence:** `90.0%`
- **Location:** `d:\漏洞挖掘\detector\project\library\std\src\sys\platform_version\darwin\core_foundation.rs:0`
- **检测方法：** `StaticAnalysis`

**解释：**
Drop implementation may panic, which can cause undefined behavior

**代码：**
```rust
//! Minimal utilities for interfacing with a dynamically loaded CoreFoundation.
#![allow(non_snake_case, non_upper_case_globals)]
use super::root_relative;
use crate::ffi::{CStr, c_char, c_void};
use crate::ptr::null_mut;
use crate::sys::common::small_c_string::run_path_with_cstr;

// MacTypes.h
pub(super) type Boolean = u8;
// CoreFoundation/CFBase.h
pub(super) type CFTypeID = usize;
pub(super) type CFOptionFlags = usize;
pub(super) type CFIndex = isize;
pub(super) type CFTypeRef = *mut c_void;
pub(super) type CFAllocatorRef = CFTypeRef;
pub(super) const kCFAllocatorDefault: CFAllocatorRef = null_mut();
// CoreFoundation/CFError.h
pub(super) type CFErrorRef = CFTypeRef;
// CoreFoundation/CFData.h
pub(super) type CFDataRef = CFTypeRef;
// CoreFoundation/CFPropertyList.h
pub(super) const kCFPropertyListImmutable: CFOptionFlags = 0;
pub(super) type CFPropertyListFormat = CFIndex;
pub(super) type CFPropertyListRef = CFTypeRef;
// CoreFoundation/CFString.h
pub(super) type CFStringRef = CFTypeRef;
pub(super) type CFStringEncoding = u32;
pub(super) const kCFStringEncodingUTF8: CFStringEncoding = 0x08000100;
// CoreFoundation/CFDictionary.h
pub(super) type CFDictionaryRef = CFTypeRef;

/// An open handle to the dynamically loaded CoreFoundation framework.
///
/// This is `dlopen`ed, and later `dlclose`d. This is done to try to avoid
/// "leaking" the CoreFoundation symbols to the rest of the user's binary if
/// they decided to not link CoreFoundation themselves.
///
/// It is also faster to look up symbols directly via this handle than with
/// `RTLD_DEFAULT`.
pub(super) struct CFHandle(*mut c_void);

macro_rules! dlsym_fn {
    (
        unsafe fn $name:ident($($param:ident: $param_ty:ty),* $(,)?) $(-> $ret:ty)?;
    ) => {
        pub(super) unsafe fn $name(&self, $($param: $param_ty),*) $(-> $ret)? {
            let ptr = unsafe {
                libc::dlsym(
                    self.0,
                    concat!(stringify!($name), '\0').as_bytes().as_ptr().cast(),
                )
            };
            if ptr.is_null() {
                let err = unsafe { CStr::from_ptr(libc::dlerror()) };
                panic!("could not find function {}: {err:?}", stringify!($name));
            }

            // SAFETY: Just checked that the symbol isn't NULL, and macro invoker verifies that
            // the signature is correct.
            let fnptr = unsafe {
                crate::mem::transmute::<
                    *mut c_void,
                    unsafe extern "C" fn($($param_ty),*) $(-> $ret)?,
                >(ptr)
            };

            // SAFETY: Upheld by caller.
            unsafe { fnptr($($param),*) }
        }
    };
}

impl CFHandle {
    /// Link to the CoreFoundation dylib, and look up symbols from that.
    pub(super) fn new() -> Self {
        // We explicitly use non-versioned path here, to allow this to work on older iOS devices.
        let cf_path =
            root_relative("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation");

        let handle = run_path_with_cstr(&cf_path, &|path| unsafe {
            Ok(libc::dlopen(path.as_ptr(), libc::RTLD_LAZY | libc::RTLD_LOCAL))
        })
        .expect("failed allocating string");

        if handle.is_null() {
            let err = unsafe { CStr::from_ptr(libc::dlerror()) };
            panic!("could not open CoreFoundation.framework: {err:?}");
        }

        Self(handle)
    }

    pub(super) fn kCFAllocatorNull(&self) -> CFAllocatorRef {
        // Available: in all CF versions.
        let static_ptr = unsafe { libc::dlsym(self.0, c"kCFAllocatorNull".as_ptr()) };
        if static_ptr.is_null() {
            let err = unsafe { CStr::from_ptr(libc::dlerror()) };
            panic!("could not find kCFAllocatorNull: {err:?}");
        }
        unsafe { *static_ptr.cast() }
    }

    // CoreFoundation/CFBase.h
    dlsym_fn!(
        // Available: in all CF versions.
        unsafe fn CFRelease(cf: CFTypeRef);
    );
    dlsym_fn!(
        // Available: in all CF versions.
        unsafe fn CFGetTypeID(cf: CFTypeRef) -> CFTypeID;
    );

    // CoreFoundation/CFData.h
    dlsym_fn!(
        // Available: in all CF versions.
        unsafe fn CFDataCreateWithBytesNoCopy(
            allocator: CFAllocatorRef,
            bytes: *const u8,
            length: CFIndex,
            bytes_deallocator: CFAllocatorRef,
        ) -> CFDataRef;
    );

    // CoreFoundation/CFPropertyList.h
    dlsym_fn!(
        // Available: since macOS 10.6.
        unsafe fn CFPropertyListCreateWithData(
            allocator: CFAllocatorRef,
            data: CFDataRef,
            options: CFOptionFlags,
            format: *mut CFPropertyListFormat,
            error: *mut CFErrorRef,
        ) -> CFPropertyListRef;
    );

    // CoreFoundation/CFString.h
    dlsym_fn!(
        // Available: in all CF versions.
        unsafe fn CFStringGetTypeID() -> CFTypeID;
    );
    dlsym_fn!(
        // Available: in all CF versions.
        unsafe fn CFStringCreateWithCStringNoCopy(
            alloc: CFAllocatorRef,
            c_str: *const c_char,
            encoding: CFStringEncoding,
            contents_deallocator: CFAllocatorRef,
        ) -> CFStringRef;
    );
    dlsym_fn!(
        // Available: in all CF versions.
        unsafe fn CFStringGetCString(
            the_string: CFStringRef,
            buffer: *mut c_char,
            buffer_size: CFIndex,
            encoding: CFStringEncoding,
        ) -> Boolean;
    );

    // CoreFoundation/CFDictionary.h
    dlsym_fn!(
        // Available: in all CF versions.
        unsafe fn CFDictionaryGetTypeID() -> CFTypeID;
    );
    dlsym_fn!(
        // Available: in all CF versions.
        unsafe fn CFDictionaryGetValue(
            the_dict: CFDictionaryRef,
            key: *const c_void,
        ) -> *const c_void;
    );
}

impl Drop for CFHandle {
    fn drop(&mut self) {
        // Ignore errors when closing. This is also what `libloading` does:
        // https://docs.rs/libloading/0.8.6/src/libloading/os/unix/mod.rs.html#374
        let _ = unsafe { libc::dlclose(self.0) };
    }
}

```

**💡 建议：**
Ensure Drop implementations never panic

#### 漏洞 #9：Potential panic in Drop implementation detected

**详情：**
- **Type:** `drop-panic`
- **Severity:** `Critical`
- **Confidence:** `90.0%`
- **Location:** `d:\漏洞挖掘\detector\project\library\std\src\sys\process\uefi.rs:0`
- **检测方法：** `StaticAnalysis`

**解释：**
Drop implementation may panic, which can cause undefined behavior

**代码：**
```rust
use r_efi::protocols::{simple_text_input, simple_text_output};

use super::env::{CommandEnv, CommandEnvs};
use crate::collections::BTreeMap;
pub use crate::ffi::OsString as EnvKey;
use crate::ffi::{OsStr, OsString};
use crate::num::{NonZero, NonZeroI32};
use crate::path::Path;
use crate::process::StdioPipes;
use crate::sys::fs::File;
use crate::sys::pal::helpers;
use crate::sys::pal::os::error_string;
use crate::sys::pipe::AnonPipe;
use crate::sys::unsupported;
use crate::{fmt, io};

////////////////////////////////////////////////////////////////////////////////
// Command
////////////////////////////////////////////////////////////////////////////////

#[derive(Debug)]
pub struct Command {
    prog: OsString,
    args: Vec<OsString>,
    stdout: Option<Stdio>,
    stderr: Option<Stdio>,
    stdin: Option<Stdio>,
    env: CommandEnv,
}

#[derive(Copy, Clone, Debug)]
pub enum Stdio {
    Inherit,
    Null,
    MakePipe,
}

impl Command {
    pub fn new(program: &OsStr) -> Command {
        Command {
            prog: program.to_os_string(),
            args: Vec::new(),
            stdout: None,
            stderr: None,
            stdin: None,
            env: Default::default(),
        }
    }

    pub fn arg(&mut self, arg: &OsStr) {
        self.args.push(arg.to_os_string());
    }

    pub fn env_mut(&mut self) -> &mut CommandEnv {
        &mut self.env
    }

    pub fn cwd(&mut self, _dir: &OsStr) {
        panic!("unsupported")
    }

    pub fn stdin(&mut self, stdin: Stdio) {
        self.stdin = Some(stdin);
    }

    pub fn stdout(&mut self, stdout: Stdio) {
        self.stdout = Some(stdout);
    }

    pub fn stderr(&mut self, stderr: Stdio) {
        self.stderr = Some(stderr);
    }

    pub fn get_program(&self) -> &OsStr {
        self.prog.as_ref()
    }

    pub fn get_args(&self) -> CommandArgs<'_> {
        CommandArgs { iter: self.args.iter() }
    }

    pub fn get_envs(&self) -> CommandEnvs<'_> {
        self.env.iter()
    }

    pub fn get_current_dir(&self) -> Option<&Path> {
        None
    }

    pub fn spawn(
        &mut self,
        _default: Stdio,
        _needs_stdin: bool,
    ) -> io::Result<(Process, StdioPipes)> {
        unsupported()
    }

    fn create_pipe(
        s: Stdio,
    ) -> io::Result<Option<helpers::OwnedProtocol<uefi_command_internal::PipeProtocol>>> {
        match s {
            Stdio::MakePipe => unsafe {
                helpers::OwnedProtocol::create(
                    uefi_command_internal::PipeProtocol::new(),
                    simple_text_output::PROTOCOL_GUID,
                )
            }
            .map(Some),
            Stdio::Null => unsafe {
                helpers::OwnedProtocol::create(
                    uefi_command_internal::PipeProtocol::null(),
                    simple_text_output::PROTOCOL_GUID,
                )
            }
            .map(Some),
            Stdio::Inherit => Ok(None),
        }
    }

    fn create_stdin(
        s: Stdio,
    ) -> io::Result<Option<helpers::OwnedProtocol<uefi_command_internal::InputProtocol>>> {
        match s {
            Stdio::Null => unsafe {
                helpers::OwnedProtocol::create(
                    uefi_command_internal::InputProtocol::null(),
                    simple_text_input::PROTOCOL_GUID,
                )
            }
            .map(Some),
            Stdio::Inherit => Ok(None),
            Stdio::MakePipe => unsupported(),
        }
    }
}

pub fn output(command: &mut Command) -> io::Result<(ExitStatus, Vec<u8>, Vec<u8>)> {
    let mut cmd = uefi_command_internal::Image::load_image(&command.prog)?;

    // UEFI adds the bin name by default
    if !command.args.is_empty() {
        let args = uefi_command_internal::create_args(&command.prog, &command.args);
        cmd.set_args(args);
    }

    // Setup Stdout
    let stdout = command.stdout.unwrap_or(Stdio::MakePipe);
    let stdout = Command::create_pipe(stdout)?;
    if let Some(con) = stdout {
        cmd.stdout_init(con)
    } else {
        cmd.stdout_inherit()
    };

    // Setup Stderr
    let stderr = command.stderr.unwrap_or(Stdio::MakePipe);
    let stderr = Command::create_pipe(stderr)?;
    if let Some(con) = stderr {
        cmd.stderr_init(con)
    } else {
        cmd.stderr_inherit()
    };

    // Setup Stdin
    let stdin = command.stdin.unwrap_or(Stdio::Null);
    let stdin = Command::create_stdin(stdin)?;
    if let Some(con) = stdin {
        cmd.stdin_init(con)
    } else {
        cmd.stdin_inherit()
    };

    let env = env_changes(&command.env);

    // Set any new vars
    if let Some(e) = &env {
        for (k, (_, v)) in e {
            match v {
                Some(v) => unsafe { crate::env::set_var(k, v) },
                None => unsafe { crate::env::remove_var(k) },
            }
        }
    }

    let stat = cmd.start_image()?;

    // Rollback any env changes
    if let Some(e) = env {
        for (k, (v, _)) in e {
            match v {
                Some(v) => unsafe { crate::env::set_var(k, v) },
                None => unsafe { crate::env::remove_var(k) },
            }
        }
    }

    let stdout = cmd.stdout()?;
    let stderr = cmd.stderr()?;

    Ok((ExitStatus(stat), stdout, stderr))
}

impl From<AnonPipe> for Stdio {
    fn from(pipe: AnonPipe) -> Stdio {
        pipe.diverge()
    }
}

impl From<io::Stdout> for Stdio {
    fn from(_: io::Stdout) -> Stdio {
        // FIXME: This is wrong.
        // Instead, the Stdio we have here should be a unit struct.
        panic!("unsupported")
    }
}

impl From<io::Stderr> for Stdio {
    fn from(_: io::Stderr) -> Stdio {
        // FIXME: This is wrong.
        // Instead, the Stdio we have here should be a unit struct.
        panic!("unsupported")
    }
}

impl From<File> for Stdio {
    fn from(_file: File) -> Stdio {
        // FIXME: This is wrong.
        // Instead, the Stdio we have here should be a unit struct.
        panic!("unsupported")
    }
}

#[derive(PartialEq, Eq, Clone, Copy, Debug)]
#[non_exhaustive]
pub struct ExitStatus(r_efi::efi::Status);

impl ExitStatus {
    pub fn exit_ok(&self) -> Result<(), ExitStatusError> {
        if self.0 == r_efi::efi::Status::SUCCESS { Ok(()) } else { Err(ExitStatusError(self.0)) }
    }

    pub fn code(&self) -> Option<i32> {
        Some(self.0.as_usize() as i32)
    }
}

impl fmt::Display for ExitStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let err_str = error_string(self.0.as_usize());
        write!(f, "{}", err_str)
    }
}

impl Default for ExitStatus {
    fn default() -> Self {
        ExitStatus(r_efi::efi::Status::SUCCESS)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ExitStatusError(r_efi::efi::Status);

impl fmt::Debug for ExitStatusError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let err_str = error_string(self.0.as_usize());
        write!(f, "{}", err_str)
    }
}

impl Into<ExitStatus> for ExitStatusError {
    fn into(self) -> ExitStatus {
        ExitStatus(self.0)
    }
}

impl ExitStatusError {
    pub fn code(self) -> Option<NonZero<i32>> {
        NonZeroI32::new(self.0.as_usize() as i32)
    }
}

#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub struct ExitCode(bool);

impl ExitCode {
    pub const SUCCESS: ExitCode = ExitCode(false);
    pub const FAILURE: ExitCode = ExitCode(true);

    pub fn as_i32(&self) -> i32 {
        self.0 as i32
    }
}

impl From<u8> for ExitCode {
    fn from(code: u8) -> Self {
        match code {
            0 => Self::SUCCESS,
            1..=255 => Self::FAILURE,
        }
    }
}

pub struct Process(!);

impl Process {
    pub fn id(&self) -> u32 {
        self.0
    }

    pub fn kill(&mut self) -> io::Result<()> {
        self.0
    }

    pub fn wait(&mut self) -> io::Result<ExitStatus> {
        self.0
    }

    pub fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        self.0
    }
}

pub struct CommandArgs<'a> {
    iter: crate::slice::Iter<'a, OsString>,
}

impl<'a> Iterator for CommandArgs<'a> {
    type Item = &'a OsStr;

    fn next(&mut self) -> Option<&'a OsStr> {
        self.iter.next().map(|x| x.as_ref())
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.iter.size_hint()
    }
}

impl<'a> ExactSizeIterator for CommandArgs<'a> {
    fn len(&self) -> usize {
        self.iter.len()
    }

    fn is_empty(&self) -> bool {
        self.iter.is_empty()
    }
}

impl<'a> fmt::Debug for CommandArgs<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.iter.clone()).finish()
    }
}

#[allow(dead_code)]
mod uefi_command_internal {
    use r_efi::protocols::{loaded_image, simple_text_input, simple_text_output};

    use crate::ffi::{OsStr, OsString};
    use crate::io::{self, const_error};
    use crate::mem::MaybeUninit;
    use crate::os::uefi::env::{boot_services, image_handle, system_table};
    use crate::os::uefi::ffi::{OsStrExt, OsStringExt};
    use crate::ptr::NonNull;
    use crate::slice;
    use crate::sys::pal::helpers::{self, OwnedTable};
    use crate::sys_common::wstr::WStrUnits;

    pub struct Image {
        handle: NonNull<crate::ffi::c_void>,
        stdout: Option<helpers::OwnedProtocol<PipeProtocol>>,
        stderr: Option<helpers::OwnedProtocol<PipeProtocol>>,
        stdin: Option<helpers::OwnedProtocol<InputProtocol>>,
        st: OwnedTable<r_efi::efi::SystemTable>,
        args: Option<(*mut u16, usize)>,
    }

    impl Image {
        pub fn load_image(p: &OsStr) -> io::Result<Self> {
            let path = helpers::OwnedDevicePath::from_text(p)?;
            let boot_services: NonNull<r_efi::efi::BootServices> = boot_services()
                .ok_or_else(|| const_error!(io::ErrorKind::NotFound, "Boot Services not found"))?
                .cast();
            let mut child_handle: MaybeUninit<r_efi::efi::Handle> = MaybeUninit::uninit();
            let image_handle = image_handle();

            let r = unsafe {
                ((*boot_services.as_ptr()).load_image)(
                    r_efi::efi::Boolean::FALSE,
                    image_handle.as_ptr(),
                    path.as_ptr(),
                    crate::ptr::null_mut(),
                    0,
                    child_handle.as_mut_ptr(),
                )
            };

            if r.is_error() {
                Err(io::Error::from_raw_os_error(r.as_usize()))
            } else {
                let child_handle = unsafe { child_handle.assume_init() };
                let child_handle = NonNull::new(child_handle).unwrap();

                let loaded_image: NonNull<loaded_image::Protocol> =
                    helpers::open_protocol(child_handle, loaded_image::PROTOCOL_GUID).unwrap();
                let st = OwnedTable::from_table(unsafe { (*loaded_image.as_ptr()).system_table });

                Ok(Self {
                    handle: child_handle,
                    stdout: None,
                    stderr: None,
                    stdin: None,
                    st,
                    args: None,
                })
            }
        }

        pub(crate) fn start_image(&mut self) -> io::Result<r_efi::efi::Status> {
            self.update_st_crc32()?;

            // Use our system table instead of the default one
            let loaded_image: NonNull<loaded_image::Protocol> =
                helpers::open_protocol(self.handle, loaded_image::PROTOCOL_GUID).unwrap();
            unsafe {
                (*loaded_image.as_ptr()).system_table = self.st.as_mut_ptr();
            }

            let boot_services: NonNull<r_efi::efi::BootServices> = boot_services()
                .ok_or_else(|| const_error!(io::ErrorKind::NotFound, "Boot Services not found"))?
                .cast();
            let mut exit_data_size: usize = 0;
            let mut exit_data: MaybeUninit<*mut u16> = MaybeUninit::uninit();

            let r = unsafe {
                ((*boot_services.as_ptr()).start_image)(
                    self.handle.as_ptr(),
                    &mut exit_data_size,
                    exit_data.as_mut_ptr(),
                )
            };

            // Drop exitdata
            if exit_data_size != 0 {
                unsafe {
                    let exit_data = exit_data.assume_init();
                    ((*boot_services.as_ptr()).free_pool)(exit_data as *mut crate::ffi::c_void);
                }
            }

            Ok(r)
        }

        fn set_stdout(
            &mut self,
            handle: r_efi::efi::Handle,
            protocol: *mut simple_text_output::Protocol,
        ) {
            unsafe {
                (*self.st.as_mut_ptr()).console_out_handle = handle;
                (*self.st.as_mut_ptr()).con_out = protocol;
            }
        }

        fn set_stderr(
            &mut self,
            handle: r_efi::efi::Handle,
            protocol: *mut simple_text_output::Protocol,
        ) {
            unsafe {
                (*self.st.as_mut_ptr()).standard_error_handle = handle;
                (*self.st.as_mut_ptr()).std_err = protocol;
            }
        }

        fn set_stdin(
            &mut self,
            handle: r_efi::efi::Handle,
            protocol: *mut simple_text_input::Protocol,
        ) {
            unsafe {
                (*self.st.as_mut_ptr()).console_in_handle = handle;
                (*self.st.as_mut_ptr()).con_in = protocol;
            }
        }

        pub fn stdout_init(&mut self, protocol: helpers::OwnedProtocol<PipeProtocol>) {
            self.set_stdout(
                protocol.handle().as_ptr(),
                protocol.as_ref() as *const PipeProtocol as *mut simple_text_output::Protocol,
            );
            self.stdout = Some(protocol);
        }

        pub fn stdout_inherit(&mut self) {
            let st: NonNull<r_efi::efi::SystemTable> = system_table().cast();
            unsafe { self.set_stdout((*st.as_ptr()).console_out_handle, (*st.as_ptr()).con_out) }
        }

        pub fn stderr_init(&mut self, protocol: helpers::OwnedProtocol<PipeProtocol>) {
            self.set_stderr(
                protocol.handle().as_ptr(),
                protocol.as_ref() as *const PipeProtocol as *mut simple_text_output::Protocol,
            );
            self.stderr = Some(protocol);
        }

        pub fn stderr_inherit(&mut self) {
            let st: NonNull<r_efi::efi::SystemTable> = system_table().cast();
            unsafe { self.set_stderr((*st.as_ptr()).standard_error_handle, (*st.as_ptr()).std_err) }
        }

        pub(crate) fn stdin_init(&mut self, protocol: helpers::OwnedProtocol<InputProtocol>) {
            self.set_stdin(
                protocol.handle().as_ptr(),
                protocol.as_ref() as *const InputProtocol as *mut simple_text_input::Protocol,
            );
            self.stdin = Some(protocol);
        }

        pub(crate) fn stdin_inherit(&mut self) {
            let st: NonNull<r_efi::efi::SystemTable> = system_table().cast();
            unsafe { self.set_stdin((*st.as_ptr()).console_in_handle, (*st.as_ptr()).con_in) }
        }

        pub fn stderr(&self) -> io::Result<Vec<u8>> {
            match &self.stderr {
                Some(stderr) => stderr.as_ref().utf8(),
                None => Ok(Vec::new()),
            }
        }

        pub fn stdout(&self) -> io::Result<Vec<u8>> {
            match &self.stdout {
                Some(stdout) => stdout.as_ref().utf8(),
                None => Ok(Vec::new()),
            }
        }

        pub fn set_args(&mut self, args: Box<[u16]>) {
            let loaded_image: NonNull<loaded_image::Protocol> =
                helpers::open_protocol(self.handle, loaded_image::PROTOCOL_GUID).unwrap();

            let len = args.len();
            let args_size: u32 = (len * size_of::<u16>()).try_into().unwrap();
            let ptr = Box::into_raw(args).as_mut_ptr();

            unsafe {
                (*loaded_image.as_ptr()).load_options = ptr as *mut crate::ffi::c_void;
                (*loaded_image.as_ptr()).load_options_size = args_size;
            }

            self.args = Some((ptr, len));
        }

        fn update_st_crc32(&mut self) -> io::Result<()> {
            let bt: NonNull<r_efi::efi::BootServices> = boot_services().unwrap().cast();
            let st_size = unsafe { (*self.st.as_ptr()).hdr.header_size as usize };
            let mut crc32: u32 = 0;

            // Set crc to 0 before calculation
            unsafe {
                (*self.st.as_mut_ptr()).hdr.crc32 = 0;
            }

            let r = unsafe {
                ((*bt.as_ptr()).calculate_crc32)(
                    self.st.as_mut_ptr() as *mut crate::ffi::c_void,
                    st_size,
                    &mut crc32,
                )
            };

            if r.is_error() {
                Err(io::Error::from_raw_os_error(r.as_usize()))
            } else {
                unsafe {
                    (*self.st.as_mut_ptr()).hdr.crc32 = crc32;
                }
                Ok(())
            }
        }
    }

    impl Drop for Image {
        fn drop(&mut self) {
            if let Some(bt) = boot_services() {
                let bt: NonNull<r_efi::efi::BootServices> = bt.cast();
                unsafe {
                    ((*bt.as_ptr()).unload_image)(self.handle.as_ptr());
                }
            }

            if let Some((ptr, len)) = self.args {
                let _ = unsafe { Box::from_raw(crate::ptr::slice_from_raw_parts_mut(ptr, len)) };
            }
        }
    }

    #[repr(C)]
    pub struct PipeProtocol {
        reset: simple_text_output::ProtocolReset,
        output_string: simple_text_output::ProtocolOutputString,
        test_string: simple_text_output::ProtocolTestString,
        query_mode: simple_text_output::ProtocolQueryMode,
        set_mode: simple_text_output::ProtocolSetMode,
        set_attribute: simple_text_output::ProtocolSetAttribute,
        clear_screen: simple_text_output::ProtocolClearScreen,
        set_cursor_position: simple_text_output::ProtocolSetCursorPosition,
        enable_cursor: simple_text_output::ProtocolEnableCursor,
        mode: *mut simple_text_output::Mode,
        _buffer: Vec<u16>,
    }

    impl PipeProtocol {
        pub fn new() -> Self {
            let mode = Box::new(simple_text_output::Mode {
                max_mode: 0,
                mode: 0,
                attribute: 0,
                cursor_column: 0,
                cursor_row: 0,
                cursor_visible: r_efi::efi::Boolean::FALSE,
            });
            Self {
                reset: Self::reset,
                output_string: Self::output_string,
                test_string: Self::test_string,
                query_mode: Self::query_mode,
                set_mode: Self::set_mode,
                set_attribute: Self::set_attribute,
                clear_screen: Self::clear_screen,
                set_cursor_position: Self::set_cursor_position,
                enable_cursor: Self::enable_cursor,
                mode: Box::into_raw(mode),
                _buffer: Vec::new(),
            }
        }

        pub fn null() -> Self {
            let mode = Box::new(simple_text_output::Mode {
                max_mode: 0,
                mode: 0,
                attribute: 0,
                cursor_column: 0,
                cursor_row: 0,
                cursor_visible: r_efi::efi::Boolean::FALSE,
            });
            Self {
                reset: Self::reset_null,
                output_string: Self::output_string_null,
                test_string: Self::test_string,
                query_mode: Self::query_mode,
                set_mode: Self::set_mode,
                set_attribute: Self::set_attribute,
                clear_screen: Self::clear_screen,
                set_cursor_position: Self::set_cursor_position,
                enable_cursor: Self::enable_cursor,
                mode: Box::into_raw(mode),
                _buffer: Vec::new(),
            }
        }

        pub fn utf8(&self) -> io::Result<Vec<u8>> {
            OsString::from_wide(&self._buffer)
                .into_string()
                .map(Into::into)
                .map_err(|_| const_error!(io::ErrorKind::Other, "UTF-8 conversion failed"))
        }

        extern "efiapi" fn reset(
            proto: *mut simple_text_output::Protocol,
            _: r_efi::efi::Boolean,
        ) -> r_efi::efi::Status {
            let proto: *mut PipeProtocol = proto.cast();
            unsafe {
                (*proto)._buffer.clear();
            }
            r_efi::efi::Status::SUCCESS
        }

        extern "efiapi" fn reset_null(
            _: *mut simple_text_output::Protocol,
            _: r_efi::efi::Boolean,
        ) -> r_efi::efi::Status {
            r_efi::efi::Status::SUCCESS
        }

        extern "efiapi" fn output_string(
            proto: *mut simple_text_output::Protocol,
            buf: *mut r_efi::efi::Char16,
        ) -> r_efi::efi::Status {
            let proto: *mut PipeProtocol = proto.cast();
            let buf_len = unsafe {
                if let Some(x) = WStrUnits::new(buf) {
                    x.count()
                } else {
                    return r_efi::efi::Status::INVALID_PARAMETER;
                }
            };
            let buf_slice = unsafe { slice::from_raw_parts(buf, buf_len) };

            unsafe {
                (*proto)._buffer.extend_from_slice(buf_slice);
            };

            r_efi::efi::Status::SUCCESS
        }

        extern "efiapi" fn output_string_null(
            _: *mut simple_text_output::Protocol,
            _: *mut r_efi::efi::Char16,
        ) -> r_efi::efi::Status {
            r_efi::efi::Status::SUCCESS
        }

        extern "efiapi" fn test_string(
            _: *mut simple_text_output::Protocol,
            _: *mut r_efi::efi::Char16,
        ) -> r_efi::efi::Status {
            r_efi::efi::Status::SUCCESS
        }

        extern "efiapi" fn query_mode(
            _: *mut simple_text_output::Protocol,
            _: usize,
            _: *mut usize,
            _: *mut usize,
        ) -> r_efi::efi::Status {
            r_efi::efi::Status::UNSUPPORTED
        }

        extern "efiapi" fn set_mode(
            _: *mut simple_text_output::Protocol,
            _: usize,
        ) -> r_efi::efi::Status {
            r_efi::efi::Status::UNSUPPORTED
        }

        extern "efiapi" fn set_attribute(
            _: *mut simple_text_output::Protocol,
            _: usize,
        ) -> r_efi::efi::Status {
            r_efi::efi::Status::UNSUPPORTED
        }

        extern "efiapi" fn clear_screen(
            _: *mut simple_text_output::Protocol,
        ) -> r_efi::efi::Status {
            r_efi::efi::Status::UNSUPPORTED
        }

        extern "efiapi" fn set_cursor_position(
            _: *mut simple_text_output::Protocol,
            _: usize,
            _: usize,
        ) -> r_efi::efi::Status {
            r_efi::efi::Status::UNSUPPORTED
        }

        extern "efiapi" fn enable_cursor(
            _: *mut simple_text_output::Protocol,
            _: r_efi::efi::Boolean,
        ) -> r_efi::efi::Status {
            r_efi::efi::Status::UNSUPPORTED
        }
    }

    impl Drop for PipeProtocol {
        fn drop(&mut self) {
            unsafe {
                let _ = Box::from_raw(self.mode);
            }
        }
    }

    #[repr(C)]
    pub(crate) struct InputProtocol {
        reset: simple_text_input::ProtocolReset,
        read_key_stroke: simple_text_input::ProtocolReadKeyStroke,
        wait_for_key: r_efi::efi::Event,
    }

    impl InputProtocol {
        pub(crate) fn null() -> Self {
            let evt = helpers::OwnedEvent::new(
                r_efi::efi::EVT_NOTIFY_WAIT,
                r_efi::efi::TPL_CALLBACK,
                Some(Self::empty_notify),
                None,
            )
            .unwrap();

            Self {
                reset: Self::null_reset,
                read_key_stroke: Self::null_read_key,
                wait_for_key: evt.into_raw(),
            }
        }

        extern "efiapi" fn null_reset(
            _: *mut simple_text_input::Protocol,
            _: r_efi::efi::Boolean,
        ) -> r_efi::efi::Status {
            r_efi::efi::Status::SUCCESS
        }

        extern "efiapi" fn null_read_key(
            _: *mut simple_text_input::Protocol,
            _: *mut simple_text_input::InputKey,
        ) -> r_efi::efi::Status {
            r_efi::efi::Status::UNSUPPORTED
        }

        extern "efiapi" fn empty_notify(_: r_efi::efi::Event, _: *mut crate::ffi::c_void) {}
    }

    impl Drop for InputProtocol {
        fn drop(&mut self) {
            // Close wait_for_key
            unsafe {
                let _ = helpers::OwnedEvent::from_raw(self.wait_for_key);
            }
        }
    }

    pub fn create_args(prog: &OsStr, args: &[OsString]) -> Box<[u16]> {
        const QUOTE: u16 = 0x0022;
        const SPACE: u16 = 0x0020;
        const CARET: u16 = 0x005e;
        const NULL: u16 = 0;

        // This is the lower bound on the final length under the assumption that
        // the arguments only contain ASCII characters.
        let mut res = Vec::with_capacity(args.iter().map(|arg| arg.len() + 3).sum());

        // Wrap program name in quotes to avoid any problems
        res.push(QUOTE);
        res.extend(prog.encode_wide());
        res.push(QUOTE);

        for arg in args {
            res.push(SPACE);

            // Wrap the argument in quotes to be treat as single arg
            res.push(QUOTE);
            for c in arg.encode_wide() {
                // CARET in quotes is used to escape CARET or QUOTE
                if c == QUOTE || c == CARET {
                    res.push(CARET);
                }
                res.push(c);
            }
            res.push(QUOTE);
        }

        res.into_boxed_slice()
    }
}

/// Create a map of environment variable changes. Allows efficient setting and rolling back of
/// environment variable changes.
///
/// Entry: (Old Value, New Value)
fn env_changes(env: &CommandEnv) -> Option<BTreeMap<EnvKey, (Option<OsString>, Option<OsString>)>> {
    if env.is_unchanged() {
        return None;
    }

    let mut result = BTreeMap::<EnvKey, (Option<OsString>, Option<OsString>)>::new();

    // Check if we want to clear all prior variables
    if env.does_clear() {
        for (k, v) in crate::env::vars_os() {
            result.insert(k.into(), (Some(v), None));
        }
    }

    for (k, v) in env.iter() {
        let v: Option<OsString> = v.map(Into::into);
        result
            .entry(k.into())
            .and_modify(|cur| *cur = (cur.0.clone(), v.clone()))
            .or_insert((crate::env::var_os(k), v));
    }

    Some(result)
}

```

**💡 建议：**
Ensure Drop implementations never panic

#### 漏洞 #10：Potential panic in Drop implementation detected

**详情：**
- **Type:** `drop-panic`
- **Severity:** `Critical`
- **Confidence:** `90.0%`
- **Location:** `d:\漏洞挖掘\detector\project\library\std\src\sys\sync\mutex\xous.rs:0`
- **检测方法：** `StaticAnalysis`

**解释：**
Drop implementation may panic, which can cause undefined behavior

**代码：**
```rust
use crate::os::xous::ffi::{blocking_scalar, do_yield};
use crate::os::xous::services::{TicktimerScalar, ticktimer_server};
use crate::sync::atomic::Ordering::{Acquire, Relaxed, Release};
use crate::sync::atomic::{Atomic, AtomicBool, AtomicUsize};

pub struct Mutex {
    /// The "locked" value indicates how many threads are waiting on this
    /// Mutex. Possible values are:
    ///     0: The lock is unlocked
    ///     1: The lock is locked and uncontended
    ///   >=2: The lock is locked and contended
    ///
    /// A lock is "contended" when there is more than one thread waiting
    /// for a lock, or it is locked for long periods of time. Rather than
    /// spinning, these locks send a Message to the ticktimer server
    /// requesting that they be woken up when a lock is unlocked.
    locked: Atomic<usize>,

    /// Whether this Mutex ever was contended, and therefore made a trip
    /// to the ticktimer server. If this was never set, then we were never
    /// on the slow path and can skip deregistering the mutex.
    contended: Atomic<bool>,
}

impl Mutex {
    #[inline]
    pub const fn new() -> Mutex {
        Mutex { locked: AtomicUsize::new(0), contended: AtomicBool::new(false) }
    }

    fn index(&self) -> usize {
        core::ptr::from_ref(self).addr()
    }

    #[inline]
    pub unsafe fn lock(&self) {
        // Try multiple times to acquire the lock without resorting to the ticktimer
        // server. For locks that are held for a short amount of time, this will
        // result in the ticktimer server never getting invoked. The `locked` value
        // will be either 0 or 1.
        for _attempts in 0..3 {
            if unsafe { self.try_lock() } {
                return;
            }
            do_yield();
        }

        // Try one more time to lock. If the lock is released between the previous code and
        // here, then the inner `locked` value will be 1 at the end of this. If it was not
        // locked, then the value will be more than 1, for example if there are multiple other
        // threads waiting on this lock.
        if unsafe { self.try_lock_or_poison() } {
            return;
        }

        // When this mutex is dropped, we will need to deregister it with the server.
        self.contended.store(true, Relaxed);

        // The lock is now "contended". When the lock is released, a Message will get sent to the
        // ticktimer server to wake it up. Note that this may already have happened, so the actual
        // value of `lock` may be anything (0, 1, 2, ...).
        blocking_scalar(
            ticktimer_server(),
            crate::os::xous::services::TicktimerScalar::LockMutex(self.index()).into(),
        )
        .expect("failure to send LockMutex command");
    }

    #[inline]
    pub unsafe fn unlock(&self) {
        let prev = self.locked.fetch_sub(1, Release);

        // If the previous value was 1, then this was a "fast path" unlock, so no
        // need to involve the Ticktimer server
        if prev == 1 {
            return;
        }

        // If it was 0, then something has gone seriously wrong and the counter
        // has just wrapped around.
        if prev == 0 {
            panic!("mutex lock count underflowed");
        }

        // Unblock one thread that is waiting on this message.
        blocking_scalar(ticktimer_server(), TicktimerScalar::UnlockMutex(self.index()).into())
            .expect("failure to send UnlockMutex command");
    }

    #[inline]
    pub unsafe fn try_lock(&self) -> bool {
        self.locked.compare_exchange(0, 1, Acquire, Relaxed).is_ok()
    }

    #[inline]
    pub unsafe fn try_lock_or_poison(&self) -> bool {
        self.locked.fetch_add(1, Acquire) == 0
    }
}

impl Drop for Mutex {
    fn drop(&mut self) {
        // If there was Mutex contention, then we involved the ticktimer. Free
        // the resources associated with this Mutex as it is deallocated.
        if self.contended.load(Relaxed) {
            blocking_scalar(ticktimer_server(), TicktimerScalar::FreeMutex(self.index()).into())
                .ok();
        }
    }
}

```

**💡 建议：**
Ensure Drop implementations never panic

#### 漏洞 #11：Potential panic in Drop implementation detected

**详情：**
- **Type:** `drop-panic`
- **Severity:** `Critical`
- **Confidence:** `90.0%`
- **Location:** `d:\漏洞挖掘\detector\project\library\std\src\sys\sync\once\queue.rs:0`
- **检测方法：** `StaticAnalysis`

**解释：**
Drop implementation may panic, which can cause undefined behavior

**代码：**
```rust
// Each `Once` has one word of atomic state, and this state is CAS'd on to
// determine what to do. There are four possible state of a `Once`:
//
// * Incomplete - no initialization has run yet, and no thread is currently
//                using the Once.
// * Poisoned - some thread has previously attempted to initialize the Once, but
//              it panicked, so the Once is now poisoned. There are no other
//              threads currently accessing this Once.
// * Running - some thread is currently attempting to run initialization. It may
//             succeed, so all future threads need to wait for it to finish.
//             Note that this state is accompanied with a payload, described
//             below.
// * Complete - initialization has completed and all future calls should finish
//              immediately.
//
// With 4 states we need 2 bits to encode this, and we use the remaining bits
// in the word we have allocated as a queue of threads waiting for the thread
// responsible for entering the RUNNING state. This queue is just a linked list
// of Waiter nodes which is monotonically increasing in size. Each node is
// allocated on the stack, and whenever the running closure finishes it will
// consume the entire queue and notify all waiters they should try again.
//
// You'll find a few more details in the implementation, but that's the gist of
// it!
//
// Futex orderings:
// When running `Once` we deal with multiple atomics:
// `Once.state_and_queue` and an unknown number of `Waiter.signaled`.
// * `state_and_queue` is used (1) as a state flag, (2) for synchronizing the
//   result of the `Once`, and (3) for synchronizing `Waiter` nodes.
//     - At the end of the `call` function we have to make sure the result
//       of the `Once` is acquired. So every load which can be the only one to
//       load COMPLETED must have at least acquire ordering, which means all
//       three of them.
//     - `WaiterQueue::drop` is the only place that may store COMPLETED, and
//       must do so with release ordering to make the result available.
//     - `wait` inserts `Waiter` nodes as a pointer in `state_and_queue`, and
//       needs to make the nodes available with release ordering. The load in
//       its `compare_exchange` can be relaxed because it only has to compare
//       the atomic, not to read other data.
//     - `WaiterQueue::drop` must see the `Waiter` nodes, so it must load
//       `state_and_queue` with acquire ordering.
//     - There is just one store where `state_and_queue` is used only as a
//       state flag, without having to synchronize data: switching the state
//       from INCOMPLETE to RUNNING in `call`. This store can be Relaxed,
//       but the read has to be Acquire because of the requirements mentioned
//       above.
// * `Waiter.signaled` is both used as a flag, and to protect a field with
//   interior mutability in `Waiter`. `Waiter.thread` is changed in
//   `WaiterQueue::drop` which then sets `signaled` with release ordering.
//   After `wait` loads `signaled` with acquire ordering and sees it is true,
//   it needs to see the changes to drop the `Waiter` struct correctly.
// * There is one place where the two atomics `Once.state_and_queue` and
//   `Waiter.signaled` come together, and might be reordered by the compiler or
//   processor. Because both use acquire ordering such a reordering is not
//   allowed, so no need for `SeqCst`.

use crate::cell::Cell;
use crate::sync::atomic::Ordering::{AcqRel, Acquire, Release};
use crate::sync::atomic::{Atomic, AtomicBool, AtomicPtr};
use crate::sync::once::OnceExclusiveState;
use crate::thread::{self, Thread};
use crate::{fmt, ptr, sync as public};

type StateAndQueue = *mut ();

pub struct Once {
    state_and_queue: Atomic<*mut ()>,
}

pub struct OnceState {
    poisoned: bool,
    set_state_on_drop_to: Cell<StateAndQueue>,
}

// Four states that a Once can be in, encoded into the lower bits of
// `state_and_queue` in the Once structure. By choosing COMPLETE as the all-zero
// state the `is_completed` check can be a bit faster on some platforms.
const INCOMPLETE: usize = 0x3;
const POISONED: usize = 0x2;
const RUNNING: usize = 0x1;
const COMPLETE: usize = 0x0;

// Mask to learn about the state. All other bits are the queue of waiters if
// this is in the RUNNING state.
const STATE_MASK: usize = 0b11;
const QUEUE_MASK: usize = !STATE_MASK;

// Representation of a node in the linked list of waiters, used while in the
// RUNNING state.
// Note: `Waiter` can't hold a mutable pointer to the next thread, because then
// `wait` would both hand out a mutable reference to its `Waiter` node, and keep
// a shared reference to check `signaled`. Instead we hold shared references and
// use interior mutability.
#[repr(align(4))] // Ensure the two lower bits are free to use as state bits.
struct Waiter {
    thread: Thread,
    signaled: Atomic<bool>,
    next: Cell<*const Waiter>,
}

// Head of a linked list of waiters.
// Every node is a struct on the stack of a waiting thread.
// Will wake up the waiters when it gets dropped, i.e. also on panic.
struct WaiterQueue<'a> {
    state_and_queue: &'a Atomic<*mut ()>,
    set_state_on_drop_to: StateAndQueue,
}

fn to_queue(current: StateAndQueue) -> *const Waiter {
    current.mask(QUEUE_MASK).cast()
}

fn to_state(current: StateAndQueue) -> usize {
    current.addr() & STATE_MASK
}

impl Once {
    #[inline]
    pub const fn new() -> Once {
        Once { state_and_queue: AtomicPtr::new(ptr::without_provenance_mut(INCOMPLETE)) }
    }

    #[inline]
    pub fn is_completed(&self) -> bool {
        // An `Acquire` load is enough because that makes all the initialization
        // operations visible to us, and, this being a fast path, weaker
        // ordering helps with performance. This `Acquire` synchronizes with
        // `Release` operations on the slow path.
        self.state_and_queue.load(Acquire).addr() == COMPLETE
    }

    #[inline]
    pub(crate) fn state(&mut self) -> OnceExclusiveState {
        match self.state_and_queue.get_mut().addr() {
            INCOMPLETE => OnceExclusiveState::Incomplete,
            POISONED => OnceExclusiveState::Poisoned,
            COMPLETE => OnceExclusiveState::Complete,
            _ => unreachable!("invalid Once state"),
        }
    }

    #[inline]
    pub(crate) fn set_state(&mut self, new_state: OnceExclusiveState) {
        *self.state_and_queue.get_mut() = match new_state {
            OnceExclusiveState::Incomplete => ptr::without_provenance_mut(INCOMPLETE),
            OnceExclusiveState::Poisoned => ptr::without_provenance_mut(POISONED),
            OnceExclusiveState::Complete => ptr::without_provenance_mut(COMPLETE),
        };
    }

    #[cold]
    #[track_caller]
    pub fn wait(&self, ignore_poisoning: bool) {
        let mut current = self.state_and_queue.load(Acquire);
        loop {
            let state = to_state(current);
            match state {
                COMPLETE => return,
                POISONED if !ignore_poisoning => {
                    // Panic to propagate the poison.
                    panic!("Once instance has previously been poisoned");
                }
                _ => {
                    current = wait(&self.state_and_queue, current, !ignore_poisoning);
                }
            }
        }
    }

    // This is a non-generic function to reduce the monomorphization cost of
    // using `call_once` (this isn't exactly a trivial or small implementation).
    //
    // Additionally, this is tagged with `#[cold]` as it should indeed be cold
    // and it helps let LLVM know that calls to this function should be off the
    // fast path. Essentially, this should help generate more straight line code
    // in LLVM.
    //
    // Finally, this takes an `FnMut` instead of a `FnOnce` because there's
    // currently no way to take an `FnOnce` and call it via virtual dispatch
    // without some allocation overhead.
    #[cold]
    #[track_caller]
    pub fn call(&self, ignore_poisoning: bool, init: &mut dyn FnMut(&public::OnceState)) {
        let mut current = self.state_and_queue.load(Acquire);
        loop {
            let state = to_state(current);
            match state {
                COMPLETE => break,
                POISONED if !ignore_poisoning => {
                    // Panic to propagate the poison.
                    panic!("Once instance has previously been poisoned");
                }
                POISONED | INCOMPLETE => {
                    // Try to register this thread as the one RUNNING.
                    if let Err(new) = self.state_and_queue.compare_exchange_weak(
                        current,
                        current.mask(QUEUE_MASK).wrapping_byte_add(RUNNING),
                        Acquire,
                        Acquire,
                    ) {
                        current = new;
                        continue;
                    }

                    // `waiter_queue` will manage other waiting threads, and
                    // wake them up on drop.
                    let mut waiter_queue = WaiterQueue {
                        state_and_queue: &self.state_and_queue,
                        set_state_on_drop_to: ptr::without_provenance_mut(POISONED),
                    };
                    // Run the initialization function, letting it know if we're
                    // poisoned or not.
                    let init_state = public::OnceState {
                        inner: OnceState {
                            poisoned: state == POISONED,
                            set_state_on_drop_to: Cell::new(ptr::without_provenance_mut(COMPLETE)),
                        },
                    };
                    init(&init_state);
                    waiter_queue.set_state_on_drop_to = init_state.inner.set_state_on_drop_to.get();
                    return;
                }
                _ => {
                    // All other values must be RUNNING with possibly a
                    // pointer to the waiter queue in the more significant bits.
                    assert!(state == RUNNING);
                    current = wait(&self.state_and_queue, current, true);
                }
            }
        }
    }
}

fn wait(
    state_and_queue: &Atomic<*mut ()>,
    mut current: StateAndQueue,
    return_on_poisoned: bool,
) -> StateAndQueue {
    let node = &Waiter {
        thread: thread::current_or_unnamed(),
        signaled: AtomicBool::new(false),
        next: Cell::new(ptr::null()),
    };

    loop {
        let state = to_state(current);
        let queue = to_queue(current);

        // If initialization has finished, return.
        if state == COMPLETE || (return_on_poisoned && state == POISONED) {
            return current;
        }

        // Update the node for our current thread.
        node.next.set(queue);

        // Try to slide in the node at the head of the linked list, making sure
        // that another thread didn't just replace the head of the linked list.
        if let Err(new) = state_and_queue.compare_exchange_weak(
            current,
            ptr::from_ref(node).wrapping_byte_add(state) as StateAndQueue,
            Release,
            Acquire,
        ) {
            current = new;
            continue;
        }

        // We have enqueued ourselves, now lets wait.
        // It is important not to return before being signaled, otherwise we
        // would drop our `Waiter` node and leave a hole in the linked list
        // (and a dangling reference). Guard against spurious wakeups by
        // reparking ourselves until we are signaled.
        while !node.signaled.load(Acquire) {
            // If the managing thread happens to signal and unpark us before we
            // can park ourselves, the result could be this thread never gets
            // unparked. Luckily `park` comes with the guarantee that if it got
            // an `unpark` just before on an unparked thread it does not park. Crucially, we know
            // the `unpark` must have happened between the `compare_exchange_weak` above and here,
            // and there's no other `park` in that code that could steal our token.
            // SAFETY: we retrieved this handle on the current thread above.
            unsafe { node.thread.park() }
        }

        return state_and_queue.load(Acquire);
    }
}

#[stable(feature = "std_debug", since = "1.16.0")]
impl fmt::Debug for Once {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Once").finish_non_exhaustive()
    }
}

impl Drop for WaiterQueue<'_> {
    fn drop(&mut self) {
        // Swap out our state with however we finished.
        let current = self.state_and_queue.swap(self.set_state_on_drop_to, AcqRel);

        // We should only ever see an old state which was RUNNING.
        assert_eq!(current.addr() & STATE_MASK, RUNNING);

        // Walk the entire linked list of waiters and wake them up (in lifo
        // order, last to register is first to wake up).
        unsafe {
            // Right after setting `node.signaled = true` the other thread may
            // free `node` if there happens to be has a spurious wakeup.
            // So we have to take out the `thread` field and copy the pointer to
            // `next` first.
            let mut queue = to_queue(current);
            while !queue.is_null() {
                let next = (*queue).next.get();
                let thread = (*queue).thread.clone();
                (*queue).signaled.store(true, Release);
                thread.unpark();
                queue = next;
            }
        }
    }
}

impl OnceState {
    #[inline]
    pub fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    #[inline]
    pub fn poison(&self) {
        self.set_state_on_drop_to.set(ptr::without_provenance_mut(POISONED));
    }
}

```

**💡 建议：**
Ensure Drop implementations never panic

#### 漏洞 #12：Potential panic in Drop implementation detected

**详情：**
- **Type:** `drop-panic`
- **Severity:** `Critical`
- **Confidence:** `90.0%`
- **Location:** `d:\漏洞挖掘\detector\project\library\std\src\sys\thread\teeos.rs:0`
- **检测方法：** `StaticAnalysis`

**解释：**
Drop implementation may panic, which can cause undefined behavior

**代码：**
```rust
use crate::mem::{self, ManuallyDrop};
use crate::sys::os;
use crate::time::Duration;
use crate::{cmp, io, ptr};

pub const DEFAULT_MIN_STACK_SIZE: usize = 8 * 1024;

unsafe extern "C" {
    safe fn TEE_Wait(timeout: u32) -> u32;
}

fn min_stack_size(_: *const libc::pthread_attr_t) -> usize {
    libc::PTHREAD_STACK_MIN.try_into().expect("Infallible")
}

pub struct Thread {
    id: libc::pthread_t,
}

// Some platforms may have pthread_t as a pointer in which case we still want
// a thread to be Send/Sync
unsafe impl Send for Thread {}
unsafe impl Sync for Thread {}

impl Thread {
    // unsafe: see thread::Builder::spawn_unchecked for safety requirements
    pub unsafe fn new(
        stack: usize,
        _name: Option<&str>,
        p: Box<dyn FnOnce()>,
    ) -> io::Result<Thread> {
        let p = Box::into_raw(Box::new(p));
        let mut native: libc::pthread_t = unsafe { mem::zeroed() };
        let mut attr: libc::pthread_attr_t = unsafe { mem::zeroed() };
        assert_eq!(unsafe { libc::pthread_attr_init(&mut attr) }, 0);
        assert_eq!(
            unsafe {
                libc::pthread_attr_settee(
                    &mut attr,
                    libc::TEESMP_THREAD_ATTR_CA_INHERIT,
                    libc::TEESMP_THREAD_ATTR_TASK_ID_INHERIT,
                    libc::TEESMP_THREAD_ATTR_HAS_SHADOW,
                )
            },
            0,
        );

        let stack_size = cmp::max(stack, min_stack_size(&attr));

        match unsafe { libc::pthread_attr_setstacksize(&mut attr, stack_size) } {
            0 => {}
            n => {
                assert_eq!(n, libc::EINVAL);
                // EINVAL means |stack_size| is either too small or not a
                // multiple of the system page size.  Because it's definitely
                // >= PTHREAD_STACK_MIN, it must be an alignment issue.
                // Round up to the nearest page and try again.
                let page_size = os::page_size();
                let stack_size =
                    (stack_size + page_size - 1) & (-(page_size as isize - 1) as usize - 1);
                assert_eq!(unsafe { libc::pthread_attr_setstacksize(&mut attr, stack_size) }, 0);
            }
        };

        let ret = unsafe { libc::pthread_create(&mut native, &attr, thread_start, p as *mut _) };
        // Note: if the thread creation fails and this assert fails, then p will
        // be leaked. However, an alternative design could cause double-free
        // which is clearly worse.
        assert_eq!(unsafe { libc::pthread_attr_destroy(&mut attr) }, 0);

        return if ret != 0 {
            // The thread failed to start and as a result p was not consumed. Therefore, it is
            // safe to reconstruct the box so that it gets deallocated.
            drop(unsafe { Box::from_raw(p) });
            Err(io::Error::from_raw_os_error(ret))
        } else {
            // The new thread will start running earliest after the next yield.
            // We add a yield here, so that the user does not have to.
            yield_now();
            Ok(Thread { id: native })
        };

        extern "C" fn thread_start(main: *mut libc::c_void) -> *mut libc::c_void {
            unsafe {
                // Next, set up our stack overflow handler which may get triggered if we run
                // out of stack.
                // this is not necessary in TEE.
                //let _handler = stack_overflow::Handler::new();
                // Finally, let's run some code.
                Box::from_raw(main as *mut Box<dyn FnOnce()>)();
            }
            ptr::null_mut()
        }
    }

    /// must join, because no pthread_detach supported
    pub fn join(self) {
        let id = self.into_id();
        let ret = unsafe { libc::pthread_join(id, ptr::null_mut()) };
        assert!(ret == 0, "failed to join thread: {}", io::Error::from_raw_os_error(ret));
    }

    pub fn into_id(self) -> libc::pthread_t {
        ManuallyDrop::new(self).id
    }
}

impl Drop for Thread {
    fn drop(&mut self) {
        // we can not call detach, so just panic if thread spawn without join
        panic!("thread must join, detach is not supported!");
    }
}

pub fn yield_now() {
    let ret = unsafe { libc::sched_yield() };
    debug_assert_eq!(ret, 0);
}

/// only main thread could wait for sometime in teeos
pub fn sleep(dur: Duration) {
    let sleep_millis = dur.as_millis();
    let final_sleep: u32 =
        if sleep_millis >= u32::MAX as u128 { u32::MAX } else { sleep_millis as u32 };
    TEE_Wait(final_sleep);
}

```

**💡 建议：**
Ensure Drop implementations never panic

#### 漏洞 #13：Potential panic in Drop implementation detected

**详情：**
- **Type:** `drop-panic`
- **Severity:** `Critical`
- **Confidence:** `90.0%`
- **Location:** `d:\漏洞挖掘\detector\project\library\std\src\sys\thread\wasip1.rs:0`
- **检测方法：** `StaticAnalysis`

**解释：**
Drop implementation may panic, which can cause undefined behavior

**代码：**
```rust
#![forbid(unsafe_op_in_unsafe_fn)]

#[cfg(target_feature = "atomics")]
use crate::io;
use crate::mem;
#[cfg(target_feature = "atomics")]
use crate::num::NonZero;
#[cfg(target_feature = "atomics")]
use crate::sys::os;
use crate::time::Duration;
#[cfg(target_feature = "atomics")]
use crate::{cmp, ptr};

// Add a few symbols not in upstream `libc` just yet.
#[cfg(target_feature = "atomics")]
mod libc {
    pub use libc::*;

    pub use crate::ffi;

    // defined in wasi-libc
    // https://github.com/WebAssembly/wasi-libc/blob/a6f871343313220b76009827ed0153586361c0d5/libc-top-half/musl/include/alltypes.h.in#L108
    #[repr(C)]
    union pthread_attr_union {
        __i: [ffi::c_int; if size_of::<ffi::c_long>() == 8 { 14 } else { 9 }],
        __vi: [ffi::c_int; if size_of::<ffi::c_long>() == 8 { 14 } else { 9 }],
        __s: [ffi::c_ulong; if size_of::<ffi::c_long>() == 8 { 7 } else { 9 }],
    }

    #[repr(C)]
    pub struct pthread_attr_t {
        __u: pthread_attr_union,
    }

    #[allow(non_camel_case_types)]
    pub type pthread_t = *mut ffi::c_void;

    pub const _SC_NPROCESSORS_ONLN: ffi::c_int = 84;

    unsafe extern "C" {
        pub fn pthread_create(
            native: *mut pthread_t,
            attr: *const pthread_attr_t,
            f: extern "C" fn(*mut ffi::c_void) -> *mut ffi::c_void,
            value: *mut ffi::c_void,
        ) -> ffi::c_int;
        pub fn pthread_join(native: pthread_t, value: *mut *mut ffi::c_void) -> ffi::c_int;
        pub fn pthread_attr_init(attrp: *mut pthread_attr_t) -> ffi::c_int;
        pub fn pthread_attr_setstacksize(
            attr: *mut pthread_attr_t,
            stack_size: libc::size_t,
        ) -> ffi::c_int;
        pub fn pthread_attr_destroy(attr: *mut pthread_attr_t) -> ffi::c_int;
        pub fn pthread_detach(thread: pthread_t) -> ffi::c_int;
    }
}

#[cfg(target_feature = "atomics")]
pub struct Thread {
    id: libc::pthread_t,
}

#[cfg(target_feature = "atomics")]
impl Drop for Thread {
    fn drop(&mut self) {
        let ret = unsafe { libc::pthread_detach(self.id) };
        debug_assert_eq!(ret, 0);
    }
}

pub const DEFAULT_MIN_STACK_SIZE: usize = 1024 * 1024;

#[cfg(target_feature = "atomics")]
impl Thread {
    // unsafe: see thread::Builder::spawn_unchecked for safety requirements
    pub unsafe fn new(
        stack: usize,
        _name: Option<&str>,
        p: Box<dyn FnOnce()>,
    ) -> io::Result<Thread> {
        let p = Box::into_raw(Box::new(p));
        let mut native: libc::pthread_t = unsafe { mem::zeroed() };
        let mut attr: libc::pthread_attr_t = unsafe { mem::zeroed() };
        assert_eq!(unsafe { libc::pthread_attr_init(&mut attr) }, 0);

        let stack_size = cmp::max(stack, DEFAULT_MIN_STACK_SIZE);

        match unsafe { libc::pthread_attr_setstacksize(&mut attr, stack_size) } {
            0 => {}
            n => {
                assert_eq!(n, libc::EINVAL);
                // EINVAL means |stack_size| is either too small or not a
                // multiple of the system page size. Because it's definitely
                // >= PTHREAD_STACK_MIN, it must be an alignment issue.
                // Round up to the nearest page and try again.
                let page_size = os::page_size();
                let stack_size =
                    (stack_size + page_size - 1) & (-(page_size as isize - 1) as usize - 1);
                assert_eq!(unsafe { libc::pthread_attr_setstacksize(&mut attr, stack_size) }, 0);
            }
        };

        let ret = unsafe { libc::pthread_create(&mut native, &attr, thread_start, p as *mut _) };
        // Note: if the thread creation fails and this assert fails, then p will
        // be leaked. However, an alternative design could cause double-free
        // which is clearly worse.
        assert_eq!(unsafe { libc::pthread_attr_destroy(&mut attr) }, 0);

        return if ret != 0 {
            // The thread failed to start and as a result p was not consumed. Therefore, it is
            // safe to reconstruct the box so that it gets deallocated.
            unsafe {
                drop(Box::from_raw(p));
            }
            Err(io::Error::from_raw_os_error(ret))
        } else {
            Ok(Thread { id: native })
        };

        extern "C" fn thread_start(main: *mut libc::c_void) -> *mut libc::c_void {
            unsafe {
                // Finally, let's run some code.
                Box::from_raw(main as *mut Box<dyn FnOnce()>)();
            }
            ptr::null_mut()
        }
    }

    pub fn join(self) {
        let id = mem::ManuallyDrop::new(self).id;
        let ret = unsafe { libc::pthread_join(id, ptr::null_mut()) };
        if ret != 0 {
            rtabort!("failed to join thread: {}", io::Error::from_raw_os_error(ret));
        }
    }
}

#[cfg(target_feature = "atomics")]
pub fn available_parallelism() -> io::Result<NonZero<usize>> {
    match unsafe { libc::sysconf(libc::_SC_NPROCESSORS_ONLN) } {
        -1 => Err(io::Error::last_os_error()),
        cpus => NonZero::new(cpus as usize).ok_or(io::Error::UNKNOWN_THREAD_COUNT),
    }
}

pub fn yield_now() {
    let ret = unsafe { wasi::sched_yield() };
    debug_assert_eq!(ret, Ok(()));
}

pub fn sleep(dur: Duration) {
    let mut nanos = dur.as_nanos();
    while nanos > 0 {
        const USERDATA: wasi::Userdata = 0x0123_45678;

        let clock = wasi::SubscriptionClock {
            id: wasi::CLOCKID_MONOTONIC,
            timeout: u64::try_from(nanos).unwrap_or(u64::MAX),
            precision: 0,
            flags: 0,
        };
        nanos -= u128::from(clock.timeout);

        let in_ = wasi::Subscription {
            userdata: USERDATA,
            u: wasi::SubscriptionU { tag: 0, u: wasi::SubscriptionUU { clock } },
        };
        unsafe {
            let mut event: wasi::Event = mem::zeroed();
            let res = wasi::poll_oneoff(&in_, &mut event, 1);
            match (res, event) {
                (
                    Ok(1),
                    wasi::Event {
                        userdata: USERDATA,
                        error: wasi::ERRNO_SUCCESS,
                        type_: wasi::EVENTTYPE_CLOCK,
                        ..
                    },
                ) => {}
                _ => panic!("thread::sleep(): unexpected result of poll_oneoff"),
            }
        }
    }
}

```

**💡 建议：**
Ensure Drop implementations never panic

### High（共 3 条）

#### 漏洞 #1：Uninitialized memory read detected

**详情：**
- **Type:** `uninitialized-read`
- **Severity:** `High`
- **Confidence:** `90.0%`
- **Location:** `d:\漏洞挖掘\detector\project\library\core\src\mem\mod.rs:712`
- **检测方法：** `StaticAnalysis`

**解释：**
assume_init used on uninitialized value within unsafe block

**代码：**
```rust
    unsafe {
        intrinsics::assert_mem_uninitialized_valid::<T>();
        let mut val = MaybeUninit::<T>::uninit();

        // Fill memory with 0x01, as an imperfect mitigation for old code that uses this function on
        // bool, nonnull, and noundef types. But don't do this if we actively want to detect UB.
        if !cfg!(any(miri, sanitize = "memory")) {
            val.as_mut_ptr().write_bytes(0x01, 1);
        }

        val.assume_init()
    }
```

**💡 建议：**
Initialize memory before reading or avoid assume_init on uninit

#### 漏洞 #2：Uninitialized memory read detected

**详情：**
- **Type:** `uninitialized-read`
- **Severity:** `High`
- **Confidence:** `90.0%`
- **Location:** `d:\漏洞挖掘\detector\project\library\std\src\sys\stdio\windows.rs:286`
- **检测方法：** `StaticAnalysis`

**解释：**
assume_init used on uninitialized value within unsafe block

**代码：**
```rust
                unsafe { utf16_buf[..read].assume_init_ref() },
                &mut self.incomplete_utf8.bytes,
            )?;

            // Read in the bytes from incomplete_utf8 until the buffer is full.
            self.incomplete_utf8.len = read_bytes as u8;
            // No-op if no bytes.
            bytes_copied += self.incomplete_utf8.read(&mut buf[bytes_copied..]);
            Ok(bytes_copied)
        } else {
            let mut utf16_buf = [MaybeUninit::<u16>::uninit(); MAX_BUFFER_SIZE / 2];

            // In the worst case, a UTF-8 string can take 3 bytes for every `u16` of a UTF-16. So
            // we can read at most a third of `buf.len()` chars and uphold the guarantee no data gets
            // lost.
            let amount = cmp::min(buf.len() / 3, utf16_buf.len());
            let read =
                read_u16s_fixup_surrogates(handle, &mut utf16_buf, amount, &mut self.surrogate)?;
            // Safety `read_u16s_fixup_surrogates` returns the number of items
            // initialized.
            let utf16s = unsafe { utf16_buf[..read].assume_init_ref() };
            match utf16_to_utf8(utf16s, buf) {
                Ok(value) => return Ok(bytes_copied + value),
                Err(e) => return Err(e),
            }
        }
```

**💡 建议：**
Initialize memory before reading or avoid assume_init on uninit

#### 漏洞 #3：Uninitialized memory read detected

**详情：**
- **Type:** `uninitialized-read`
- **Severity:** `High`
- **Confidence:** `90.0%`
- **Location:** `d:\漏洞挖掘\detector\project\library\test\src\term\win.rs:119`
- **检测方法：** `StaticAnalysis`

**解释：**
assume_init used on uninitialized value within unsafe block

**代码：**
```rust
        unsafe {
            let mut buffer_info = MaybeUninit::<CONSOLE_SCREEN_BUFFER_INFO>::uninit();
            let handle = GetStdHandle(STD_OUTPUT_HANDLE);
            if GetConsoleScreenBufferInfo(handle, buffer_info.as_mut_ptr()) != 0 {
                let buffer_info = buffer_info.assume_init();
                fg = bits_to_color(buffer_info.wAttributes);
                bg = bits_to_color(buffer_info.wAttributes >> 4);
            } else {
                fg = color::WHITE;
                bg = color::BLACK;
            }
        }
```

**💡 建议：**
Initialize memory before reading or avoid assume_init on uninit

---

*由 VulnFusion 生成 - 高级漏洞检测工具*
*融合 Rudra 与 SafeDrop 技术*

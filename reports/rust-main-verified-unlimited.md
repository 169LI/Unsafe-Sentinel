# VulnFusion 安全分析报告

融合 Rudra 与 SafeDrop 的高级漏洞检测

## 分析摘要

- **分析文件总数：** 6331
- **代码行数：** 2471096
- **发现漏洞数：** 20
- **分析时长：** 6029
- **unsafe 块数：** 40052

### 按严重程度统计

| 严重程度 | 数量 |
|----------|-------|
| Critical | 17 |
| High | 3 |

### 按类型统计

| 类型 | 数量 |
|------|-------|
| drop-panic | 17 |
| uninitialized-read | 3 |

## 漏洞详情

### Critical（共 17 条）

#### 漏洞 #1：Potential panic in Drop implementation detected

**详情：**
- **Type:** `drop-panic`
- **Severity:** `Critical`
- **Confidence:** `90.0%`
- **Location:** `d:\漏洞挖掘\detector\project\rust-main\compiler\rustc_data_structures\src\profiling.rs:0`
- **检测方法：** `StaticAnalysis`

**解释：**
Drop implementation may panic, which can cause undefined behavior

**代码：**
```rust
//! # Rust Compiler Self-Profiling
//!
//! This module implements the basic framework for the compiler's self-
//! profiling support. It provides the `SelfProfiler` type which enables
//! recording "events". An event is something that starts and ends at a given
//! point in time and has an ID and a kind attached to it. This allows for
//! tracing the compiler's activity.
//!
//! Internally this module uses the custom tailored [measureme][mm] crate for
//! efficiently recording events to disk in a compact format that can be
//! post-processed and analyzed by the suite of tools in the `measureme`
//! project. The highest priority for the tracing framework is on incurring as
//! little overhead as possible.
//!
//!
//! ## Event Overview
//!
//! Events have a few properties:
//!
//! - The `event_kind` designates the broad category of an event (e.g. does it
//!   correspond to the execution of a query provider or to loading something
//!   from the incr. comp. on-disk cache, etc).
//! - The `event_id` designates the query invocation or function call it
//!   corresponds to, possibly including the query key or function arguments.
//! - Each event stores the ID of the thread it was recorded on.
//! - The timestamp stores beginning and end of the event, or the single point
//!   in time it occurred at for "instant" events.
//!
//!
//! ## Event Filtering
//!
//! Event generation can be filtered by event kind. Recording all possible
//! events generates a lot of data, much of which is not needed for most kinds
//! of analysis. So, in order to keep overhead as low as possible for a given
//! use case, the `SelfProfiler` will only record the kinds of events that
//! pass the filter specified as a command line argument to the compiler.
//!
//!
//! ## `event_id` Assignment
//!
//! As far as `measureme` is concerned, `event_id`s are just strings. However,
//! it would incur too much overhead to generate and persist each `event_id`
//! string at the point where the event is recorded. In order to make this more
//! efficient `measureme` has two features:
//!
//! - Strings can share their content, so that re-occurring parts don't have to
//!   be copied over and over again. One allocates a string in `measureme` and
//!   gets back a `StringId`. This `StringId` is then used to refer to that
//!   string. `measureme` strings are actually DAGs of string components so that
//!   arbitrary sharing of substrings can be done efficiently. This is useful
//!   because `event_id`s contain lots of redundant text like query names or
//!   def-path components.
//!
//! - `StringId`s can be "virtual" which means that the client picks a numeric
//!   ID according to some application-specific scheme and can later make that
//!   ID be mapped to an actual string. This is used to cheaply generate
//!   `event_id`s while the events actually occur, causing little timing
//!   distortion, and then later map those `StringId`s, in bulk, to actual
//!   `event_id` strings. This way the largest part of the tracing overhead is
//!   localized to one contiguous chunk of time.
//!
//! How are these `event_id`s generated in the compiler? For things that occur
//! infrequently (e.g. "generic activities"), we just allocate the string the
//! first time it is used and then keep the `StringId` in a hash table. This
//! is implemented in `SelfProfiler::get_or_alloc_cached_string()`.
//!
//! For queries it gets more interesting: First we need a unique numeric ID for
//! each query invocation (the `QueryInvocationId`). This ID is used as the
//! virtual `StringId` we use as `event_id` for a given event. This ID has to
//! be available both when the query is executed and later, together with the
//! query key, when we allocate the actual `event_id` strings in bulk.
//!
//! We could make the compiler generate and keep track of such an ID for each
//! query invocation but luckily we already have something that fits all the
//! the requirements: the query's `DepNodeIndex`. So we use the numeric value
//! of the `DepNodeIndex` as `event_id` when recording the event and then,
//! just before the query context is dropped, we walk the entire query cache
//! (which stores the `DepNodeIndex` along with the query key for each
//! invocation) and allocate the corresponding strings together with a mapping
//! for `DepNodeIndex as StringId`.
//!
//! [mm]: https://github.com/rust-lang/measureme/

use std::borrow::Borrow;
use std::collections::hash_map::Entry;
use std::error::Error;
use std::fmt::Display;
use std::intrinsics::unlikely;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};
use std::{fs, process};

pub use measureme::EventId;
use measureme::{EventIdBuilder, Profiler, SerializableString, StringId};
use parking_lot::RwLock;
use smallvec::SmallVec;
use tracing::warn;

use crate::fx::FxHashMap;
use crate::outline;
use crate::sync::AtomicU64;

bitflags::bitflags! {
    #[derive(Clone, Copy)]
    struct EventFilter: u16 {
        const GENERIC_ACTIVITIES  = 1 << 0;
        const QUERY_PROVIDERS     = 1 << 1;
        /// Store detailed instant events, including timestamp and thread ID,
        /// per each query cache hit. Note that this is quite expensive.
        const QUERY_CACHE_HITS    = 1 << 2;
        const QUERY_BLOCKED       = 1 << 3;
        const INCR_CACHE_LOADS    = 1 << 4;

        const QUERY_KEYS          = 1 << 5;
        const FUNCTION_ARGS       = 1 << 6;
        const LLVM                = 1 << 7;
        const INCR_RESULT_HASHING = 1 << 8;
        const ARTIFACT_SIZES      = 1 << 9;
        /// Store aggregated counts of cache hits per query invocation.
        const QUERY_CACHE_HIT_COUNTS  = 1 << 10;

        const DEFAULT = Self::GENERIC_ACTIVITIES.bits() |
                        Self::QUERY_PROVIDERS.bits() |
                        Self::QUERY_BLOCKED.bits() |
                        Self::INCR_CACHE_LOADS.bits() |
                        Self::INCR_RESULT_HASHING.bits() |
                        Self::ARTIFACT_SIZES.bits() |
                        Self::QUERY_CACHE_HIT_COUNTS.bits();

        const ARGS = Self::QUERY_KEYS.bits() | Self::FUNCTION_ARGS.bits();
        const QUERY_CACHE_HIT_COMBINED = Self::QUERY_CACHE_HITS.bits() | Self::QUERY_CACHE_HIT_COUNTS.bits();
    }
}

// keep this in sync with the `-Z self-profile-events` help message in rustc_session/options.rs
const EVENT_FILTERS_BY_NAME: &[(&str, EventFilter)] = &[
    ("none", EventFilter::empty()),
    ("all", EventFilter::all()),
    ("default", EventFilter::DEFAULT),
    ("generic-activity", EventFilter::GENERIC_ACTIVITIES),
    ("query-provider", EventFilter::QUERY_PROVIDERS),
    ("query-cache-hit", EventFilter::QUERY_CACHE_HITS),
    ("query-cache-hit-count", EventFilter::QUERY_CACHE_HIT_COUNTS),
    ("query-blocked", EventFilter::QUERY_BLOCKED),
    ("incr-cache-load", EventFilter::INCR_CACHE_LOADS),
    ("query-keys", EventFilter::QUERY_KEYS),
    ("function-args", EventFilter::FUNCTION_ARGS),
    ("args", EventFilter::ARGS),
    ("llvm", EventFilter::LLVM),
    ("incr-result-hashing", EventFilter::INCR_RESULT_HASHING),
    ("artifact-sizes", EventFilter::ARTIFACT_SIZES),
];

/// Something that uniquely identifies a query invocation.
pub struct QueryInvocationId(pub u32);

/// Which format to use for `-Z time-passes`
#[derive(Clone, Copy, PartialEq, Hash, Debug)]
pub enum TimePassesFormat {
    /// Emit human readable text
    Text,
    /// Emit structured JSON
    Json,
}

/// A reference to the SelfProfiler. It can be cloned and sent across thread
/// boundaries at will.
#[derive(Clone)]
pub struct SelfProfilerRef {
    // This field is `None` if self-profiling is disabled for the current
    // compilation session.
    profiler: Option<Arc<SelfProfiler>>,

    // We store the filter mask directly in the reference because that doesn't
    // cost anything and allows for filtering with checking if the profiler is
    // actually enabled.
    event_filter_mask: EventFilter,

    // Print verbose generic activities to stderr.
    print_verbose_generic_activities: Option<TimePassesFormat>,
}

impl SelfProfilerRef {
    pub fn new(
        profiler: Option<Arc<SelfProfiler>>,
        print_verbose_generic_activities: Option<TimePassesFormat>,
    ) -> SelfProfilerRef {
        // If there is no SelfProfiler then the filter mask is set to NONE,
        // ensuring that nothing ever tries to actually access it.
        let event_filter_mask =
            profiler.as_ref().map_or(EventFilter::empty(), |p| p.event_filter_mask);

        SelfProfilerRef { profiler, event_filter_mask, print_verbose_generic_activities }
    }

    /// This shim makes sure that calls only get executed if the filter mask
    /// lets them pass. It also contains some trickery to make sure that
    /// code is optimized for non-profiling compilation sessions, i.e. anything
    /// past the filter check is never inlined so it doesn't clutter the fast
    /// path.
    #[inline(always)]
    fn exec<F>(&self, event_filter: EventFilter, f: F) -> TimingGuard<'_>
    where
        F: for<'a> FnOnce(&'a SelfProfiler) -> TimingGuard<'a>,
    {
        #[inline(never)]
        #[cold]
        fn cold_call<F>(profiler_ref: &SelfProfilerRef, f: F) -> TimingGuard<'_>
        where
            F: for<'a> FnOnce(&'a SelfProfiler) -> TimingGuard<'a>,
        {
            let profiler = profiler_ref.profiler.as_ref().unwrap();
            f(profiler)
        }

        if self.event_filter_mask.contains(event_filter) {
            cold_call(self, f)
        } else {
            TimingGuard::none()
        }
    }

    /// Start profiling a verbose generic activity. Profiling continues until the
    /// VerboseTimingGuard returned from this call is dropped. In addition to recording
    /// a measureme event, "verbose" generic activities also print a timing entry to
    /// stderr if the compiler is invoked with -Ztime-passes.
    pub fn verbose_generic_activity(&self, event_label: &'static str) -> VerboseTimingGuard<'_> {
        let message_and_format =
            self.print_verbose_generic_activities.map(|format| (event_label.to_owned(), format));

        VerboseTimingGuard::start(message_and_format, self.generic_activity(event_label))
    }

    /// Like `verbose_generic_activity`, but with an extra arg.
    pub fn verbose_generic_activity_with_arg<A>(
        &self,
        event_label: &'static str,
        event_arg: A,
    ) -> VerboseTimingGuard<'_>
    where
        A: Borrow<str> + Into<String>,
    {
        let message_and_format = self
            .print_verbose_generic_activities
            .map(|format| (format!("{}({})", event_label, event_arg.borrow()), format));

        VerboseTimingGuard::start(
            message_and_format,
            self.generic_activity_with_arg(event_label, event_arg),
        )
    }

    /// Start profiling a generic activity. Profiling continues until the
    /// TimingGuard returned from this call is dropped.
    #[inline(always)]
    pub fn generic_activity(&self, event_label: &'static str) -> TimingGuard<'_> {
        self.exec(EventFilter::GENERIC_ACTIVITIES, |profiler| {
            let event_label = profiler.get_or_alloc_cached_string(event_label);
            let event_id = EventId::from_label(event_label);
            TimingGuard::start(profiler, profiler.generic_activity_event_kind, event_id)
        })
    }

    /// Start profiling with some event filter for a given event. Profiling continues until the
    /// TimingGuard returned from this call is dropped.
    #[inline(always)]
    pub fn generic_activity_with_event_id(&self, event_id: EventId) -> TimingGuard<'_> {
        self.exec(EventFilter::GENERIC_ACTIVITIES, |profiler| {
            TimingGuard::start(profiler, profiler.generic_activity_event_kind, event_id)
        })
    }

    /// Start profiling a generic activity. Profiling continues until the
    /// TimingGuard returned from this call is dropped.
    #[inline(always)]
    pub fn generic_activity_with_arg<A>(
        &self,
        event_label: &'static str,
        event_arg: A,
    ) -> TimingGuard<'_>
    where
        A: Borrow<str> + Into<String>,
    {
        self.exec(EventFilter::GENERIC_ACTIVITIES, |profiler| {
            let builder = EventIdBuilder::new(&profiler.profiler);
            let event_label = profiler.get_or_alloc_cached_string(event_label);
            let event_id = if profiler.event_filter_mask.contains(EventFilter::FUNCTION_ARGS) {
                let event_arg = profiler.get_or_alloc_cached_string(event_arg);
                builder.from_label_and_arg(event_label, event_arg)
            } else {
                builder.from_label(event_label)
            };
            TimingGuard::start(profiler, profiler.generic_activity_event_kind, event_id)
        })
    }

    /// Start profiling a generic activity, allowing costly arguments to be recorded. Profiling
    /// continues until the `TimingGuard` returned from this call is dropped.
    ///
    /// If the arguments to a generic activity are cheap to create, use `generic_activity_with_arg`
    /// or `generic_activity_with_args` for their simpler API. However, if they are costly or
    /// require allocation in sufficiently hot contexts, then this allows for a closure to be called
    /// only when arguments were asked to be recorded via `-Z self-profile-events=args`.
    ///
    /// In this case, the closure will be passed a `&mut EventArgRecorder`, to help with recording
    /// one or many arguments within the generic activity being profiled, by calling its
    /// `record_arg` method for example.
    ///
    /// This `EventArgRecorder` may implement more specific traits from other rustc crates, e.g. for
    /// richer handling of rustc-specific argument types, while keeping this single entry-point API
    /// for recording arguments.
    ///
    /// Note: recording at least one argument is *required* for the self-profiler to create the
    /// `TimingGuard`. A panic will be triggered if that doesn't happen. This function exists
    /// explicitly to record arguments, so it fails loudly when there are none to record.
    ///
    #[inline(always)]
    pub fn generic_activity_with_arg_recorder<F>(
        &self,
        event_label: &'static str,
        mut f: F,
    ) -> TimingGuard<'_>
    where
        F: FnMut(&mut EventArgRecorder<'_>),
    {
        // Ensure this event will only be recorded when self-profiling is turned on.
        self.exec(EventFilter::GENERIC_ACTIVITIES, |profiler| {
            let builder = EventIdBuilder::new(&profiler.profiler);
            let event_label = profiler.get_or_alloc_cached_string(event_label);

            // Ensure the closure to create event arguments will only be called when argument
            // recording is turned on.
            let event_id = if profiler.event_filter_mask.contains(EventFilter::FUNCTION_ARGS) {
                // Set up the builder and call the user-provided closure to record potentially
                // costly event arguments.
                let mut recorder = EventArgRecorder { profiler, args: SmallVec::new() };
                f(&mut recorder);

                // It is expected that the closure will record at least one argument. If that
                // doesn't happen, it's a bug: we've been explicitly called in order to record
                // arguments, so we fail loudly when there are none to record.
                if recorder.args.is_empty() {
                    panic!(
                        "The closure passed to `generic_activity_with_arg_recorder` needs to \
                         record at least one argument"
                    );
                }

                builder.from_label_and_args(event_label, &recorder.args)
            } else {
                builder.from_label(event_label)
            };
            TimingGuard::start(profiler, profiler.generic_activity_event_kind, event_id)
        })
    }

    /// Record the size of an artifact that the compiler produces
    ///
    /// `artifact_kind` is the class of artifact (e.g., query_cache, object_file, etc.)
    /// `artifact_name` is an identifier to the specific artifact being stored (usually a filename)
    #[inline(always)]
    pub fn artifact_size<A>(&self, artifact_kind: &str, artifact_name: A, size: u64)
    where
        A: Borrow<str> + Into<String>,
    {
        drop(self.exec(EventFilter::ARTIFACT_SIZES, |profiler| {
            let builder = EventIdBuilder::new(&profiler.profiler);
            let event_label = profiler.get_or_alloc_cached_string(artifact_kind);
            let event_arg = profiler.get_or_alloc_cached_string(artifact_name);
            let event_id = builder.from_label_and_arg(event_label, event_arg);
            let thread_id = get_thread_id();

            profiler.profiler.record_integer_event(
                profiler.artifact_size_event_kind,
                event_id,
                thread_id,
                size,
            );

            TimingGuard::none()
        }))
    }

    #[inline(always)]
    pub fn generic_activity_with_args(
        &self,
        event_label: &'static str,
        event_args: &[String],
    ) -> TimingGuard<'_> {
        self.exec(EventFilter::GENERIC_ACTIVITIES, |profiler| {
            let builder = EventIdBuilder::new(&profiler.profiler);
            let event_label = profiler.get_or_alloc_cached_string(event_label);
            let event_id = if profiler.event_filter_mask.contains(EventFilter::FUNCTION_ARGS) {
                let event_args: Vec<_> = event_args
                    .iter()
                    .map(|s| profiler.get_or_alloc_cached_string(&s[..]))
                    .collect();
                builder.from_label_and_args(event_label, &event_args)
            } else {
                builder.from_label(event_label)
            };
            TimingGuard::start(profiler, profiler.generic_activity_event_kind, event_id)
        })
    }

    /// Start profiling a query provider. Profiling continues until the
    /// TimingGuard returned from this call is dropped.
    #[inline(always)]
    pub fn query_provider(&self) -> TimingGuard<'_> {
        self.exec(EventFilter::QUERY_PROVIDERS, |profiler| {
            TimingGuard::start(profiler, profiler.query_event_kind, EventId::INVALID)
        })
    }

    /// Record a query in-memory cache hit.
    #[inline(always)]
    pub fn query_cache_hit(&self, query_invocation_id: QueryInvocationId) {
        #[inline(never)]
        #[cold]
        fn cold_call(profiler_ref: &SelfProfilerRef, query_invocation_id: QueryInvocationId) {
            if profiler_ref.event_filter_mask.contains(EventFilter::QUERY_CACHE_HIT_COUNTS) {
                profiler_ref
                    .profiler
                    .as_ref()
                    .unwrap()
                    .increment_query_cache_hit_counters(QueryInvocationId(query_invocation_id.0));
            }
            if unlikely(profiler_ref.event_filter_mask.contains(EventFilter::QUERY_CACHE_HITS)) {
                profiler_ref.instant_query_event(
                    |profiler| profiler.query_cache_hit_event_kind,
                    query_invocation_id,
                );
            }
        }

        // We check both kinds of query cache hit events at once, to reduce overhead in the
        // common case (with self-profile disabled).
        if unlikely(self.event_filter_mask.intersects(EventFilter::QUERY_CACHE_HIT_COMBINED)) {
            cold_call(self, query_invocation_id);
        }
    }

    /// Start profiling a query being blocked on a concurrent execution.
    /// Profiling continues until the TimingGuard returned from this call is
    /// dropped.
    #[inline(always)]
    pub fn query_blocked(&self) -> TimingGuard<'_> {
        self.exec(EventFilter::QUERY_BLOCKED, |profiler| {
            TimingGuard::start(profiler, profiler.query_blocked_event_kind, EventId::INVALID)
        })
    }

    /// Start profiling how long it takes to load a query result from the
    /// incremental compilation on-disk cache. Profiling continues until the
    /// TimingGuard returned from this call is dropped.
    #[inline(always)]
    pub fn incr_cache_loading(&self) -> TimingGuard<'_> {
        self.exec(EventFilter::INCR_CACHE_LOADS, |profiler| {
            TimingGuard::start(
                profiler,
                profiler.incremental_load_result_event_kind,
                EventId::INVALID,
            )
        })
    }

    /// Start profiling how long it takes to hash query results for incremental compilation.
    /// Profiling continues until the TimingGuard returned from this call is dropped.
    #[inline(always)]
    pub fn incr_result_hashing(&self) -> TimingGuard<'_> {
        self.exec(EventFilter::INCR_RESULT_HASHING, |profiler| {
            TimingGuard::start(
                profiler,
                profiler.incremental_result_hashing_event_kind,
                EventId::INVALID,
            )
        })
    }

    #[inline(always)]
    fn instant_query_event(
        &self,
        event_kind: fn(&SelfProfiler) -> StringId,
        query_invocation_id: QueryInvocationId,
    ) {
        let event_id = StringId::new_virtual(query_invocation_id.0);
        let thread_id = get_thread_id();
        let profiler = self.profiler.as_ref().unwrap();
        profiler.profiler.record_instant_event(
            event_kind(profiler),
            EventId::from_virtual(event_id),
            thread_id,
        );
    }

    pub fn with_profiler(&self, f: impl FnOnce(&SelfProfiler)) {
        if let Some(profiler) = &self.profiler {
            f(profiler)
        }
    }

    /// Gets a `StringId` for the given string. This method makes sure that
    /// any strings going through it will only be allocated once in the
    /// profiling data.
    /// Returns `None` if the self-profiling is not enabled.
    pub fn get_or_alloc_cached_string(&self, s: &str) -> Option<StringId> {
        self.profiler.as_ref().map(|p| p.get_or_alloc_cached_string(s))
    }

    /// Store query cache hits to the self-profile log.
    /// Should be called once at the end of the compilation session.
    ///
    /// The cache hits are stored per **query invocation**, not **per query kind/type**.
    /// `analyzeme` can later deduplicate individual query labels from the QueryInvocationId event
    /// IDs.
    pub fn store_query_cache_hits(&self) {
        if self.event_filter_mask.contains(EventFilter::QUERY_CACHE_HIT_COUNTS) {
            let profiler = self.profiler.as_ref().unwrap();
            let query_hits = profiler.query_hits.read();
            let builder = EventIdBuilder::new(&profiler.profiler);
            let thread_id = get_thread_id();
            for (query_invocation, hit_count) in query_hits.iter().enumerate() {
                let hit_count = hit_count.load(Ordering::Relaxed);
                // No need to record empty cache hit counts
                if hit_count > 0 {
                    let event_id =
                        builder.from_label(StringId::new_virtual(query_invocation as u64));
                    profiler.profiler.record_integer_event(
                        profiler.query_cache_hit_count_event_kind,
                        event_id,
                        thread_id,
                        hit_count,
                    );
                }
            }
        }
    }

    #[inline]
    pub fn enabled(&self) -> bool {
        self.profiler.is_some()
    }

    #[inline]
    pub fn llvm_recording_enabled(&self) -> bool {
        self.event_filter_mask.contains(EventFilter::LLVM)
    }
    #[inline]
    pub fn get_self_profiler(&self) -> Option<Arc<SelfProfiler>> {
        self.profiler.clone()
    }

    /// Is expensive recording of query keys and/or function arguments enabled?
    pub fn is_args_recording_enabled(&self) -> bool {
        self.enabled() && self.event_filter_mask.intersects(EventFilter::ARGS)
    }
}

/// A helper for recording costly arguments to self-profiling events. Used with
/// `SelfProfilerRef::generic_activity_with_arg_recorder`.
pub struct EventArgRecorder<'p> {
    /// The `SelfProfiler` used to intern the event arguments that users will ask to record.
    profiler: &'p SelfProfiler,

    /// The interned event arguments to be recorded in the generic activity event.
    ///
    /// The most common case, when actually recording event arguments, is to have one argument. Then
    /// followed by recording two, in a couple places.
    args: SmallVec<[StringId; 2]>,
}

impl EventArgRecorder<'_> {
    /// Records a single argument within the current generic activity being profiled.
    ///
    /// Note: when self-profiling with costly event arguments, at least one argument
    /// needs to be recorded. A panic will be triggered if that doesn't happen.
    pub fn record_arg<A>(&mut self, event_arg: A)
    where
        A: Borrow<str> + Into<String>,
    {
        let event_arg = self.profiler.get_or_alloc_cached_string(event_arg);
        self.args.push(event_arg);
    }
}

pub struct SelfProfiler {
    profiler: Profiler,
    event_filter_mask: EventFilter,

    string_cache: RwLock<FxHashMap<String, StringId>>,

    /// Recording individual query cache hits as "instant" measureme events
    /// is incredibly expensive. Instead of doing that, we simply aggregate
    /// cache hit *counts* per query invocation, and then store the final count
    /// of cache hits per invocation at the end of the compilation session.
    ///
    /// With this approach, we don't know the individual thread IDs and timestamps
    /// of cache hits, but it has very little overhead on top of `-Zself-profile`.
    /// Recording the cache hits as individual events made compilation 3-5x slower.
    ///
    /// Query invocation IDs should be monotonic integers, so we can store them in a vec,
    /// rather than using a hashmap.
    query_hits: RwLock<Vec<AtomicU64>>,

    query_event_kind: StringId,
    generic_activity_event_kind: StringId,
    incremental_load_result_event_kind: StringId,
    incremental_result_hashing_event_kind: StringId,
    query_blocked_event_kind: StringId,
    query_cache_hit_event_kind: StringId,
    artifact_size_event_kind: StringId,
    /// Total cache hits per query invocation
    query_cache_hit_count_event_kind: StringId,
}

impl SelfProfiler {
    pub fn new(
        output_directory: &Path,
        crate_name: Option<&str>,
        event_filters: Option<&[String]>,
        counter_name: &str,
    ) -> Result<SelfProfiler, Box<dyn Error + Send + Sync>> {
        fs::create_dir_all(output_directory)?;

        let crate_name = crate_name.unwrap_or("unknown-crate");
        // HACK(eddyb) we need to pad the PID, strange as it may seem, as its
        // length can behave as a source of entropy for heap addresses, when
        // ASLR is disabled and the heap is otherwise deterministic.
        let pid: u32 = process::id();
        let filename = format!("{crate_name}-{pid:07}.rustc_profile");
        let path = output_directory.join(filename);
        let profiler =
            Profiler::with_counter(&path, measureme::counters::Counter::by_name(counter_name)?)?;

        let query_event_kind = profiler.alloc_string("Query");
        let generic_activity_event_kind = profiler.alloc_string("GenericActivity");
        let incremental_load_result_event_kind = profiler.alloc_string("IncrementalLoadResult");
        let incremental_result_hashing_event_kind =
            profiler.alloc_string("IncrementalResultHashing");
        let query_blocked_event_kind = profiler.alloc_string("QueryBlocked");
        let query_cache_hit_event_kind = profiler.alloc_string("QueryCacheHit");
        let artifact_size_event_kind = profiler.alloc_string("ArtifactSize");
        let query_cache_hit_count_event_kind = profiler.alloc_string("QueryCacheHitCount");

        let mut event_filter_mask = EventFilter::empty();

        if let Some(event_filters) = event_filters {
            let mut unknown_events = vec![];
            for item in event_filters {
                if let Some(&(_, mask)) =
                    EVENT_FILTERS_BY_NAME.iter().find(|&(name, _)| name == item)
                {
                    event_filter_mask |= mask;
                } else {
                    unknown_events.push(item.clone());
                }
            }

            // Warn about any unknown event names
            if !unknown_events.is_empty() {
                unknown_events.sort();
                unknown_events.dedup();

                warn!(
                    "Unknown self-profiler events specified: {}. Available options are: {}.",
                    unknown_events.join(", "),
                    EVENT_FILTERS_BY_NAME
                        .iter()
                        .map(|&(name, _)| name.to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                );
            }
        } else {
            event_filter_mask = EventFilter::DEFAULT;
        }

        Ok(SelfProfiler {
            profiler,
            event_filter_mask,
            string_cache: RwLock::new(FxHashMap::default()),
            query_event_kind,
            generic_activity_event_kind,
            incremental_load_result_event_kind,
            incremental_result_hashing_event_kind,
            query_blocked_event_kind,
            query_cache_hit_event_kind,
            artifact_size_event_kind,
            query_cache_hit_count_event_kind,
            query_hits: Default::default(),
        })
    }

    /// Allocates a new string in the profiling data. Does not do any caching
    /// or deduplication.
    pub fn alloc_string<STR: SerializableString + ?Sized>(&self, s: &STR) -> StringId {
        self.profiler.alloc_string(s)
    }

    /// Store a cache hit of a query invocation
    pub fn increment_query_cache_hit_counters(&self, id: QueryInvocationId) {
        // Fast path: assume that the query was already encountered before, and just record
        // a cache hit.
        let mut guard = self.query_hits.upgradable_read();
        let query_hits = &guard;
        let index = id.0 as usize;
        if index < query_hits.len() {
            // We only want to increment the count, no other synchronization is required
            query_hits[index].fetch_add(1, Ordering::Relaxed);
        } else {
            // If not, we need to extend the query hit map to the highest observed ID
            guard.with_upgraded(|vec| {
                vec.resize_with(index + 1, || AtomicU64::new(0));
                vec[index] = AtomicU64::from(1);
            });
        }
    }

    /// Gets a `StringId` for the given string. This method makes sure that
    /// any strings going through it will only be allocated once in the
    /// profiling data.
    pub fn get_or_alloc_cached_string<A>(&self, s: A) -> StringId
    where
        A: Borrow<str> + Into<String>,
    {
        // Only acquire a read-lock first since we assume that the string is
        // already present in the common case.
        {
            let string_cache = self.string_cache.read();

            if let Some(&id) = string_cache.get(s.borrow()) {
                return id;
            }
        }

        let mut string_cache = self.string_cache.write();
        // Check if the string has already been added in the small time window
        // between dropping the read lock and acquiring the write lock.
        match string_cache.entry(s.into()) {
            Entry::Occupied(e) => *e.get(),
            Entry::Vacant(e) => {
                let string_id = self.profiler.alloc_string(&e.key()[..]);
                *e.insert(string_id)
            }
        }
    }

    pub fn map_query_invocation_id_to_string(&self, from: QueryInvocationId, to: StringId) {
        let from = StringId::new_virtual(from.0);
        self.profiler.map_virtual_to_concrete_string(from, to);
    }

    pub fn bulk_map_query_invocation_id_to_single_string<I>(&self, from: I, to: StringId)
    where
        I: Iterator<Item = QueryInvocationId> + ExactSizeIterator,
    {
        let from = from.map(|qid| StringId::new_virtual(qid.0));
        self.profiler.bulk_map_virtual_to_single_concrete_string(from, to);
    }

    pub fn query_key_recording_enabled(&self) -> bool {
        self.event_filter_mask.contains(EventFilter::QUERY_KEYS)
    }

    pub fn event_id_builder(&self) -> EventIdBuilder<'_> {
        EventIdBuilder::new(&self.profiler)
    }
}

#[must_use]
pub struct TimingGuard<'a>(Option<measureme::TimingGuard<'a>>);

impl<'a> TimingGuard<'a> {
    #[inline]
    pub fn start(
        profiler: &'a SelfProfiler,
        event_kind: StringId,
        event_id: EventId,
    ) -> TimingGuard<'a> {
        let thread_id = get_thread_id();
        let raw_profiler = &profiler.profiler;
        let timing_guard =
            raw_profiler.start_recording_interval_event(event_kind, event_id, thread_id);
        TimingGuard(Some(timing_guard))
    }

    #[inline]
    pub fn finish_with_query_invocation_id(self, query_invocation_id: QueryInvocationId) {
        if let Some(guard) = self.0 {
            outline(|| {
                let event_id = StringId::new_virtual(query_invocation_id.0);
                let event_id = EventId::from_virtual(event_id);
                guard.finish_with_override_event_id(event_id);
            });
        }
    }

    #[inline]
    pub fn none() -> TimingGuard<'a> {
        TimingGuard(None)
    }

    #[inline(always)]
    pub fn run<R>(self, f: impl FnOnce() -> R) -> R {
        let _timer = self;
        f()
    }
}

struct VerboseInfo {
    start_time: Instant,
    start_rss: Option<usize>,
    message: String,
    format: TimePassesFormat,
}

#[must_use]
pub struct VerboseTimingGuard<'a> {
    info: Option<VerboseInfo>,
    _guard: TimingGuard<'a>,
}

impl<'a> VerboseTimingGuard<'a> {
    pub fn start(
        message_and_format: Option<(String, TimePassesFormat)>,
        _guard: TimingGuard<'a>,
    ) -> Self {
        VerboseTimingGuard {
            _guard,
            info: message_and_format.map(|(message, format)| VerboseInfo {
                start_time: Instant::now(),
                start_rss: get_resident_set_size(),
                message,
                format,
            }),
        }
    }

    #[inline(always)]
    pub fn run<R>(self, f: impl FnOnce() -> R) -> R {
        let _timer = self;
        f()
    }
}

impl Drop for VerboseTimingGuard<'_> {
    fn drop(&mut self) {
        if let Some(info) = &self.info {
            let end_rss = get_resident_set_size();
            let dur = info.start_time.elapsed();
            print_time_passes_entry(&info.message, dur, info.start_rss, end_rss, info.format);
        }
    }
}

struct JsonTimePassesEntry<'a> {
    pass: &'a str,
    time: f64,
    start_rss: Option<usize>,
    end_rss: Option<usize>,
}

impl Display for JsonTimePassesEntry<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self { pass: what, time, start_rss, end_rss } = self;
        write!(f, r#"{{"pass":"{what}","time":{time},"rss_start":"#).unwrap();
        match start_rss {
            Some(rss) => write!(f, "{rss}")?,
            None => write!(f, "null")?,
        }
        write!(f, r#","rss_end":"#)?;
        match end_rss {
            Some(rss) => write!(f, "{rss}")?,
            None => write!(f, "null")?,
        }
        write!(f, "}}")?;
        Ok(())
    }
}

pub fn print_time_passes_entry(
    what: &str,
    dur: Duration,
    start_rss: Option<usize>,
    end_rss: Option<usize>,
    format: TimePassesFormat,
) {
    match format {
        TimePassesFormat::Json => {
            let entry =
                JsonTimePassesEntry { pass: what, time: dur.as_secs_f64(), start_rss, end_rss };

            eprintln!(r#"time: {entry}"#);
            return;
        }
        TimePassesFormat::Text => (),
    }

    // Print the pass if its duration is greater than 5 ms, or it changed the
    // measured RSS.
    let is_notable = || {
        if dur.as_millis() > 5 {
            return true;
        }

        if let (Some(start_rss), Some(end_rss)) = (start_rss, end_rss) {
            let change_rss = end_rss.abs_diff(start_rss);
            if change_rss > 0 {
                return true;
            }
        }

        false
    };
    if !is_notable() {
        return;
    }

    let rss_to_mb = |rss| (rss as f64 / 1_000_000.0).round() as usize;
    let rss_change_to_mb = |rss| (rss as f64 / 1_000_000.0).round() as i128;

    let mem_string = match (start_rss, end_rss) {
        (Some(start_rss), Some(end_rss)) => {
            let change_rss = end_rss as i128 - start_rss as i128;

            format!(
                "; rss: {:>4}MB -> {:>4}MB ({:>+5}MB)",
                rss_to_mb(start_rss),
                rss_to_mb(end_rss),
                rss_change_to_mb(change_rss),
            )
        }
        (Some(start_rss), None) => format!("; rss start: {:>4}MB", rss_to_mb(start_rss)),
        (None, Some(end_rss)) => format!("; rss end: {:>4}MB", rss_to_mb(end_rss)),
        (None, None) => String::new(),
    };

    eprintln!("time: {:>7}{}\t{}", duration_to_secs_str(dur), mem_string, what);
}

// Hack up our own formatting for the duration to make it easier for scripts
// to parse (always use the same number of decimal places and the same unit).
pub fn duration_to_secs_str(dur: std::time::Duration) -> String {
    format!("{:.3}", dur.as_secs_f64())
}

fn get_thread_id() -> u32 {
    std::thread::current().id().as_u64().get() as u32
}

// Memory reporting
cfg_select! {
    windows => {
        pub fn get_resident_set_size() -> Option<usize> {
            use windows::{
                Win32::System::ProcessStatus::{K32GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS},
                Win32::System::Threading::GetCurrentProcess,
            };

            let mut pmc = PROCESS_MEMORY_COUNTERS::default();
            let pmc_size = size_of_val(&pmc);
            unsafe {
                K32GetProcessMemoryInfo(
                    GetCurrentProcess(),
                    &mut pmc,
                    pmc_size as u32,
                )
            }
            .ok()
            .ok()?;

            Some(pmc.WorkingSetSize)
        }
    }
    target_os = "macos" => {
        pub fn get_resident_set_size() -> Option<usize> {
            use libc::{c_int, c_void, getpid, proc_pidinfo, proc_taskinfo, PROC_PIDTASKINFO};
            use std::mem;
            const PROC_TASKINFO_SIZE: c_int = size_of::<proc_taskinfo>() as c_int;

            unsafe {
                let mut info: proc_taskinfo = mem::zeroed();
                let info_ptr = &mut info as *mut proc_taskinfo as *mut c_void;
                let pid = getpid() as c_int;
                let ret = proc_pidinfo(pid, PROC_PIDTASKINFO, 0, info_ptr, PROC_TASKINFO_SIZE);
                if ret == PROC_TASKINFO_SIZE {
                    Some(info.pti_resident_size as usize)
                } else {
                    None
                }
            }
        }
    }
    unix => {
        pub fn get_resident_set_size() -> Option<usize> {
            let field = 1;
            let contents = fs::read("/proc/self/statm").ok()?;
            let contents = String::from_utf8(contents).ok()?;
            let s = contents.split_whitespace().nth(field)?;
            let npages = s.parse::<usize>().ok()?;
            Some(npages * 4096)
        }
    }
    _ => {
        pub fn get_resident_set_size() -> Option<usize> {
            None
        }
    }
}

#[cfg(test)]
mod tests;

```

**💡 建议：**
Ensure Drop implementations never panic

#### 漏洞 #2：Potential panic in Drop implementation detected

**详情：**
- **Type:** `drop-panic`
- **Severity:** `Critical`
- **Confidence:** `90.0%`
- **Location:** `d:\漏洞挖掘\detector\project\rust-main\compiler\rustc_errors\src\lock.rs:0`
- **检测方法：** `StaticAnalysis`

**解释：**
Drop implementation may panic, which can cause undefined behavior

**代码：**
```rust
//! Bindings to acquire a global named lock.
//!
//! This is intended to be used to synchronize multiple compiler processes to
//! ensure that we can output complete errors without interleaving on Windows.
//! Note that this is currently only needed for allowing only one 32-bit MSVC
//! linker to execute at once on MSVC hosts, so this is only implemented for
//! `cfg(windows)`. Also note that this may not always be used on Windows,
//! only when targeting 32-bit MSVC.
//!
//! For more information about why this is necessary, see where this is called.

use std::any::Any;

#[cfg(windows)]
pub(crate) fn acquire_global_lock(name: &str) -> Box<dyn Any> {
    use std::ffi::CString;
    use std::io;

    use windows::Win32::Foundation::{CloseHandle, HANDLE, WAIT_ABANDONED, WAIT_OBJECT_0};
    use windows::Win32::System::Threading::{
        CreateMutexA, INFINITE, ReleaseMutex, WaitForSingleObject,
    };
    use windows::core::PCSTR;

    struct Handle(HANDLE);

    impl Drop for Handle {
        fn drop(&mut self) {
            unsafe {
                // FIXME can panic here
                CloseHandle(self.0).unwrap();
            }
        }
    }

    struct Guard(Handle);

    impl Drop for Guard {
        fn drop(&mut self) {
            unsafe {
                // FIXME can panic here
                ReleaseMutex((self.0).0).unwrap();
            }
        }
    }

    let cname = CString::new(name).unwrap();
    // Create a named mutex, with no security attributes and also not
    // acquired when we create it.
    //
    // This will silently create one if it doesn't already exist, or it'll
    // open up a handle to one if it already exists.
    let mutex = unsafe { CreateMutexA(None, false, PCSTR::from_raw(cname.as_ptr().cast())) }
        .unwrap_or_else(|_| panic!("failed to create global mutex named `{}`", name));
    let mutex = Handle(mutex);

    // Acquire the lock through `WaitForSingleObject`.
    //
    // A return value of `WAIT_OBJECT_0` means we successfully acquired it.
    //
    // A return value of `WAIT_ABANDONED` means that the previous holder of
    // the thread exited without calling `ReleaseMutex`. This can happen,
    // for example, when the compiler crashes or is interrupted via ctrl-c
    // or the like. In this case, however, we are still transferred
    // ownership of the lock so we continue.
    //
    // If an error happens.. well... that's surprising!
    match unsafe { WaitForSingleObject(mutex.0, INFINITE) } {
        WAIT_OBJECT_0 | WAIT_ABANDONED => (),
        err => panic!(
            "WaitForSingleObject failed on global mutex named `{}`: {} (ret={:x})",
            name,
            io::Error::last_os_error(),
            err.0
        ),
    }

    // Return a guard which will call `ReleaseMutex` when dropped.
    Box::new(Guard(mutex))
}

#[cfg(not(windows))]
pub(crate) fn acquire_global_lock(_name: &str) -> Box<dyn Any> {
    Box::new(())
}

```

**💡 建议：**
Ensure Drop implementations never panic

#### 漏洞 #3：Potential panic in Drop implementation detected

**详情：**
- **Type:** `drop-panic`
- **Severity:** `Critical`
- **Confidence:** `90.0%`
- **Location:** `d:\漏洞挖掘\detector\project\rust-main\compiler\rustc_lint_defs\src\builtin.rs:0`
- **检测方法：** `StaticAnalysis`

**解释：**
Drop implementation may panic, which can cause undefined behavior

**代码：**
```rust
//! Some lints that are built in to the compiler.
//!
//! These are the built-in lints that are emitted direct in the main
//! compiler code, rather than using their own custom pass. Those
//! lints are all available in `rustc_lint::builtin`.
//!
//! When removing a lint, make sure to also add a call to `register_removed` in
//! compiler/rustc_lint/src/lib.rs.

use rustc_span::edition::Edition;

use crate::{FutureIncompatibilityReason, declare_lint, declare_lint_pass};

declare_lint_pass! {
    /// Does nothing as a lint pass, but registers some `Lint`s
    /// that are used by other parts of the compiler.
    HardwiredLints => [
        // tidy-alphabetical-start
        AARCH64_SOFTFLOAT_NEON,
        ABSOLUTE_PATHS_NOT_STARTING_WITH_CRATE,
        AMBIGUOUS_ASSOCIATED_ITEMS,
        AMBIGUOUS_GLOB_IMPORTS,
        AMBIGUOUS_GLOB_REEXPORTS,
        ARITHMETIC_OVERFLOW,
        ASM_SUB_REGISTER,
        BAD_ASM_STYLE,
        BARE_TRAIT_OBJECTS,
        BINDINGS_WITH_VARIANT_NAME,
        BREAK_WITH_LABEL_AND_LOOP,
        COHERENCE_LEAK_CHECK,
        CONFLICTING_REPR_HINTS,
        CONST_EVALUATABLE_UNCHECKED,
        CONST_ITEM_MUTATION,
        DEAD_CODE,
        DEPENDENCY_ON_UNIT_NEVER_TYPE_FALLBACK,
        DEPRECATED,
        DEPRECATED_IN_FUTURE,
        DEPRECATED_SAFE_2024,
        DEPRECATED_WHERE_CLAUSE_LOCATION,
        DUPLICATE_MACRO_ATTRIBUTES,
        ELIDED_LIFETIMES_IN_ASSOCIATED_CONSTANT,
        ELIDED_LIFETIMES_IN_PATHS,
        EXPLICIT_BUILTIN_CFGS_IN_FLAGS,
        EXPORTED_PRIVATE_DEPENDENCIES,
        FFI_UNWIND_CALLS,
        FORBIDDEN_LINT_GROUPS,
        FUNCTION_ITEM_REFERENCES,
        FUZZY_PROVENANCE_CASTS,
        HIDDEN_GLOB_REEXPORTS,
        ILL_FORMED_ATTRIBUTE_INPUT,
        INCOMPLETE_INCLUDE,
        INEFFECTIVE_UNSTABLE_TRAIT_IMPL,
        INLINE_NO_SANITIZE,
        INVALID_DOC_ATTRIBUTES,
        INVALID_MACRO_EXPORT_ARGUMENTS,
        INVALID_TYPE_PARAM_DEFAULT,
        IRREFUTABLE_LET_PATTERNS,
        LARGE_ASSIGNMENTS,
        LATE_BOUND_LIFETIME_ARGUMENTS,
        LEGACY_DERIVE_HELPERS,
        LINKER_MESSAGES,
        LONG_RUNNING_CONST_EVAL,
        LOSSY_PROVENANCE_CASTS,
        MACRO_EXPANDED_MACRO_EXPORTS_ACCESSED_BY_ABSOLUTE_PATHS,
        MACRO_USE_EXTERN_CRATE,
        MALFORMED_DIAGNOSTIC_ATTRIBUTES,
        MALFORMED_DIAGNOSTIC_FORMAT_LITERALS,
        META_VARIABLE_MISUSE,
        MISPLACED_DIAGNOSTIC_ATTRIBUTES,
        MISSING_ABI,
        MISSING_UNSAFE_ON_EXTERN,
        MUST_NOT_SUSPEND,
        NAMED_ARGUMENTS_USED_POSITIONALLY,
        NEVER_TYPE_FALLBACK_FLOWING_INTO_UNSAFE,
        NON_CONTIGUOUS_RANGE_ENDPOINTS,
        NON_EXHAUSTIVE_OMITTED_PATTERNS,
        OUT_OF_SCOPE_MACRO_CALLS,
        OVERLAPPING_RANGE_ENDPOINTS,
        PATTERNS_IN_FNS_WITHOUT_BODY,
        PRIVATE_BOUNDS,
        PRIVATE_INTERFACES,
        PROC_MACRO_DERIVE_RESOLUTION_FALLBACK,
        PUB_USE_OF_PRIVATE_EXTERN_CRATE,
        REDUNDANT_IMPORTS,
        REDUNDANT_LIFETIMES,
        REFINING_IMPL_TRAIT_INTERNAL,
        REFINING_IMPL_TRAIT_REACHABLE,
        RENAMED_AND_REMOVED_LINTS,
        REPR_C_ENUMS_LARGER_THAN_INT,
        REPR_TRANSPARENT_NON_ZST_FIELDS,
        RTSAN_NONBLOCKING_ASYNC,
        RUST_2021_INCOMPATIBLE_CLOSURE_CAPTURES,
        RUST_2021_INCOMPATIBLE_OR_PATTERNS,
        RUST_2021_PREFIXES_INCOMPATIBLE_SYNTAX,
        RUST_2021_PRELUDE_COLLISIONS,
        RUST_2024_GUARDED_STRING_INCOMPATIBLE_SYNTAX,
        RUST_2024_INCOMPATIBLE_PAT,
        RUST_2024_PRELUDE_COLLISIONS,
        SELF_CONSTRUCTOR_FROM_OUTER_ITEM,
        SEMICOLON_IN_EXPRESSIONS_FROM_MACROS,
        SINGLE_USE_LIFETIMES,
        SOFT_UNSTABLE,
        STABLE_FEATURES,
        SUPERTRAIT_ITEM_SHADOWING_DEFINITION,
        SUPERTRAIT_ITEM_SHADOWING_USAGE,
        TAIL_EXPR_DROP_ORDER,
        TEST_UNSTABLE_LINT,
        TEXT_DIRECTION_CODEPOINT_IN_COMMENT,
        TEXT_DIRECTION_CODEPOINT_IN_LITERAL,
        TRIVIAL_CASTS,
        TRIVIAL_NUMERIC_CASTS,
        TYVAR_BEHIND_RAW_POINTER,
        UNCONDITIONAL_PANIC,
        UNCONDITIONAL_RECURSION,
        UNCOVERED_PARAM_IN_PROJECTION,
        UNEXPECTED_CFGS,
        UNFULFILLED_LINT_EXPECTATIONS,
        UNINHABITED_STATIC,
        UNKNOWN_CRATE_TYPES,
        UNKNOWN_DIAGNOSTIC_ATTRIBUTES,
        UNKNOWN_LINTS,
        UNNAMEABLE_TEST_ITEMS,
        UNNAMEABLE_TYPES,
        UNREACHABLE_CODE,
        UNREACHABLE_PATTERNS,
        UNSAFE_ATTR_OUTSIDE_UNSAFE,
        UNSAFE_OP_IN_UNSAFE_FN,
        UNSTABLE_NAME_COLLISIONS,
        UNSTABLE_SYNTAX_PRE_EXPANSION,
        UNSUPPORTED_CALLING_CONVENTIONS,
        UNUSED_ASSIGNMENTS,
        UNUSED_ASSOCIATED_TYPE_BOUNDS,
        UNUSED_ATTRIBUTES,
        UNUSED_CRATE_DEPENDENCIES,
        UNUSED_EXTERN_CRATES,
        UNUSED_FEATURES,
        UNUSED_IMPORTS,
        UNUSED_LABELS,
        UNUSED_LIFETIMES,
        UNUSED_MACROS,
        UNUSED_MACRO_RULES,
        UNUSED_MUT,
        UNUSED_QUALIFICATIONS,
        UNUSED_UNSAFE,
        UNUSED_VARIABLES,
        USELESS_DEPRECATED,
        VARARGS_WITHOUT_PATTERN,
        WARNINGS,
        // tidy-alphabetical-end
    ]
}

declare_lint! {
    /// The `forbidden_lint_groups` lint detects violations of
    /// `forbid` applied to a lint group. Due to a bug in the compiler,
    /// these used to be overlooked entirely. They now generate a warning.
    ///
    /// ### Example
    ///
    /// ```rust
    /// #![forbid(warnings)]
    /// #![warn(bad_style)]
    ///
    /// fn main() {}
    /// ```
    ///
    /// {{produces}}
    ///
    /// ### Recommended fix
    ///
    /// If your crate is using `#![forbid(warnings)]`,
    /// we recommend that you change to `#![deny(warnings)]`.
    ///
    /// ### Explanation
    ///
    /// Due to a compiler bug, applying `forbid` to lint groups
    /// previously had no effect. The bug is now fixed but instead of
    /// enforcing `forbid` we issue this future-compatibility warning
    /// to avoid breaking existing crates.
    pub FORBIDDEN_LINT_GROUPS,
    Warn,
    "applying forbid to lint-groups",
    @future_incompatible = FutureIncompatibleInfo {
        reason: FutureIncompatibilityReason::FutureReleaseError,
        reference: "issue #81670 <https://github.com/rust-lang/rust/issues/81670>",
        report_in_deps: true,
    };
}

declare_lint! {
    /// The `ill_formed_attribute_input` lint detects ill-formed attribute
    /// inputs that were previously accepted and used in practice.
    ///
    /// ### Example
    ///
    /// ```rust,compile_fail
    /// #[inline = "this is not valid"]
    /// fn foo() {}
    /// ```
    ///
    /// {{produces}}
    ///
    /// ### Explanation
    ///
    /// Previously, inputs for many built-in attributes weren't validated and
    /// nonsensical attribute inputs were accepted. After validation was
    /// added, it was determined that some existing projects made use of these
    /// invalid forms. This is a [future-incompatible] lint to transition this
    /// to a hard error in the future. See [issue #57571] for more details.
    ///
    /// Check the [attribute reference] for details on the valid inputs for
    /// attributes.
    ///
    /// [issue #57571]: https://github.com/rust-lang/rust/issues/57571
    /// [attribute reference]: https://doc.rust-lang.org/nightly/reference/attributes.html
    /// [future-incompatible]: ../index.md#future-incompatible-lints
    pub ILL_FORMED_ATTRIBUTE_INPUT,
    Deny,
    "ill-formed attribute inputs that were previously accepted and used in practice",
    @future_incompatible = FutureIncompatibleInfo {
        reason: FutureIncompatibilityReason::FutureReleaseError,
        reference: "issue #57571 <https://github.com/rust-lang/rust/issues/57571>",
        report_in_deps: true,
    };
    crate_level_only
}

declare_lint! {
    /// The `conflicting_repr_hints` lint detects [`repr` attributes] with
    /// conflicting hints.
    ///
    /// [`repr` attributes]: https://doc.rust-lang.org/reference/type-layout.html#representations
    ///
    /// ### Example
    ///
    /// ```rust,compile_fail
    /// #[repr(u32, u64)]
    /// enum Foo {
    ///     Variant1,
    /// }
    /// ```
    ///
    /// {{produces}}
    ///
    /// ### Explanation
    ///
    /// The compiler incorrectly accepted these conflicting representations in
    /// the past. This is a [future-incompatible] lint to transition this to a
    /// hard error in the future. See [issue #68585] for more details.
    ///
    /// To correct the issue, remove one of the conflicting hints.
    ///
    /// [issue #68585]: https://github.com/rust-lang/rust/issues/68585
    /// [future-incompatible]: ../index.md#future-incompatible-lints
    pub CONFLICTING_REPR_HINTS,
    Deny,
    "conflicts between `#[repr(..)]` hints that were previously accepted and used in practice",
    @future_incompatible = FutureIncompatibleInfo {
        reason: FutureIncompatibilityReason::FutureReleaseError,
        reference: "issue #68585 <https://github.com/rust-lang/rust/issues/68585>",
        report_in_deps: true,
    };
}

declare_lint! {
    /// The `meta_variable_misuse` lint detects possible meta-variable misuse
    /// in macro definitions.
    ///
    /// ### Example
    ///
    /// ```rust,compile_fail
    /// #![deny(meta_variable_misuse)]
    ///
    /// macro_rules! foo {
    ///     () => {};
    ///     ($( $i:ident = $($j:ident),+ );*) => { $( $( $i = $k; )+ )* };
    /// }
    ///
    /// fn main() {
    ///     foo!();
    /// }
    /// ```
    ///
    /// {{produces}}
    ///
    /// ### Explanation
    ///
    /// There are quite a few different ways a [`macro_rules`] macro can be
    /// improperly defined. Many of these errors were previously only detected
    /// when the macro was expanded or not at all. This lint is an attempt to
    /// catch some of these problems when the macro is *defined*.
    ///
    /// This lint is "allow" by default because it may have false positives
    /// and other issues. See [issue #61053] for more details.
    ///
    /// [`macro_rules`]: https://doc.rust-lang.org/reference/macros-by-example.html
    /// [issue #61053]: https://github.com/rust-lang/rust/issues/61053
    pub META_VARIABLE_MISUSE,
    Allow,
    "possible meta-variable misuse at macro definition"
}

declare_lint! {
    /// The `incomplete_include` lint detects the use of the [`include!`]
    /// macro with a file that contains more than one expression.
    ///
    /// [`include!`]: https://doc.rust-lang.org/std/macro.include.html
    ///
    /// ### Example
    ///
    /// ```rust,ignore (needs separate file)
    /// fn main() {
    ///     include!("foo.txt");
    /// }
    /// ```
    ///
    /// where the file `foo.txt` contains:
    ///
    /// ```text
    /// println!("hi!");
    /// ```
    ///
    /// produces:
    ///
    /// ```text
    /// error: include macro expected single expression in source
    ///  --> foo.txt:1:14
    ///   |
    /// 1 | println!("1");
    ///   |              ^
    ///   |
    ///   = note: `#[deny(incomplete_include)]` on by default
    /// ```
    ///
    /// ### Explanation
    ///
    /// The [`include!`] macro is currently only intended to be used to
    /// include a single [expression] or multiple [items]. Historically it
    /// would ignore any contents after the first expression, but that can be
    /// confusing. In the example above, the `println!` expression ends just
    /// before the semicolon, making the semicolon "extra" information that is
    /// ignored. Perhaps even more surprising, if the included file had
    /// multiple print statements, the subsequent ones would be ignored!
    ///
    /// One workaround is to place the contents in braces to create a [block
    /// expression]. Also consider alternatives, like using functions to
    /// encapsulate the expressions, or use [proc-macros].
    ///
    /// This is a lint instead of a hard error because existing projects were
    /// found to hit this error. To be cautious, it is a lint for now. The
    /// future semantics of the `include!` macro are also uncertain, see
    /// [issue #35560].
    ///
    /// [items]: https://doc.rust-lang.org/reference/items.html
    /// [expression]: https://doc.rust-lang.org/reference/expressions.html
    /// [block expression]: https://doc.rust-lang.org/reference/expressions/block-expr.html
    /// [proc-macros]: https://doc.rust-lang.org/reference/procedural-macros.html
    /// [issue #35560]: https://github.com/rust-lang/rust/issues/35560
    pub INCOMPLETE_INCLUDE,
    Deny,
    "trailing content in included file"
}

declare_lint! {
    /// The `arithmetic_overflow` lint detects that an arithmetic operation
    /// will [overflow].
    ///
    /// [overflow]: https://doc.rust-lang.org/reference/expressions/operator-expr.html#overflow
    ///
    /// ### Example
    ///
    /// ```rust,compile_fail
    /// 1_i32 << 32;
    /// ```
    ///
    /// {{produces}}
    ///
    /// ### Explanation
    ///
    /// It is very likely a mistake to perform an arithmetic operation that
    /// overflows its value. If the compiler is able to detect these kinds of
    /// overflows at compile-time, it will trigger this lint. Consider
    /// adjusting the expression to avoid overflow, or use a data type that
    /// will not overflow.
    pub ARITHMETIC_OVERFLOW,
    Deny,
    "arithmetic operation overflows",
    @eval_always = true
}

declare_lint! {
    /// The `unconditional_panic` lint detects an operation that will cause a
    /// panic at runtime.
    ///
    /// ### Example
    ///
    /// ```rust,compile_fail
    /// # #![allow(unused)]
    /// let x = 1 / 0;
    /// ```
    ///
    /// {{produces}}
    ///
    /// ### Explanation
    ///
    /// This lint detects code that is very likely incorrect because it will
    /// always panic, such as division by zero and out-of-bounds array
    /// accesses. Consider adjusting your code if this is a bug, or using the
    /// `panic!` or `unreachable!` macro instead in case the panic is intended.
    pub UNCONDITIONAL_PANIC,
    Deny,
    "operation will cause a panic at runtime",
    @eval_always = true
}

declare_lint! {
    /// The `unused_imports` lint detects imports that are never used.
    ///
    /// ### Example
    ///
    /// ```rust
    /// use std::collections::HashMap;
    /// ```
    ///
    /// {{produces}}
    ///
    /// ### Explanation
    ///
    /// Unused imports may signal a mistake or unfinished code, and clutter
    /// the code, and should be removed. If you intended to re-export the item
    /// to make it available outside of the module, add a visibility modifier
    /// like `pub`.
    pub UNUSED_IMPORTS,
    Warn,
    "imports that are never used"
}

declare_lint! {
    /// The `redundant_imports` lint detects imports that are redundant due to being
    /// imported already; either through a previous import, or being present in
    /// the prelude.
    ///
    /// ### Example
    ///
    /// ```rust,compile_fail
    /// #![deny(redundant_imports)]
    /// use std::option::Option::None;
    /// fn foo() -> Option<i32> { None }
    /// ```
    ///
    /// {{produces}}
    ///
    /// ### Explanation
    ///
    /// Redundant imports are unnecessary and can be removed to simplify code.
    /// If you intended to re-export the item to make it available outside of the
    /// module, add a visibility modifier like `pub`.
    pub REDUNDANT_IMPORTS,
    Allow,
    "imports that are redundant due to being imported already"
}

declare_lint! {
    /// The `must_not_suspend` lint guards against values that shouldn't be held across suspend points
    /// (`.await`)
    ///
    /// ### Example
    ///
    /// ```rust
    /// #![feature(must_not_suspend)]
    /// #![warn(must_not_suspend)]
    ///
    /// #[must_not_suspend]
    /// struct SyncThing {}
    ///
    /// async fn yield_now() {}
    ///
    /// pub async fn uhoh() {
    ///     let guard = SyncThing {};
    ///     yield_now().await;
    ///     let _guard = guard;
    /// }
    /// ```
    ///
    /// {{produces}}
    ///
    /// ### Explanation
    ///
    /// The `must_not_suspend` lint detects values that are marked with the `#[must_not_suspend]`
    /// attribute being held across suspend points. A "suspend" point is usually a `.await` in an async
    /// function.
    ///
    /// This attribute can be used to mark values that are semantically incorrect across suspends
    /// (like certain types of timers), values that have async alternatives, and values that
    /// regularly cause problems with the `Send`-ness of async fn's returned futures (like
    /// `MutexGuard`'s)
    ///
    pub MUST_NOT_SUSPEND,
    Allow,
    "use of a `#[must_not_suspend]` value across a yield point",
    @feature_gate = must_not_suspend;
}

declare_lint! {
    /// The `unused_extern_crates` lint guards against `extern crate` items
    /// that are never used.
    ///
    /// ### Example
    ///
    /// ```rust,compile_fail
    /// #![deny(unused_extern_crates)]
    /// #![deny(warnings)]
    /// extern crate proc_macro;
    /// ```
    ///
    /// {{produces}}
    ///
    /// ### Explanation
    ///
    /// `extern crate` items that are unused have no effect and should be
    /// removed. Note that there are some cases where specifying an `extern
    /// crate` is desired for the side effect of ensuring the given crate is
    /// linked, even though it is not otherwise directly referenced. The lint
    /// can be silenced by aliasing the crate to an underscore, such as
    /// `extern crate foo as _`. Also note that it is no longer idiomatic to
    /// use `extern crate` in the [2018 edition], as extern crates are now
    /// automatically added in scope.
    ///
    /// This lint is "allow" by default because it can be noisy, and produce
    /// false-positives. If a dependency is being removed from a project, it
    /// is recommended to remove it from the build configuration (such as
    /// `Cargo.toml`) to ensure stale build entries aren't left behind.
    ///
    /// [2018 edition]: https://doc.rust-lang.org/edition-guide/rust-2018/module-system/path-clarity.html#no-more-extern-crate
    pub UNUSED_EXTERN_CRATES,
    Allow,
    "extern crates that are never used"
}

declare_lint! {
    /// The `unused_crate_dependencies` lint detects crate dependencies that
    /// are never used.
    ///
    /// ### Example
    ///
    /// ```rust,ignore (needs extern crate)
    /// #![deny(unused_crate_dependencies)]
    /// ```
    ///
    /// This will produce:
    ///
    /// ```text
    /// error: extern crate `regex` is unused in crate `lint_example`
    ///   |
    ///   = help: remove the dependency or add `use regex as _;` to the crate root
    /// note: the lint level is defined here
    ///  --> src/lib.rs:1:9
    ///   |
    /// 1 | #![deny(unused_crate_dependencies)]
    ///   |         ^^^^^^^^^^^^^^^^^^^^^^^^^
    /// ```
    ///
    /// ### Explanation
    ///
    /// After removing the code that uses a dependency, this usually also
    /// requires removing the dependency from the build configuration.
    /// However, sometimes that step can be missed, which leads to time wasted
    /// building dependencies that are no longer used. This lint can be
    /// enabled to detect dependencies that are never used (more specifically,
    /// any dependency passed with the `--extern` command-line flag that is
    /// never referenced via [`use`], [`extern crate`], or in any [path]).
    ///
    /// This lint is "allow" by default because it can provide false positives
    /// depending on how the build system is configured. For example, when
    /// using Cargo, a "package" consists of multiple crates (such as a
    /// library and a binary), but the dependencies are defined for the
    /// package as a whole. If there is a dependency that is only used in the
    /// binary, but not the library, then the lint will be incorrectly issued
    /// in the library.
    ///
    /// [path]: https://doc.rust-lang.org/reference/paths.html
    /// [`use`]: https://doc.rust-lang.org/reference/items/use-declarations.html
    /// [`extern crate`]: https://doc.rust-lang.org/reference/items/extern-crates.html
    pub UNUSED_CRATE_DEPENDENCIES,
    Allow,
    "crate dependencies that are never used",
    crate_level_only
}

declare_lint! {
    /// The `unused_qualifications` lint detects unnecessarily qualified
    /// names.
    ///
    /// ### Example
    ///
    /// ```rust,compile_fail
    /// #![deny(unused_qualifications)]
    /// mod foo {
    ///     pub fn bar() {}
    /// }
    ///
    /// fn main() {
    ///     use foo::bar;
    ///     foo::bar();
    ///     bar();
    /// }
    /// ```
    ///
    /// {{produces}}
    ///
    /// ### Explanation
    ///
    /// If an item from another module is already brought into scope, then
    /// there is no need to qualify it in this case. You can call `bar()`
    /// directly, without the `foo::`.
    ///
    /// This lint is "allow" by default because it is somewhat pedantic, and
    /// doesn't indicate an actual problem, but rather a stylistic choice, and
    /// can be noisy when refactoring or moving around code.
    pub UNUSED_QUALIFICATIONS,
    Allow,
    "detects unnecessarily qualified names"
}

declare_lint! {
    /// The `unknown_lints` lint detects unrecognized lint attributes.
    ///
    /// ### Example
    ///
    /// ```rust
    /// #![allow(not_a_real_lint)]
    /// ```
    ///
    /// {{produces}}
    ///
    /// ### Explanation
    ///
    /// It is usually a mistake to specify a lint that does not exist. Check
    /// the spelling, and check the lint listing for the correct name. Also
    /// consider if you are using an old version of the compiler, and the lint
    /// is only available in a newer version.
    pub UNKNOWN_LINTS,
    Warn,
    "unrecognized lint attribute",
    @eval_always = true
}

declare_lint! {
    /// The `unfulfilled_lint_expectations` lint detects when a lint expectation is
    /// unfulfilled.
    ///
    /// ### Example
    ///
    /// ```rust
    /// #[expect(unused_variables)]
    /// let x = 10;
    /// println!("{}", x);
    /// ```
    ///
    /// {{produces}}
    ///
    /// ### Explanation
    ///
    /// The `#[expect]` attribute can be used to create a lint expectation. The
    /// expectation is fulfilled, if a `#[warn]` attribute at the same location
    /// would result in a lint emission. If the expectation is unfulfilled,
    /// because no lint was emitted, this lint will be emitted on the attribute.
    ///
    pub UNFULFILLED_LINT_EXPECTATIONS,
    Warn,
    "unfulfilled lint expectation"
}

declare_lint! {
    /// The `unused_variables` lint detects variables which are not used in
    /// any way.
    ///
    /// ### Example
    ///
    /// ```rust
    /// let x = 5;
    /// ```
    ///
    /// {{produces}}
    ///
    /// ### Explanation
    ///
    /// Unused variables may signal a mistake or unfinished code. To silence
    /// the warning for the individual variable, prefix it with an underscore
    /// such as `_x`.
    pub UNUSED_VARIABLES,
    Warn,
    "detect variables which are not used in any way"
}

declare_lint! {
    /// The `unused_assignments` lint detects assignments that will never be read.
    ///
    /// ### Example
    ///
    /// ```rust
    /// let mut x = 5;
    /// x = 6;
    /// ```
    ///
    /// {{produces}}
    ///
    /// ### Explanation
    ///
    /// Unused assignments may signal a mistake or unfinished code. If the
    /// variable is never used after being assigned, then the assignment can
    /// be removed. Variables with an underscore prefix such as `_x` will not
    /// trigger this lint.
    pub UNUSED_ASSIGNMENTS,
    Warn,
    "detect assignments that will never be read"
}

declare_lint! {
    /// The `dead_code` lint detects unused, unexported items.
    ///
    /// ### Example
    ///
    /// ```rust
    /// fn foo() {}
    /// ```
    ///
    /// {{produces}}
    ///
    /// ### Explanation
    ///
    /// Dead code may signal a mistake or unfinished code. To silence the
    /// warning for individual items, prefix the name with an underscore such
    /// as `_foo`. If it was intended to expose the item outside of the crate,
    /// consider adding a visibility modifier like `pub`.
    ///
    /// To preserve the numbering of tuple structs with unused fields,
    /// change the unused fields to have unit type or use
    /// `PhantomData`.
    ///
    /// Otherwise consider removing the unused code.
    ///
    /// ### Limitations
    ///
    /// Removing fields that are only used for side-effects and never
    /// read will result in behavioral changes. Examples of this
    /// include:
    ///
    /// - If a field's value performs an action when it is dropped.
    /// - If a field's type does not implement an auto trait
    ///   (e.g. `Send`, `Sync`, `Unpin`).
    ///
    /// For side-effects from dropping field values, this lint should
    /// be allowed on those fields. For side-effects from containing
    /// field types, `PhantomData` should be used.
    pub DEAD_CODE,
    Warn,
    "detect unused, unexported items"
}

declare_lint! {
    /// The `unused_attributes` lint detects attributes that were not used by
    /// the compiler.
    ///
    /// ### Example
    ///
    /// ```rust
    /// #![ignore]
    /// ```
    ///
    /// {{produces}}
    ///
    /// ### Explanation
    ///
    /// Unused [attributes] may indicate the attribute is placed in the wrong
    /// position. Consider removing it, or placing it in the correct position.
    /// Also consider if you intended to use an _inner attribute_ (with a `!`
    /// such as `#![allow(unused)]`) which applies to the item the attribute
    /// is within, or an _outer attribute_ (without a `!` such as
    /// `#[allow(unused)]`) which applies to the item *following* the
    /// attribute.
    ///
    /// [attributes]: https://doc.rust-lang.org/reference/attributes.html
    pub UNUSED_ATTRIBUTES,
    Warn,
    "detects attributes that were not used by the compiler"
}

declare_lint! {
    /// The `unreachable_code` lint detects unreachable code paths.
    ///
    /// ### Example
    ///
    /// ```rust,no_run
    /// panic!("we never go past here!");
    ///
    /// let x = 5;
    /// ```
    ///
    /// {{produces}}
    ///
    /// ### Explanation
    ///
    /// Unreachable code may signal a mistake or unfinished code. If the code
    /// is no longer in use, consider removing it.
    pub UNREACHABLE_CODE,
    Warn,
    "detects unreachable code paths",
    report_in_external_macro
}

declare_lint! {
    /// The `unreachable_patterns` lint detects unreachable patterns.
    ///
    /// ### Example
    ///
    /// ```rust
    /// let x = 5;
    /// match x {
    ///     y => (),
    ///     5 => (),
    /// }
    /// ```
    ///
    /// {{produces}}
    ///
    /// ### Explanation
    ///
    /// This usually indicates a mistake in how the patterns are specified or
    /// ordered. In this example, the `y` pattern will always match, so the
    /// five is impossible to reach. Remember, match arms match in order, you
    /// probably wanted to put the `5` case above the `y` case.
    pub UNREACHABLE_PATTERNS,
    Warn,
    "detects unreachable patterns"
}

declare_lint! {
    /// The `overlapping_range_endpoints` lint detects `match` arms that have [range patterns] that
    /// overlap on their endpoints.
    ///
    /// [range patterns]: https://doc.rust-lang.org/nightly/reference/patterns.html#range-patterns
    ///
    /// ### Example
    ///
    /// ```rust
    /// let x = 123u8;
    /// match x {
    ///     0..=100 => { println!("small"); }
    ///     100..=255 => { println!("large"); }
    /// }
    /// ```
    ///
    /// {{produces}}
    ///
    /// ### Explanation
    ///
    /// It is likely a mistake to have range patterns in a match expression that overlap in this
    /// way. Check that the beginning and end values are what you expect, and keep in mind that
    /// with `..=` the left and right bounds are inclusive.
    pub OVERLAPPING_RANGE_ENDPOINTS,
    Warn,
    "detects range patterns with overlapping endpoints"
}

declare_lint! {
    /// The `non_contiguous_range_endpoints` lint detects likely off-by-one errors when using
    /// exclusive [range patterns].
    ///
    /// [range patterns]: https://doc.rust-lang.org/nightly/reference/patterns.html#range-patterns
    ///
    /// ### Example
    ///
    /// ```rust
    /// let x = 123u32;
    /// match x {
    ///     0..100 => { println!("small"); }
    ///     101..1000 => { println!("large"); }
    ///     _ => { println!("larger"); }
    /// }
    /// ```
    ///
    /// {{produces}}
    ///
    /// ### Explanation
    ///
    /// It is likely a mistake to have range patterns in a match expression that miss out a single
    /// number. Check that the beginning and end values are what you expect, and keep in mind that
    /// with `..=` the right bound is inclusive, and with `..` it is exclusive.
    pub NON_CONTIGUOUS_RANGE_ENDPOINTS,
    Warn,
    "detects off-by-one errors with exclusive range patterns"
}

declare_lint! {
    /// The `bindings_with_variant_name` lint detects pattern bindings with
    /// the same name as one of the matched variants.
    ///
    /// ### Example
    ///
    /// ```rust,compile_fail
    /// pub enum Enum {
    ///     Foo,
    ///     Bar,
    /// }
    ///
    /// pub fn foo(x: Enum) {
    ///     match x {
    ///         Foo => {}
    ///         Bar => {}
    ///     }
    /// }
    /// ```
    ///
    /// {{produces}}
    ///
    /// ### Explanation
    ///
    /// It is usually a mistake to specify an enum variant name as an
    /// [identifier pattern]. In the example above, the `match` arms are
    /// specifying a variable name to bind the value of `x` to. The second arm
    /// is ignored because the first one matches *all* values. The likely
    /// intent is that the arm was intended to match on the enum variant.
    ///
    /// Two possible solutions are:
    ///
    /// * Specify the enum variant using a [path pattern], such as
    ///   `Enum::Foo`.
    /// * Bring the enum variants into local scope, such as adding `use
    ///   Enum::*;` to the beginning of the `foo` function in the example
    ///   above.
    ///
    /// [identifier pattern]: https://doc.rust-lang.org/reference/patterns.html#identifier-patterns
    /// [path pattern]: https://doc.rust-lang.org/reference/patterns.html#path-patterns
    pub BINDINGS_WITH_VARIANT_NAME,
    Deny,
    "detects pattern bindings with the same name as one of the matched variants"
}

declare_lint! {
    /// The `unused_macros` lint detects macros that were not used.
    ///
    /// Note that this lint is distinct from the `unused_macro_rules` lint,
    /// which checks for single rules that never match of an otherwise used
    /// macro, and thus never expand.
    ///
    /// ### Example
    ///
    /// ```rust
    /// macro_rules! unused {
    ///     () => {};
    /// }
    ///
    /// fn main() {
    /// }
    /// ```
    ///
    /// {{produces}}
    ///
    /// ### Explanation
    ///
    /// Unused macros may signal a mistake or unfinished code. To silence the
    /// warning for the individual macro, prefix the name with an underscore
    /// such as `_my_macro`. If you intended to export the macro to make it
    /// available outside of the crate, use the [`macro_export` attribute].
    ///
    /// [`macro_export` attribute]: https://doc.rust-lang.org/reference/macros-by-example.html#path-based-scope
    pub UNUSED_MACROS,
    Warn,
    "detects macros that were not used"
}

declare_lint! {
    /// The `unused_macro_rules` lint detects macro rules that were not used.
    ///
    /// Note that the lint is distinct from the `unused_macros` lint, which
    /// fires if the entire macro is never called, while this lint fires for
    /// single unused rules of the macro that is otherwise used.
    /// `unused_macro_rules` fires only if `unused_macros` wouldn't fire.
    ///
    /// ### Example
    ///
    /// ```rust
    /// #[warn(unused_macro_rules)]
    /// macro_rules! unused_empty {
    ///     (hello) => { println!("Hello, world!") }; // This rule is unused
    ///     () => { println!("empty") }; // This rule is used
    /// }
    ///
    /// fn main() {
    ///     unused_empty!(hello);
    /// }
    /// ```
    ///
    /// {{produces}}
    ///
    /// ### Explanation
    ///
    /// Unused macro rules may signal a mistake or unfinished code. Furthermore,
    /// they slow down compilation. Right now, silencing the warning is not
    /// supported on a single rule level, so you have to add an allow to the
    /// entire macro definition.
    ///
    /// If you intended to export the macro to make it
    /// available outside of the crate, use the [`macro_export` attribute].
    ///
    /// [`macro_export` attribute]: https://doc.rust-lang.org/reference/macros-by-example.html#path-based-scope
    pub UNUSED_MACRO_RULES,
    Allow,
    "detects macro rules that were not used"
}

declare_lint! {
    /// The `warnings` lint allows you to change the level of other
    /// lints which produce warnings.
    ///
    /// ### Example
    ///
    /// ```rust
    /// #![deny(warnings)]
    /// fn foo() {}
    /// ```
    ///
    /// {{produces}}
    ///
    /// ### Explanation
    ///
    /// The `warnings` lint is a bit special; by changing its level, you
    /// change every other warning that would produce a warning to whatever
    /// value you'd like. As such, you won't ever trigger this lint in your
    /// code directly.
    pub WARNINGS,
    Warn,
    "mass-change the level for lints which produce warnings"
}

declare_lint! {
    /// The `unused_features` lint detects unused or unknown features found in
    /// crate-level [`feature` attributes].
    ///
    /// [`feature` attributes]: https://doc.rust-lang.org/nightly/unstable-book/
    ///
    /// Note: This lint is currently not functional, see [issue #44232] for
    /// more details.
    ///
    /// [issue #44232]: https://github.com/rust-lang/rust/issues/44232
    pub UNUSED_FEATURES,
    Warn,
    "unused features found in crate-level `#[feature]` directives"
}

declare_lint! {
    /// The `stable_features` lint detects a [`feature` attribute] that
    /// has since been made stable.
    ///
    /// [`feature` attribute]: https://doc.rust-lang.org/nightly/unstable-book/
    ///
    /// ### Example
    ///
    /// ```rust
    /// #![feature(test_accepted_feature)]
    /// fn main() {}
    /// ```
    ///
    /// {{produces}}
    ///
    /// ### Explanation
    ///
    /// When a feature is stabilized, it is no longer necessary to include a
    /// `#![feature]` attribute for it. To fix, simply remove the
    /// `#![feature]` attribute.
    pub STABLE_FEATURES,
    Warn,
    "stable features found in `#[feature]` directive"
}

declare_lint! {
    /// The `unknown_crate_types` lint detects an unknown crate type found in
    /// a [`crate_type` attribute].
    ///
    /// ### Example
    ///
    /// ```rust,compile_fail
    /// #![crate_type="lol"]
    /// fn main() {}
    /// ```
    ///
    /// {{produces}}
    ///
    /// ### Explanation
    ///
    /// An unknown value give to the `crate_type` attribute is almost
    /// certainly a mistake.
    ///
    /// [`crate_type` attribute]: https://doc.rust-lang.org/reference/linkage.html
    pub UNKNOWN_CRATE_TYPES,
    Deny,
    "unknown crate type found in `#[crate_type]` directive",
    crate_level_only
}

declare_lint! {
    /// The `trivial_casts` lint detects trivial casts which could be replaced
    /// with coercion, which may require a temporary variable.
    ///
    /// ### Example
    ///
    /// ```rust,compile_fail
    /// #![deny(trivial_casts)]
    /// let x: &u32 = &42;
    /// let y = x as *const u32;
    /// ```
    ///
    /// {{produces}}
    ///
    /// ### Explanation
    ///
    /// A trivial cast is a cast `e as T` where `e` has type `U` and `U` is a
    /// subtype of `T`. This type of cast is usually unnecessary, as it can be
    /// usually be inferred.
    ///
    /// This lint is "allow" by default because there are situations, such as
    /// with FFI interfaces or complex type aliases, where it triggers
    /// incorrectly, or in situations where it will be more difficult to
    /// clearly express the intent. It may be possible that this will become a
    /// warning in the future, possibly with an explicit syntax for coercions
    /// providing a convenient way to work around the current issues.
    /// See [RFC 401 (coercions)][rfc-401], [RFC 803 (type ascription)][rfc-803] and
    /// [RFC 3307 (remove type ascription)][rfc-3307] for historical context.
    ///
    /// [rfc-401]: https://github.com/rust-lang/rfcs/blob/master/text/0401-coercions.md
    /// [rfc-803]: https://github.com/rust-lang/rfcs/blob/master/text/0803-type-ascription.md
    /// [rfc-3307]: https://github.com/rust-lang/rfcs/blob/master/text/3307-de-rfc-type-ascription.md
    pub TRIVIAL_CASTS,
    Allow,
    "detects trivial casts which could be removed"
}

declare_lint! {
    /// The `trivial_numeric_casts` lint detects trivial numeric casts of types
    /// which could be removed.
    ///
    /// ### Example
    ///
    /// ```rust,compile_fail
    /// #![deny(trivial_numeric_casts)]
    /// let x = 42_i32 as i32;
    /// ```
    ///
    /// {{produces}}
    ///
    /// ### Explanation
    ///
    /// A trivial numeric cast is a cast of a numeric type to the same numeric
    /// type. This type of cast is usually unnecessary.
    ///
    /// This lint is "allow" by default because there are situations, such as
    /// with FFI interfaces or complex type aliases, where it triggers
    /// incorrectly, or in situations where it will be more difficult to
    /// clearly express the intent. It may be possible that this will become a
    /// warning in the future, possibly with an explicit syntax for coercions
    /// providing a convenient way to work around the current issues.
    /// See [RFC 401 (coercions)][rfc-401], [RFC 803 (type ascription)][rfc-803] and
    /// [RFC 3307 (remove type ascription)][rfc-3307] for historical context.
    ///
    /// [rfc-401]: https://github.com/rust-lang/rfcs/blob/master/text/0401-coercions.md
    /// [rfc-803]: https://github.com/rust-lang/rfcs/blob/master/text/0803-type-ascription.md
    /// [rfc-3307]: https://github.com/rust-lang/rfcs/blob/master/text/3307-de-rfc-type-ascription.md
    pub TRIVIAL_NUMERIC_CASTS,
    Allow,
    "detects trivial casts of numeric types which could be removed"
}

declare_lint! {
    /// The `exported_private_dependencies` lint detects private dependencies
    /// that are exposed in a public interface.
    ///
    /// ### Example
    ///
    /// ```rust,ignore (needs-dependency)
    /// pub fn foo() -> Option<some_private_dependency::Thing> {
    ///     None
    /// }
    /// ```
    ///
    /// This will produce:
    ///
    /// ```text
    /// warning: type `bar::Thing` from private dependency 'bar' in public interface
    ///  --> src/lib.rs:3:1
    ///   |
    /// 3 | pub fn foo() -> Option<bar::Thing> {
    ///   | ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    ///   |
    ///   = note: `#[warn(exported_private_dependencies)]` on by default
    /// ```
    ///
    /// ### Explanation
    ///
    /// Dependencies can be marked as "private" to indicate that they are not
    /// exposed in the public interface of a crate. This can be used by Cargo
    /// to independently resolve those dependencies because it can assume it
    /// does not need to unify them with other packages using that same
    /// dependency. This lint is an indication of a violation of that
    /// contract.
    ///
    /// To fix this, avoid exposing the dependency in your public interface.
    /// Or, switch the dependency to a public dependency.
    ///
    /// Note that support for this is only available on the nightly channel.
    /// See [RFC 1977] for more details, as well as the [Cargo documentation].
    ///
    /// [RFC 1977]: https://github.com/rust-lang/rfcs/blob/master/text/1977-public-private-dependencies.md
    /// [Cargo documentation]: https://doc.rust-lang.org/nightly/cargo/reference/unstable.html#public-dependency
    pub EXPORTED_PRIVATE_DEPENDENCIES,
    Warn,
    "public interface leaks type from a private dependency"
}

declare_lint! {
    /// The `pub_use_of_private_extern_crate` lint detects a specific
    /// situation of re-exporting a private `extern crate`.
    ///
    /// ### Example
    ///
    /// ```rust,compile_fail
    /// extern crate core;
    /// pub use core as reexported_core;
    /// ```
    ///
    /// {{produces}}
    ///
    /// ### Explanation
    ///
    /// A public `use` declaration should not be used to publically re-export a
    /// private `extern crate`. `pub extern crate` should be used instead.
    ///
    /// This was historically allowed, but is not the intended behavior
    /// according to the visibility rules. This is a [future-incompatible]
    /// lint to transition this to a hard error in the future. See [issue
    /// #127909] for more details.
    ///
    /// [issue #127909]: https://github.com/rust-lang/rust/issues/127909
    /// [future-incompatible]: ../index.md#future-incompatible-lints
    pub PUB_USE_OF_PRIVATE_EXTERN_CRATE,
    Deny,
    "detect public re-exports of private extern crates",
    @future_incompatible = FutureIncompatibleInfo {
        reason: FutureIncompatibilityReason::FutureReleaseError,
        reference: "issue #127909 <https://github.com/rust-lang/rust/issues/127909>",
        report_in_deps: true,
    };
}

declare_lint! {
    /// The `invalid_type_param_default` lint detects type parameter defaults
    /// erroneously allowed in an invalid location.
    ///
    /// ### Example
    ///
    /// ```rust,compile_fail
    /// fn foo<T=i32>(t: T) {}
    /// ```
    ///
    /// {{produces}}
    ///
    /// ### Explanation
    ///
    /// Default type parameters were only intended to be allowed in certain
    /// situations, but historically the compiler allowed them everywhere.
    /// This is a [future-incompatible] lint to transition this to a hard
    /// error in the future. See [issue #36887] for more details.
    ///
    /// [issue #36887]: https://github.com/rust-lang/rust/issues/36887
    /// [future-incompatible]: ../index.md#future-incompatible-lints
    pub INVALID_TYPE_PARAM_DEFAULT,
    Deny,
    "type parameter default erroneously allowed in invalid location",
    @future_incompatible = FutureIncompatibleInfo {
        reason: FutureIncompatibilityReason::FutureReleaseError,
        reference: "issue #36887 <https://github.com/rust-lang/rust/issues/36887>",
        report_in_deps: true,
    };
}

declare_lint! {
    /// The `renamed_and_removed_lints` lint detects lints that have been
    /// renamed or removed.
    ///
    /// ### Example
    ///
    /// ```rust
    /// #![deny(raw_pointer_derive)]
    /// ```
    ///
    /// {{produces}}
    ///
    /// ### Explanation
    ///
    /// To fix this, either remove the lint or use the new name. This can help
    /// avoid confusion about lints that are no longer valid, and help
    /// maintain consistency for renamed lints.
    pub RENAMED_AND_REMOVED_LINTS,
    Warn,
    "lints that have been renamed or removed"
}

declare_lint! {
    /// The `const_item_mutation` lint detects attempts to mutate a `const`
    /// item.
    ///
    /// ### Example
    ///
    /// ```rust
    /// const FOO: [i32; 1] = [0];
    ///
    /// fn main() {
    ///     FOO[0] = 1;
    ///     // This will print "[0]".
    ///     println!("{:?}", FOO);
    /// }
    /// ```
    ///
    /// {{produces}}
    ///
    /// ### Explanation
    ///
    /// Trying to directly mutate a `const` item is almost always a mistake.
    /// What is happening in the example above is that a temporary copy of the
    /// `const` is mutated, but the original `const` is not. Each time you
    /// refer to the `const` by name (such as `FOO` in the example above), a
    /// separate copy of the value is inlined at that location.
    ///
    /// This lint checks for writing directly to a field (`FOO.field =
    /// some_value`) or array entry (`FOO[0] = val`), or taking a mutable
    /// reference to the const item (`&mut FOO`), including through an
    /// autoderef (`FOO.some_mut_self_method()`).
    ///
    /// There are various alternatives depending on what you are trying to
    /// accomplish:
    ///
    /// * First, always reconsider using mutable globals, as they can be
    ///   difficult to use correctly, and can make the code more difficult to
    ///   use or understand.
    /// * If you are trying to perform a one-time initialization of a global:
    ///     * If the value can be computed at compile-time, consider using
    ///       const-compatible values (see [Constant Evaluation]).
    ///     * For more complex single-initialization cases, consider using
    ///       [`std::sync::LazyLock`].
    /// * If you truly need a mutable global, consider using a [`static`],
    ///   which has a variety of options:
    ///   * Simple data types can be directly defined and mutated with an
    ///     [`atomic`] type.
    ///   * More complex types can be placed in a synchronization primitive
    ///     like a [`Mutex`], which can be initialized with one of the options
    ///     listed above.
    ///   * A [mutable `static`] is a low-level primitive, requiring unsafe.
    ///     Typically This should be avoided in preference of something
    ///     higher-level like one of the above.
    ///
    /// [Constant Evaluation]: https://doc.rust-lang.org/reference/const_eval.html
    /// [`static`]: https://doc.rust-lang.org/reference/items/static-items.html
    /// [mutable `static`]: https://doc.rust-lang.org/reference/items/static-items.html#mutable-statics
    /// [`std::sync::LazyLock`]: https://doc.rust-lang.org/stable/std/sync/struct.LazyLock.html
    /// [`atomic`]: https://doc.rust-lang.org/std/sync/atomic/index.html
    /// [`Mutex`]: https://doc.rust-lang.org/std/sync/struct.Mutex.html
    pub CONST_ITEM_MUTATION,
    Warn,
    "detects attempts to mutate a `const` item",
}

declare_lint! {
    /// The `patterns_in_fns_without_body` lint detects `mut` identifier
    /// patterns as a parameter in functions without a body.
    ///
    /// ### Example
    ///
    /// ```rust,compile_fail
    /// trait Trait {
    ///     fn foo(mut arg: u8);
    /// }
    /// ```
    ///
    /// {{produces}}
    ///
    /// ### Explanation
    ///
    /// To fix this, remove `mut` from the parameter in the trait definition;
    /// it can be used in the implementation. That is, the following is OK:
    ///
    /// ```rust
    /// trait Trait {
    ///     fn foo(arg: u8); // Removed `mut` here
    /// }
    ///
    /// impl Trait for i32 {
    ///     fn foo(mut arg: u8) { // `mut` here is OK
    ///
    ///     }
    /// }
    /// ```
    ///
    /// Trait definitions can define functions without a body to specify a
    /// function that implementors must define. The parameter names in the
    /// body-less functions are only allowed to be `_` or an [identifier] for
    /// documentation purposes (only the type is relevant). Previous versions
    /// of the compiler erroneously allowed [identifier patterns] with the
    /// `mut` keyword, but this was not intended to be allowed. This is a
    /// [future-incompatible] lint to transition this to a hard error in the
    /// future. See [issue #35203] for more details.
    ///
    /// [identifier]: https://doc.rust-lang.org/reference/identifiers.html
    /// [identifier patterns]: https://doc.rust-lang.org/reference/patterns.html#identifier-patterns
    /// [issue #35203]: https://github.com/rust-lang/rust/issues/35203
    /// [future-incompatible]: ../index.md#future-incompatible-lints
    pub PATTERNS_IN_FNS_WITHOUT_BODY,
    Deny,
    "patterns in functions without body were erroneously allowed",
    @future_incompatible = FutureIncompatibleInfo {
        reason: FutureIncompatibilityReason::FutureReleaseError,
        reference: "issue #35203 <https://github.com/rust-lang/rust/issues/35203>",
    };
}

declare_lint! {
    /// The `late_bound_lifetime_arguments` lint detects generic lifetime
    /// arguments in path segments with late bound lifetime parameters.
    ///
    /// ### Example
    ///
    /// ```rust
    /// struct S;
    ///
    /// impl S {
    ///     fn late(self, _: &u8, _: &u8) {}
    /// }
    ///
    /// fn main() {
    ///     S.late::<'static>(&0, &0);
    /// }
    /// ```
    ///
    /// {{produces}}
    ///
    /// ### Explanation
    ///
    /// It is not clear how to provide arguments for early-bound lifetime
    /// parameters if they are intermixed with late-bound parameters in the
    /// same list. For now, providing any explicit arguments will trigger this
    /// lint if late-bound parameters are present, so in the future a solution
    /// can be adopted without hitting backward compatibility issues. This is
    /// a [future-incompatible] lint to transition this to a hard error in the
    /// future. See [issue #42868] for more details, along with a description
    /// of the difference between early and late-bound parameters.
    ///
    /// [issue #42868]: https://github.com/rust-lang/rust/issues/42868
    /// [future-incompatible]: ../index.md#future-incompatible-lints
    pub LATE_BOUND_LIFETIME_ARGUMENTS,
    Warn,
    "detects generic lifetime arguments in path segments with late bound lifetime parameters",
    @future_incompatible = FutureIncompatibleInfo {
        reason: FutureIncompatibilityReason::FutureReleaseError,
        reference: "issue #42868 <https://github.com/rust-lang/rust/issues/42868>",
    };
}

declare_lint! {
    /// The `coherence_leak_check` lint detects conflicting implementations of
    /// a trait that are only distinguished by the old leak-check code.
    ///
    /// ### Example
    ///
    /// ```rust
    /// trait SomeTrait { }
    /// impl SomeTrait for for<'a> fn(&'a u8) { }
    /// impl<'a> SomeTrait for fn(&'a u8) { }
    /// ```
    ///
    /// {{produces}}
    ///
    /// ### Explanation
    ///
    /// In the past, the compiler would accept trait implementations for
    /// identical functions that differed only in where the lifetime binder
    /// appeared. Due to a change in the borrow checker implementation to fix
    /// several bugs, this is no longer allowed. However, since this affects
    /// existing code, this is a [future-incompatible] lint to transition this
    /// to a hard error in the future.
    ///
    /// Code relying on this pattern should introduce "[newtypes]",
    /// like `struct Foo(for<'a> fn(&'a u8))`.
    ///
    /// See [issue #56105] for more details.
    ///
    /// [issue #56105]: https://github.com/rust-lang/rust/issues/56105
    /// [newtypes]: https://doc.rust-lang.org/book/ch19-04-advanced-types.html#using-the-newtype-pattern-for-type-safety-and-abstraction
    /// [future-incompatible]: ../index.md#future-incompatible-lints
    pub COHERENCE_LEAK_CHECK,
    Warn,
    "distinct impls distinguished only by the leak-check code",
    @future_incompatible = FutureIncompatibleInfo {
        reason: FutureIncompatibilityReason::Custom("the behavior may change in a future release"),
        reference: "issue #56105 <https://github.com/rust-lang/rust/issues/56105>",
    };
}

declare_lint! {
    /// The `deprecated` lint detects use of deprecated items.
    ///
    /// ### Example
    ///
    /// ```rust
    /// #[deprecated]
    /// fn foo() {}
    ///
    /// fn bar() {
    ///     foo();
    /// }
    /// ```
    ///
    /// {{produces}}
    ///
    /// ### Explanation
    ///
    /// Items may be marked "deprecated" with the [`deprecated` attribute] to
    /// indicate that they should no longer be used. Usually the attribute
    /// should include a note on what to use instead, or check the
    /// documentation.
    ///
    /// [`deprecated` attribute]: https://doc.rust-lang.org/reference/attributes/diagnostics.html#the-deprecated-attribute
    pub DEPRECATED,
    Warn,
    "detects use of deprecated items",
    report_in_external_macro
}

declare_lint! {
    /// The `unused_unsafe` lint detects unnecessary use of an `unsafe` block.
    ///
    /// ### Example
    ///
    /// ```rust
    /// unsafe {}
    /// ```
    ///
    /// {{produces}}
    ///
    /// ### Explanation
    ///
    /// If nothing within the block requires `unsafe`, then remove the
    /// `unsafe` marker because it is not required and may cause confusion.
    pub UNUSED_UNSAFE,
    Warn,
    "unnecessary use of an `unsafe` block"
}

declare_lint! {
    /// The `unused_mut` lint detects mut variables which don't need to be
    /// mutable.
    ///
    /// ### Example
    ///
    /// ```rust
    /// let mut x = 5;
    /// ```
    ///
    /// {{produces}}
    ///
    /// ### Explanation
    ///
    /// The preferred style is to only mark variables as `mut` if it is
    /// required.
    pub UNUSED_MUT,
    Warn,
    "detect mut variables which don't need to be mutable"
}

declare_lint! {
    /// The `rust_2024_incompatible_pat` lint
    /// detects patterns whose meaning will change in the Rust 2024 edition.
    ///
    /// ### Example
    ///
    /// ```rust,edition2021
    /// #![warn(rust_2024_incompatible_pat)]
    ///
    /// if let Some(&a) = &Some(&0u8) {
    ///     let _: u8 = a;
    /// }
    /// if let Some(mut _a) = &mut Some(0u8) {
    ///     _a = 7u8;
    /// }
    /// ```
    ///
    /// {{produces}}
    ///
    /// ### Explanation
    ///
    /// In Rust 2024 and above, the `mut` keyword does not reset the pattern binding mode,
    /// and nor do `&` or `&mut` patterns. The lint will suggest code that
    /// has the same meaning in all editions.
    pub RUST_2024_INCOMPATIBLE_PAT,
    Allow,
    "detects patterns whose meaning will change in Rust 2024",
    @future_incompatible = FutureIncompatibleInfo {
        reason: FutureIncompatibilityReason::EditionSemanticsChange(Edition::Edition2024),
        reference: "<https://doc.rust-lang.org/edition-guide/rust-2024/match-ergonomics.html>",
    };
}

declare_lint! {
    /// The `unconditional_recursion` lint detects functions that cannot
    /// return without calling themselves.
    ///
    /// ### Example
    ///
    /// ```rust
    /// fn foo() {
    ///     foo();
    /// }
    /// ```
    ///
    /// {{produces}}
    ///
    /// ### Explanation
    ///
    /// It is usually a mistake to have a recursive call that does not have
    /// some condition to cause it to terminate. If you really intend to have
    /// an infinite loop, using a `loop` expression is recommended.
    pub UNCONDITIONAL_RECURSION,
    Warn,
    "functions that cannot return without calling themselves"
}

declare_lint! {
    /// The `single_use_lifetimes` lint detects lifetimes that are only used
    /// once.
    ///
    /// ### Example
    ///
    /// ```rust,compile_fail
    /// #![deny(single_use_lifetimes)]
    ///
    /// fn foo<'a>(x: &'a u32) {}
    /// ```
    ///
    /// {{produces}}
    ///
    /// ### Explanation
    ///
    /// Specifying an explicit lifetime like `'a` in a function or `impl`
    /// should only be used to link together two things. Otherwise, you should
    /// just use `'_` to indicate that the lifetime is not linked to anything,
    /// or elide the lifetime altogether if possible.
    ///
    /// This lint is "allow" by default because it was introduced at a time
    /// when `'_` and elided lifetimes were first being introduced, and this
    /// lint would be too noisy. Also, there are some known false positives
    /// that it produces. See [RFC 2115] for historical context, and [issue
    /// #44752] for more details.
    ///
    /// [RFC 2115]: https://github.com/rust-lang/rfcs/blob/master/text/2115-argument-lifetimes.md
    /// [issue #44752]: https://github.com/rust-lang/rust/issues/44752
    pub SINGLE_USE_LIFETIMES,
    Allow,
    "detects lifetime parameters that are only used once"
}

declare_lint! {
    /// The `unused_lifetimes` lint detects lifetime parameters that are never
    /// used.
    ///
    /// ### Example
    ///
    /// ```rust,compile_fail
    /// #[deny(unused_lifetimes)]
    ///
    /// pub fn foo<'a>() {}
    /// ```
    ///
    /// {{produces}}
    ///
    /// ### Explanation
    ///
    /// Unused lifetime parameters may signal a mistake or unfinished code.
    /// Consider removing the parameter.
    pub UNUSED_LIFETIMES,
    Allow,
    "detects lifetime parameters that are never used"
}

declare_lint! {
    /// The `redundant_lifetimes` lint detects lifetime parameters that are
    /// redundant because they are equal to another named lifetime.
    ///
    /// ### Example
    ///
    /// ```rust,compile_fail
    /// #[deny(redundant_lifetimes)]
    ///
    /// // `'a = 'static`, so all usages of `'a` can be replaced with `'static`
    /// pub fn bar<'a: 'static>() {}
    ///
    /// // `'a = 'b`, so all usages of `'b` can be replaced with `'a`
    /// pub fn bar<'a: 'b, 'b: 'a>() {}
    /// ```
    ///
    /// {{produces}}
    ///
    /// ### Explanation
    ///
    /// Unused lifetime parameters may signal a mistake or unfinished code.
    /// Consider removing the parameter.
    pub REDUNDANT_LIFETIMES,
    Allow,
    "detects lifetime parameters that are redundant because they are equal to some other named lifetime"
}

declare_lint! {
    /// The `tyvar_behind_raw_pointer` lint detects raw pointer to an
    /// inference variable.
    ///
    /// ### Example
    ///
    /// ```rust,edition2015
    /// // edition 2015
    /// let data = std::ptr::null();
    /// let _ = &data as *const *const ();
    ///
    /// if data.is_null() {}
    /// ```
    ///
    /// {{produces}}
    ///
    /// ### Explanation
    ///
    /// This kind of inference was previously allowed, but with the future
    /// arrival of [arbitrary self types], this can introduce ambiguity. To
    /// resolve this, use an explicit type instead of relying on type
    /// inference.
    ///
    /// This is a [future-incompatible] lint to transition this to a hard
    /// error in the 2018 edition. See [issue #46906] for more details. This
    /// is currently a hard-error on the 2018 edition, and is "warn" by
    /// default in the 2015 edition.
    ///
    /// [arbitrary self types]: https://github.com/rust-lang/rust/issues/44874
    /// [issue #46906]: https://github.com/rust-lang/rust/issues/46906
    /// [future-incompatible]: ../index.md#future-incompatible-lints
    pub TYVAR_BEHIND_RAW_POINTER,
    Warn,
    "raw pointer to an inference variable",
    @future_incompatible = FutureIncompatibleInfo {
        reason: FutureIncompatibilityReason::EditionError(Edition::Edition2018),
        reference: "issue #46906 <https://github.com/rust-lang/rust/issues/46906>",
    };
}

declare_lint! {
    /// The `elided_lifetimes_in_paths` lint detects the use of hidden
    /// lifetime parameters.
    ///
    /// ### Example
    ///
    /// ```rust,compile_fail
    /// #![deny(elided_lifetimes_in_paths)]
    /// #![deny(warnings)]
    /// struct Foo<'a> {
    ///     x: &'a u32
    /// }
    ///
    /// fn foo(x: &Foo) {
    /// }
    /// ```
    ///
    /// {{produces}}
    ///
    /// ### Explanation
    ///
    /// Elided lifetime parameters can make it difficult to see at a glance
    /// that borrowing is occurring. This lint ensures that lifetime
    /// parameters are always explicitly stated, even if it is the `'_`
    /// [placeholder lifetime].
    ///
    /// This lint is "allow" by default because it has some known issues, and
    /// may require a significant transition for old code.
    ///
    /// [placeholder lifetime]: https://doc.rust-lang.org/reference/lifetime-elision.html#lifetime-elision-in-functions
    pub ELIDED_LIFETIMES_IN_PATHS,
    Allow,
    "hidden lifetime parameters in types are deprecated"
}

declare_lint! {
    /// The `bare_trait_objects` lint suggests using `dyn Trait` for trait
    /// objects.
    ///
    /// ### Example
    ///
    /// ```rust,edition2018
    /// trait Trait { }
    ///
    /// fn takes_trait_object(_: Box<Trait>) {
    /// }
    /// ```
    ///
    /// {{produces}}
    ///
    /// ### Explanation
    ///
    /// Without the `dyn` indicator, it can be ambiguous or confusing when
    /// reading code as to whether or not you are looking at a trait object.
    /// The `dyn` keyword makes it explicit, and adds a symmetry to contrast
    /// with [`impl Trait`].
    ///
    /// [`impl Trait`]: https://doc.rust-lang.org/book/ch10-02-traits.html#traits-as-parameters
    pub BARE_TRAIT_OBJECTS,
    Warn,
    "suggest using `dyn Trait` for trait objects",
    @future_incompatible = FutureIncompatibleInfo {
        reason: FutureIncompatibilityReason::EditionError(Edition::Edition2021),
        reference: "<https://doc.rust-lang.org/edition-guide/rust-2021/warnings-promoted-to-error.html>",
    };
}

declare_lint! {
    /// The `absolute_paths_not_starting_with_crate` lint detects fully
    /// qualified paths that start with a module name instead of `crate`,
    /// `self`, or an extern crate name
    ///
    /// ### Example
    ///
    /// ```rust,edition2015,compile_fail
    /// #![deny(absolute_paths_not_starting_with_crate)]
    ///
    /// mod foo {
    ///     pub fn bar() {}
    /// }
    ///
    /// fn main() {
    ///     ::foo::bar();
    /// }
    /// ```
    ///
    /// {{produces}}
    ///
    /// ### Explanation
    ///
    /// Rust [editions] allow the language to evolve without breaking
    /// backwards compatibility. This lint catches code that uses absolute
    /// paths in the style of the 2015 edition. In the 2015 edition, absolute
    /// paths (those starting with `::`) refer to either the crate root or an
    /// external crate. In the 2018 edition it was changed so that they only
    /// refer to external crates. The path prefix `crate::` should be used
    /// instead to reference items from the crate root.
    ///
    /// If you switch the compiler from the 2015 to 2018 edition without
    /// updating the code, then it will fail to compile if the old style paths
    /// are used. You can manually change the paths to use the `crate::`
    /// prefix to transition to the 2018 edition.
    ///
    /// This lint solves the problem automatically. It is "allow" by default
    /// because the code is perfectly valid in the 2015 edition. The [`cargo
    /// fix`] tool with the `--edition` flag will switch this lint to "warn"
    /// and automatically apply the suggested fix from the compiler. This
    /// provides a completely automated way to update old code to the 2018
    /// edition.
    ///
    /// [editions]: https://doc.rust-lang.org/edition-guide/
    /// [`cargo fix`]: https://doc.rust-lang.org/cargo/commands/cargo-fix.html
    pub ABSOLUTE_PATHS_NOT_STARTING_WITH_CRATE,
    Allow,
    "fully qualified paths that start with a module name \
     instead of `crate`, `self`, or an extern crate name",
     @future_incompatible = FutureIncompatibleInfo {
        reason: FutureIncompatibilityReason::EditionError(Edition::Edition2018),
        reference: "issue #53130 <https://github.com/rust-lang/rust/issues/53130>",
     };
}

declare_lint! {
    /// The `unstable_name_collisions` lint detects that you have used a name
    /// that the standard library plans to add in the future.
    ///
    /// ### Example
    ///
    /// ```rust
    /// trait MyIterator : Iterator {
    ///     // is_partitioned is an unstable method that already exists on the Iterator trait
    ///     fn is_partitioned<P>(self, predicate: P) -> bool
    ///     where
    ///         Self: Sized,
    ///         P: FnMut(Self::Item) -> bool,
    ///     {true}
    /// }
    ///
    /// impl<T: ?Sized> MyIterator for T where T: Iterator { }
    ///
    /// let x = vec![1, 2, 3];
    /// let _ = x.iter().is_partitioned(|_| true);
    /// ```
    ///
    /// {{produces}}
    ///
    /// ### Explanation
    ///
    /// When new methods are added to traits in the standard library, they are
    /// usually added in an "unstable" form which is only available on the
    /// [nightly channel] with a [`feature` attribute]. If there is any
    /// preexisting code which extends a trait to have a method with the same
    /// name, then the names will collide. In the future, when the method is
    /// stabilized, this will cause an error due to the ambiguity. This lint
    /// is an early-warning to let you know that there may be a collision in
    /// the future. This can be avoided by adding type annotations to
    /// disambiguate which trait method you intend to call, such as
    /// `MyIterator::is_partitioned(my_iter, my_predicate)` or renaming or removing the method.
    ///
    /// [nightly channel]: https://doc.rust-lang.org/book/appendix-07-nightly-rust.html
    /// [`feature` attribute]: https://doc.rust-lang.org/nightly/unstable-book/
    pub UNSTABLE_NAME_COLLISIONS,
    Warn,
    "detects name collision with an existing but unstable method",
    @future_incompatible = FutureIncompatibleInfo {
        reason: FutureIncompatibilityReason::Custom(
            "once this associated item is added to the standard library, \
             the ambiguity may cause an error or change in behavior!"
        ),
        reference: "issue #48919 <https://github.com/rust-lang/rust/issues/48919>",
        // Note: this item represents future incompatibility of all unstable functions in the
        //       standard library, and thus should never be removed or changed to an error.
    };
}

declare_lint! {
    /// The `irrefutable_let_patterns` lint detects [irrefutable patterns]
    /// in [`if let`]s, [`while let`]s, and `if let` guards.
    ///
    /// ### Example
    ///
    /// ```rust
    /// if let _ = 123 {
    ///     println!("always runs!");
    /// }
    /// ```
    ///
    /// {{produces}}
    ///
    /// ### Explanation
    ///
    /// There usually isn't a reason to have an irrefutable pattern in an
    /// `if let` or `while let` statement, because the pattern will always match
    /// successfully. A [`let`] or [`loop`] statement will suffice. However,
    /// when generating code with a macro, forbidding irrefutable patterns
    /// would require awkward workarounds in situations where the macro
    /// doesn't know if the pattern is refutable or not. This lint allows
    /// macros to accept this form, while alerting for a possibly incorrect
    /// use in normal code.
    ///
    /// See [RFC 2086] for more details.
    ///
    /// [irrefutable patterns]: https://doc.rust-lang.org/reference/patterns.html#refutability
    /// [`if let`]: https://doc.rust-lang.org/reference/expressions/if-expr.html#if-let-expressions
    /// [`while let`]: https://doc.rust-lang.org/reference/expressions/loop-expr.html#predicate-pattern-loops
    /// [`let`]: https://doc.rust-lang.org/reference/statements.html#let-statements
    /// [`loop`]: https://doc.rust-lang.org/reference/expressions/loop-expr.html#infinite-loops
    /// [RFC 2086]: https://github.com/rust-lang/rfcs/blob/master/text/2086-allow-if-let-irrefutables.md
    pub IRREFUTABLE_LET_PATTERNS,
    Warn,
    "detects irrefutable patterns in `if let` and `while let` statements"
}

declare_lint! {
    /// The `unused_labels` lint detects [labels] that are never used.
    ///
    /// [labels]: https://doc.rust-lang.org/reference/expressions/loop-expr.html#loop-labels
    ///
    /// ### Example
    ///
    /// ```rust,no_run
    /// 'unused_label: loop {}
    /// ```
    ///
    /// {{produces}}
    ///
    /// ### Explanation
    ///
    /// Unused labels may signal a mistake or unfinished code. To silence the
    /// warning for the individual label, prefix it with an underscore such as
    /// `'_my_label:`.
    pub UNUSED_LABELS,
    Warn,
    "detects labels that are never used"
}

declare_lint! {
    /// The `proc_macro_derive_resolution_fallback` lint detects proc macro
    /// derives using inaccessible names from parent modules.
    ///
    /// ### Example
    ///
    /// ```rust,ignore (proc-macro)
    /// // foo.rs
    /// #![crate_type = "proc-macro"]
    ///
    /// extern crate proc_macro;
    ///
    /// use proc_macro::*;
    ///
    /// #[proc_macro_derive(Foo)]
    /// pub fn foo1(a: TokenStream) -> TokenStream {
    ///     drop(a);
    ///     "mod __bar { static mut BAR: Option<Something> = None; }".parse().unwrap()
    /// }
    /// ```
    ///
    /// ```rust,ignore (needs-dependency)
    /// // bar.rs
    /// #[macro_use]
    /// extern crate foo;
    ///
    /// struct Something;
    ///
    /// #[derive(Foo)]
    /// struct Another;
    ///
    /// fn main() {}
    /// ```
    ///
    /// This will produce:
    ///
    /// ```text
    /// warning: cannot find type `Something` in this scope
    ///  --> src/main.rs:8:10
    ///   |
    /// 8 | #[derive(Foo)]
    ///   |          ^^^ names from parent modules are not accessible without an explicit import
    ///   |
    ///   = note: `#[warn(proc_macro_derive_resolution_fallback)]` on by default
    ///   = warning: this was previously accepted by the compiler but is being phased out; it will become a hard error in a future release!
    ///   = note: for more information, see issue #50504 <https://github.com/rust-lang/rust/issues/50504>
    /// ```
    ///
    /// ### Explanation
    ///
    /// If a proc-macro generates a module, the compiler unintentionally
    /// allowed items in that module to refer to items in the crate root
    /// without importing them. This is a [future-incompatible] lint to
    /// transition this to a hard error in the future. See [issue #50504] for
    /// more details.
    ///
    /// [issue #50504]: https://github.com/rust-lang/rust/issues/50504
    /// [future-incompatible]: ../index.md#future-incompatible-lints
    pub PROC_MACRO_DERIVE_RESOLUTION_FALLBACK,
    Deny,
    "detects proc macro derives using inaccessible names from parent modules",
    @future_incompatible = FutureIncompatibleInfo {
        reason: FutureIncompatibilityReason::FutureReleaseError,
        reference: "issue #83583 <https://github.com/rust-lang/rust/issues/83583>",
        report_in_deps: true,
    };
}

declare_lint! {
    /// The `macro_use_extern_crate` lint detects the use of the [`macro_use` attribute].
    ///
    /// ### Example
    ///
    /// ```rust,ignore (needs extern crate)
    /// #![deny(macro_use_extern_crate)]
    ///
    /// #[macro_use]
    /// extern crate serde_json;
    ///
    /// fn main() {
    ///     let _ = json!{{}};
    /// }
    /// ```
    ///
    /// This will produce:
    ///
    /// ```text
    /// error: applying the `#[macro_use]` attribute to an `extern crate` item is deprecated
    ///  --> src/main.rs:3:1
    ///   |
    /// 3 | #[macro_use]
    ///   | ^^^^^^^^^^^^
    ///   |
    ///   = help: remove it and import macros at use sites with a `use` item instead
    /// note: the lint level is defined here
    ///  --> src/main.rs:1:9
    ///   |
    /// 1 | #![deny(macro_use_extern_crate)]
    ///   |         ^^^^^^^^^^^^^^^^^^^^^^
    /// ```
    ///
    /// ### Explanation
    ///
    /// The [`macro_use` attribute] on an [`extern crate`] item causes
    /// macros in that external crate to be brought into the prelude of the
    /// crate, making the macros in scope everywhere. As part of the efforts
    /// to simplify handling of dependencies in the [2018 edition], the use of
    /// `extern crate` is being phased out. To bring macros from extern crates
    /// into scope, it is recommended to use a [`use` import].
    ///
    /// This lint is "allow" by default because this is a stylistic choice
    /// that has not been settled, see [issue #52043] for more information.
    ///
    /// [`macro_use` attribute]: https://doc.rust-lang.org/reference/macros-by-example.html#the-macro_use-attribute
    /// [`use` import]: https://doc.rust-lang.org/reference/items/use-declarations.html
    /// [issue #52043]: https://github.com/rust-lang/rust/issues/52043
    pub MACRO_USE_EXTERN_CRATE,
    Allow,
    "the `#[macro_use]` attribute is now deprecated in favor of using macros \
     via the module system"
}

declare_lint! {
    /// The `macro_expanded_macro_exports_accessed_by_absolute_paths` lint
    /// detects macro-expanded [`macro_export`] macros from the current crate
    /// that cannot be referred to by absolute paths.
    ///
    /// [`macro_export`]: https://doc.rust-lang.org/reference/macros-by-example.html#path-based-scope
    ///
    /// ### Example
    ///
    /// ```rust,compile_fail
    /// macro_rules! define_exported {
    ///     () => {
    ///         #[macro_export]
    ///         macro_rules! exported {
    ///             () => {};
    ///         }
    ///     };
    /// }
    ///
    /// define_exported!();
    ///
    /// fn main() {
    ///     crate::exported!();
    /// }
    /// ```
    ///
    /// {{produces}}
    ///
    /// ### Explanation
    ///
    /// The intent is that all macros marked with the `#[macro_export]`
    /// attribute are made available in the root of the crate. However, when a
    /// `macro_rules!` definition is generated by another macro, the macro
    /// expansion is unable to uphold this rule. This is a
    /// [future-incompatible] lint to transition this to a hard error in the
    /// future. See [issue #53495] for more details.
    ///
    /// [issue #53495]: https://github.com/rust-lang/rust/issues/53495
    /// [future-incompatible]: ../index.md#future-incompatible-lints
    pub MACRO_EXPANDED_MACRO_EXPORTS_ACCESSED_BY_ABSOLUTE_PATHS,
    Deny,
    "macro-expanded `macro_export` macros from the current crate \
     cannot be referred to by absolute paths",
    @future_incompatible = FutureIncompatibleInfo {
        reason: FutureIncompatibilityReason::FutureReleaseError,
        reference: "issue #52234 <https://github.com/rust-lang/rust/issues/52234>",
        report_in_deps: true,
    };
    crate_level_only
}

declare_lint! {
    /// The `explicit_outlives_requirements` lint detects unnecessary
    /// lifetime bounds that can be inferred.
    ///
    /// ### Example
    ///
    /// ```rust,compile_fail
    /// # #![allow(unused)]
    /// #![deny(explicit_outlives_requirements)]
    /// #![deny(warnings)]
    ///
    /// struct SharedRef<'a, T>
    /// where
    ///     T: 'a,
    /// {
    ///     data: &'a T,
    /// }
    /// ```
    ///
    /// {{produces}}
    ///
    /// ### Explanation
    ///
    /// If a `struct` contains a reference, such as `&'a T`, the compiler
    /// requires that `T` outlives the lifetime `'a`. This historically
    /// required writing an explicit lifetime bound to indicate this
    /// requirement. However, this can be overly explicit, causing clutter and
    /// unnecessary complexity. The language was changed to automatically
    /// infer the bound if it is not specified. Specifically, if the struct
    /// contains a reference, directly or indirectly, to `T` with lifetime
    /// `'x`, then it will infer that `T: 'x` is a requirement.
    ///
    /// This lint is "allow" by default because it can be noisy for existing
    /// code that already had these requirements. This is a stylistic choice,
    /// as it is still valid to explicitly state the bound. It also has some
    /// false positives that can cause confusion.
    ///
    /// See [RFC 2093] for more details.
    ///
    /// [RFC 2093]: https://github.com/rust-lang/rfcs/blob/master/text/2093-infer-outlives.md
    pub EXPLICIT_OUTLIVES_REQUIREMENTS,
    Allow,
    "outlives requirements can be inferred"
}

declare_lint! {
    /// The `deprecated_in_future` lint is internal to rustc and should not be
    /// used by user code.
    ///
    /// This lint is only enabled in the standard library. It works with the
    /// use of `#[deprecated]` with a `since` field of a version in the future.
    /// This allows something to be marked as deprecated in a future version,
    /// and then this lint will ensure that the item is no longer used in the
    /// standard library. See the [stability documentation] for more details.
    ///
    /// [stability documentation]: https://rustc-dev-guide.rust-lang.org/stability.html#deprecated
    pub DEPRECATED_IN_FUTURE,
    Allow,
    "detects use of items that will be deprecated in a future version",
    report_in_external_macro
}

declare_lint! {
    /// The `ambiguous_associated_items` lint detects ambiguity between
    /// [associated items] and [enum variants].
    ///
    /// [associated items]: https://doc.rust-lang.org/reference/items/associated-items.html
    /// [enum variants]: https://doc.rust-lang.org/reference/items/enumerations.html
    ///
    /// ### Example
    ///
    /// ```rust,compile_fail
    /// enum E {
    ///     V
    /// }
    ///
    /// trait Tr {
    ///     type V;
    ///     fn foo() -> Self::V;
    /// }
    ///
    /// impl Tr for E {
    ///     type V = u8;
    ///     // `Self::V` is ambiguous because it may refer to the associated type or
    ///     // the enum variant.
    ///     fn foo() -> Self::V { 0 }
    /// }
    /// ```
    ///
    /// {{produces}}
    ///
    /// ### Explanation
    ///
    /// Previous versions of Rust did not allow accessing enum variants
    /// through [type aliases]. When this ability was added (see [RFC 2338]), this
    /// introduced some situations where it can be ambiguous what a type
    /// was referring to.
    ///
    /// To fix this ambiguity, you should use a [qualified path] to explicitly
    /// state which type to use. For example, in the above example the
    /// function can be written as `fn f() -> <Self as Tr>::V { 0 }` to
    /// specifically refer to the associated type.
    ///
    /// This is a [future-incompatible] lint to transition this to a hard
    /// error in the future. See [issue #57644] for more details.
    ///
    /// [issue #57644]: https://github.com/rust-lang/rust/issues/57644
    /// [type aliases]: https://doc.rust-lang.org/reference/items/type-aliases.html#type-aliases
    /// [RFC 2338]: https://github.com/rust-lang/rfcs/blob/master/text/2338-type-alias-enum-variants.md
    /// [qualified path]: https://doc.rust-lang.org/reference/paths.html#qualified-paths
    /// [future-incompatible]: ../index.md#future-incompatible-lints
    pub AMBIGUOUS_ASSOCIATED_ITEMS,
    Deny,
    "ambiguous associated items",
    @future_incompatible = FutureIncompatibleInfo {
        reason: FutureIncompatibilityReason::FutureReleaseError,
        reference: "issue #57644 <https://github.com/rust-lang/rust/issues/57644>",
    };
}

declare_lint! {
    /// The `soft_unstable` lint detects unstable features that were unintentionally allowed on
    /// stable. This is a [future-incompatible] lint to transition this to a hard error in the
    /// future. See [issue #64266] for more details.
    ///
    /// [issue #64266]: https://github.com/rust-lang/rust/issues/64266
    /// [future-incompatible]: ../index.md#future-incompatible-lints
    pub SOFT_UNSTABLE,
    Deny,
    "a feature gate that doesn't break dependent crates",
    @future_incompatible = FutureIncompatibleInfo {
        reason: FutureIncompatibilityReason::FutureReleaseError,
        reference: "issue #64266 <https://github.com/rust-lang/rust/issues/64266>",
        report_in_deps: true,
    };
}

declare_lint! {
    /// The `inline_no_sanitize` lint detects incompatible use of
    /// [`#[inline(always)]`][inline] and [`#[sanitize(xyz = "off")]`][sanitize].
    ///
    /// [inline]: https://doc.rust-lang.org/reference/attributes/codegen.html#the-inline-attribute
    /// [sanitize]: https://doc.rust-lang.org/nightly/unstable-book/language-features/no-sanitize.html
    ///
    /// ### Example
    ///
    /// ```rust
    /// #![feature(sanitize)]
    ///
    /// #[inline(always)]
    /// #[sanitize(address = "off")]
    /// fn x() {}
    ///
    /// fn main() {
    ///     x()
    /// }
    /// ```
    ///
    /// {{produces}}
    ///
    /// ### Explanation
    ///
    /// The use of the [`#[inline(always)]`][inline] attribute prevents the
    /// the [`#[sanitize(xyz = "off")]`][sanitize] attribute from working.
    /// Consider temporarily removing `inline` attribute.
    pub INLINE_NO_SANITIZE,
    Warn,
    r#"detects incompatible use of `#[inline(always)]` and `#[sanitize(... = "off")]`"#,
}

declare_lint! {
    /// The `rtsan_nonblocking_async` lint detects incompatible use of
    /// [`#[sanitize(realtime = "nonblocking")]`][sanitize] on async functions.
    ///
    /// [sanitize]: https://doc.rust-lang.org/nightly/unstable-book/language-features/no-sanitize.html
    /// ### Example
    ///
    #[cfg_attr(bootstrap, doc = "```ignore")]
    #[cfg_attr(not(bootstrap), doc = "```rust,no_run")]
    /// #![feature(sanitize)]
    ///
    /// #[sanitize(realtime = "nonblocking")]
    /// async fn x() {}
    ///
    /// fn main() {
    ///     x();
    /// }
    #[cfg_attr(bootstrap, doc = "```")]
    #[cfg_attr(not(bootstrap), doc = "```")]
    ///
    /// {{produces}}
    ///
    /// ### Explanation
    ///
    /// The sanitizer only considers the async function body nonblocking. The executor, which runs on
    /// every `.await` point can run non-realtime code, without the sanitizer catching it.
    pub RTSAN_NONBLOCKING_ASYNC,
    Warn,
    r#"detects incompatible uses of `#[sanitize(realtime = "nonblocking")]` on async functions"#,
}

declare_lint! {
    /// The `asm_sub_register` lint detects using only a subset of a register
    /// for inline asm inputs.
    ///
    /// ### Example
    ///
    /// ```rust,ignore (fails on non-x86_64)
    /// #[cfg(target_arch="x86_64")]
    /// use std::arch::asm;
    ///
    /// fn main() {
    ///     #[cfg(target_arch="x86_64")]
    ///     unsafe {
    ///         asm!("mov {0}, {0}", in(reg) 0i16);
    ///     }
    /// }
    /// ```
    ///
    /// This will produce:
    ///
    /// ```text
    /// warning: formatting may not be suitable for sub-register argument
    ///  --> src/main.rs:7:19
    ///   |
    /// 7 |         asm!("mov {0}, {0}", in(reg) 0i16);
    ///   |                   ^^^  ^^^           ---- for this argument
    ///   |
    ///   = note: `#[warn(asm_sub_register)]` on by default
    ///   = help: use the `x` modifier to have the register formatted as `ax`
    ///   = help: or use the `r` modifier to keep the default formatting of `rax`
    /// ```
    ///
    /// ### Explanation
    ///
    /// Registers on some architectures can use different names to refer to a
    /// subset of the register. By default, the compiler will use the name for
    /// the full register size. To explicitly use a subset of the register,
    /// you can override the default by using a modifier on the template
    /// string operand to specify when subregister to use. This lint is issued
    /// if you pass in a value with a smaller data type than the default
    /// register size, to alert you of possibly using the incorrect width. To
    /// fix this, add the suggested modifier to the template, or cast the
    /// value to the correct size.
    ///
    /// See [register template modifiers] in the reference for more details.
    ///
    /// [register template modifiers]: https://doc.rust-lang.org/nightly/reference/inline-assembly.html#template-modifiers
    pub ASM_SUB_REGISTER,
    Warn,
    "using only a subset of a register for inline asm inputs",
}

declare_lint! {
    /// The `bad_asm_style` lint detects the use of the `.intel_syntax` and
    /// `.att_syntax` directives.
    ///
    /// ### Example
    ///
    /// ```rust,ignore (fails on non-x86_64)
    /// #[cfg(target_arch="x86_64")]
    /// use std::arch::asm;
    ///
    /// fn main() {
    ///     #[cfg(target_arch="x86_64")]
    ///     unsafe {
    ///         asm!(
    ///             ".att_syntax",
    ///             "movq %{0}, %{0}", in(reg) 0usize
    ///         );
    ///     }
    /// }
    /// ```
    ///
    /// This will produce:
    ///
    /// ```text
    /// warning: avoid using `.att_syntax`, prefer using `options(att_syntax)` instead
    ///  --> src/main.rs:8:14
    ///   |
    /// 8 |             ".att_syntax",
    ///   |              ^^^^^^^^^^^
    ///   |
    ///   = note: `#[warn(bad_asm_style)]` on by default
    /// ```
    ///
    /// ### Explanation
    ///
    /// On x86, `asm!` uses the intel assembly syntax by default. While this
    /// can be switched using assembler directives like `.att_syntax`, using the
    /// `att_syntax` option is recommended instead because it will also properly
    /// prefix register placeholders with `%` as required by AT&T syntax.
    pub BAD_ASM_STYLE,
    Warn,
    "incorrect use of inline assembly",
}

declare_lint! {
    /// The `unsafe_op_in_unsafe_fn` lint detects unsafe operations in unsafe
    /// functions without an explicit unsafe block.
    ///
    /// ### Example
    ///
    /// ```rust,compile_fail
    /// #![deny(unsafe_op_in_unsafe_fn)]
    ///
    /// unsafe fn foo() {}
    ///
    /// unsafe fn bar() {
    ///     foo();
    /// }
    ///
    /// fn main() {}
    /// ```
    ///
    /// {{produces}}
    ///
    /// ### Explanation
    ///
    /// Currently, an [`unsafe fn`] allows any [unsafe] operation within its
    /// body. However, this can increase the surface area of code that needs
    /// to be scrutinized for proper behavior. The [`unsafe` block] provides a
    /// convenient way to make it clear exactly which parts of the code are
    /// performing unsafe operations. In the future, it is desired to change
    /// it so that unsafe operations cannot be performed in an `unsafe fn`
    /// without an `unsafe` block.
    ///
    /// The fix to this is to wrap the unsafe code in an `unsafe` block.
    ///
    /// This lint is "allow" by default on editions up to 2021, from 2024 it is
    /// "warn" by default; the plan for increasing severity further is
    /// still being considered. See [RFC #2585] and [issue #71668] for more
    /// details.
    ///
    /// [`unsafe fn`]: https://doc.rust-lang.org/reference/unsafe-functions.html
    /// [`unsafe` block]: https://doc.rust-lang.org/reference/expressions/block-expr.html#unsafe-blocks
    /// [unsafe]: https://doc.rust-lang.org/reference/unsafety.html
    /// [RFC #2585]: https://github.com/rust-lang/rfcs/blob/master/text/2585-unsafe-block-in-unsafe-fn.md
    /// [issue #71668]: https://github.com/rust-lang/rust/issues/71668
    pub UNSAFE_OP_IN_UNSAFE_FN,
    Allow,
    "unsafe operations in unsafe functions without an explicit unsafe block are deprecated",
    @future_incompatible = FutureIncompatibleInfo {
        reason: FutureIncompatibilityReason::EditionSemanticsChange(Edition::Edition2024),
        reference: "<https://doc.rust-lang.org/edition-guide/rust-2024/unsafe-op-in-unsafe-fn.html>",
        explain_reason: false
    };
    @edition Edition2024 => Warn;
}

declare_lint! {
    /// The `fuzzy_provenance_casts` lint detects an `as` cast between an integer
    /// and a pointer.
    ///
    /// ### Example
    ///
    /// ```rust
    /// #![feature(strict_provenance_lints)]
    /// #![warn(fuzzy_provenance_casts)]
    ///
    /// fn main() {
    ///     let _dangling = 16_usize as *const u8;
    /// }
    /// ```
    ///
    /// {{produces}}
    ///
    /// ### Explanation
    ///
    /// This lint is part of the strict provenance effort, see [issue #95228].
    /// Casting an integer to a pointer is considered bad style, as a pointer
    /// contains, besides the *address* also a *provenance*, indicating what
    /// memory the pointer is allowed to read/write. Casting an integer, which
    /// doesn't have provenance, to a pointer requires the compiler to assign
    /// (guess) provenance. The compiler assigns "all exposed valid" (see the
    /// docs of [`ptr::with_exposed_provenance`] for more information about this
    /// "exposing"). This penalizes the optimiser and is not well suited for
    /// dynamic analysis/dynamic program verification (e.g. Miri or CHERI
    /// platforms).
    ///
    /// It is much better to use [`ptr::with_addr`] instead to specify the
    /// provenance you want. If using this function is not possible because the
    /// code relies on exposed provenance then there is as an escape hatch
    /// [`ptr::with_exposed_provenance`].
    ///
    /// [issue #95228]: https://github.com/rust-lang/rust/issues/95228
    /// [`ptr::with_addr`]: https://doc.rust-lang.org/core/primitive.pointer.html#method.with_addr
    /// [`ptr::with_exposed_provenance`]: https://doc.rust-lang.org/core/ptr/fn.with_exposed_provenance.html
    pub FUZZY_PROVENANCE_CASTS,
    Allow,
    "a fuzzy integer to pointer cast is used",
    @feature_gate = strict_provenance_lints;
}

declare_lint! {
    /// The `lossy_provenance_casts` lint detects an `as` cast between a pointer
    /// and an integer.
    ///
    /// ### Example
    ///
    /// ```rust
    /// #![feature(strict_provenance_lints)]
    /// #![warn(lossy_provenance_casts)]
    ///
    /// fn main() {
    ///     let x: u8 = 37;
    ///     let _addr: usize = &x as *const u8 as usize;
    /// }
    /// ```
    ///
    /// {{produces}}
    ///
    /// ### Explanation
    ///
    /// This lint is part of the strict provenance effort, see [issue #95228].
    /// Casting a pointer to an integer is a lossy operation, because beyond
    /// just an *address* a pointer may be associated with a particular
    /// *provenance*. This information is used by the optimiser and for dynamic
    /// analysis/dynamic program verification (e.g. Miri or CHERI platforms).
    ///
    /// Since this cast is lossy, it is considered good style to use the
    /// [`ptr::addr`] method instead, which has a similar effect, but doesn't
    /// "expose" the pointer provenance. This improves optimisation potential.
    /// See the docs of [`ptr::addr`] and [`ptr::expose_provenance`] for more information
    /// about exposing pointer provenance.
    ///
    /// If your code can't comply with strict provenance and needs to expose
    /// the provenance, then there is [`ptr::expose_provenance`] as an escape hatch,
    /// which preserves the behaviour of `as usize` casts while being explicit
    /// about the semantics.
    ///
    /// [issue #95228]: https://github.com/rust-lang/rust/issues/95228
    /// [`ptr::addr`]: https://doc.rust-lang.org/core/primitive.pointer.html#method.addr
    /// [`ptr::expose_provenance`]: https://doc.rust-lang.org/core/primitive.pointer.html#method.expose_provenance
    pub LOSSY_PROVENANCE_CASTS,
    Allow,
    "a lossy pointer to integer cast is used",
    @feature_gate = strict_provenance_lints;
}

declare_lint! {
    /// The `const_evaluatable_unchecked` lint detects a generic constant used
    /// in a type.
    ///
    /// ### Example
    ///
    /// ```rust
    /// const fn foo<T>() -> usize {
    ///     if size_of::<*mut T>() < 8 { // size of *mut T does not depend on T
    ///         4
    ///     } else {
    ///         8
    ///     }
    /// }
    ///
    /// fn test<T>() {
    ///     let _ = [0; foo::<T>()];
    /// }
    /// ```
    ///
    /// {{produces}}
    ///
    /// ### Explanation
    ///
    /// In the 1.43 release, some uses of generic parameters in array repeat
    /// expressions were accidentally allowed. This is a [future-incompatible]
    /// lint to transition this to a hard error in the future. See [issue
    /// #76200] for a more detailed description and possible fixes.
    ///
    /// [future-incompatible]: ../index.md#future-incompatible-lints
    /// [issue #76200]: https://github.com/rust-lang/rust/issues/76200
    pub CONST_EVALUATABLE_UNCHECKED,
    Warn,
    "detects a generic constant is used in a type without a emitting a warning",
    @future_incompatible = FutureIncompatibleInfo {
        reason: FutureIncompatibilityReason::FutureReleaseError,
        reference: "issue #76200 <https://github.com/rust-lang/rust/issues/76200>",
    };
}

declare_lint! {
    /// The `function_item_references` lint detects function references that are
    /// formatted with [`fmt::Pointer`] or transmuted.
    ///
    /// [`fmt::Pointer`]: https://doc.rust-lang.org/std/fmt/trait.Pointer.html
    ///
    /// ### Example
    ///
    /// ```rust
    /// fn foo() { }
    ///
    /// fn main() {
    ///     println!("{:p}", &foo);
    /// }
    /// ```
    ///
    /// {{produces}}
    ///
    /// ### Explanation
    ///
    /// Taking a reference to a function may be mistaken as a way to obtain a
    /// pointer to that function. This can give unexpected results when
    /// formatting the reference as a pointer or transmuting it. This lint is
    /// issued when function references are formatted as pointers, passed as
    /// arguments bound by [`fmt::Pointer`] or transmuted.
    pub FUNCTION_ITEM_REFERENCES,
    Warn,
    "suggest casting to a function pointer when attempting to take references to function items",
}

declare_lint! {
    /// The `uninhabited_static` lint detects uninhabited statics.
    ///
    /// ### Example
    ///
    /// ```rust
    /// enum Void {}
    /// unsafe extern {
    ///     static EXTERN: Void;
    /// }
    /// ```
    ///
    /// {{produces}}
    ///
    /// ### Explanation
    ///
    /// Statics with an uninhabited type can never be initialized, so they are impossible to define.
    /// However, this can be side-stepped with an `extern static`, leading to problems later in the
    /// compiler which assumes that there are no initialized uninhabited places (such as locals or
    /// statics). This was accidentally allowed, but is being phased out.
    pub UNINHABITED_STATIC,
    Warn,
    "uninhabited static",
    @future_incompatible = FutureIncompatibleInfo {
        reason: FutureIncompatibilityReason::FutureReleaseError,
        reference: "issue #74840 <https://github.com/rust-lang/rust/issues/74840>",
    };
}

declare_lint! {
    /// The `unnameable_test_items` lint detects [`#[test]`][test] functions
    /// that are not able to be run by the test harness because they are in a
    /// position where they are not nameable.
    ///
    /// [test]: https://doc.rust-lang.org/reference/attributes/testing.html#the-test-attribute
    ///
    /// ### Example
    ///
    /// ```rust,test
    /// fn main() {
    ///     #[test]
    ///     fn foo() {
    ///         // This test will not fail because it does not run.
    ///         assert_eq!(1, 2);
    ///     }
    /// }
    /// ```
    ///
    /// {{produces}}
    ///
    /// ### Explanation
    ///
    /// In order for the test harness to run a test, the test function must be
    /// located in a position where it can be accessed from the crate root.
    /// This generally means it must be defined in a module, and not anywhere
    /// else such as inside another function. The compiler previously allowed
    /// this without an error, so a lint was added as an alert that a test is
    /// not being used. Whether or not this should be allowed has not yet been
    /// decided, see [RFC 2471] and [issue #36629].
    ///
    /// [RFC 2471]: https://github.com/rust-lang/rfcs/pull/2471#issuecomment-397414443
    /// [issue #36629]: https://github.com/rust-lang/rust/issues/36629
    pub UNNAMEABLE_TEST_ITEMS,
    Warn,
    "detects an item that cannot be named being marked as `#[test_case]`",
    report_in_external_macro
}

declare_lint! {
    /// The `useless_deprecated` lint detects deprecation attributes with no effect.
    ///
    /// ### Example
    ///
    /// ```rust,compile_fail
    /// struct X;
    ///
    /// #[deprecated = "message"]
    /// impl Default for X {
    ///     fn default() -> Self {
    ///         X
    ///     }
    /// }
    /// ```
    ///
    /// {{produces}}
    ///
    /// ### Explanation
    ///
    /// Deprecation attributes have no effect on trait implementations.
    pub USELESS_DEPRECATED,
    Deny,
    "detects deprecation attributes with no effect",
}

declare_lint! {
    /// The `ineffective_unstable_trait_impl` lint detects `#[unstable]` attributes which are not used.
    ///
    /// ### Example
    ///
    /// ```rust,compile_fail
    /// #![feature(staged_api)]
    ///
    /// #[derive(Clone)]
    /// #[stable(feature = "x", since = "1")]
    /// struct S {}
    ///
    /// #[unstable(feature = "y", issue = "none")]
    /// impl Copy for S {}
    /// ```
    ///
    /// {{produces}}
    ///
    /// ### Explanation
    ///
    /// `staged_api` does not currently support using a stability attribute on `impl` blocks.
    /// `impl`s are always stable if both the type and trait are stable, and always unstable otherwise.
    pub INEFFECTIVE_UNSTABLE_TRAIT_IMPL,
    Deny,
    "detects `#[unstable]` on stable trait implementations for stable types"
}

declare_lint! {
    /// The `self_constructor_from_outer_item` lint detects cases where the `Self` constructor
    /// was silently allowed due to a bug in the resolver, and which may produce surprising
    /// and unintended behavior.
    ///
    /// Using a `Self` type alias from an outer item was never intended, but was silently allowed.
    /// This is deprecated -- and is a hard error when the `Self` type alias references generics
    /// that are not in scope.
    ///
    /// ### Example
    ///
    /// ```rust,compile_fail
    /// #![deny(self_constructor_from_outer_item)]
    ///
    /// struct S0(usize);
    ///
    /// impl S0 {
    ///     fn foo() {
    ///         const C: S0 = Self(0);
    ///         fn bar() -> S0 {
    ///             Self(0)
    ///         }
    ///     }
    /// }
    /// ```
    ///
    /// {{produces}}
    ///
    /// ### Explanation
    ///
    /// The `Self` type alias should not be reachable because nested items are not associated with
    /// the scope of the parameters from the parent item.
    pub SELF_CONSTRUCTOR_FROM_OUTER_ITEM,
    Warn,
    "detect unsupported use of `Self` from outer item",
    @future_incompatible = FutureIncompatibleInfo {
        reason: FutureIncompatibilityReason::FutureReleaseError,
        reference: "issue #124186 <https://github.com/rust-lang/rust/issues/124186>",
    };
}

declare_lint! {
    /// The `semicolon_in_expressions_from_macros` lint detects trailing semicolons
    /// in macro bodies when the macro is invoked in expression position.
    /// This was previous accepted, but is being phased out.
    ///
    /// ### Example
    ///
    /// ```rust,compile_fail
    /// #![deny(semicolon_in_expressions_from_macros)]
    /// macro_rules! foo {
    ///     () => { true; }
    /// }
    ///
    /// fn main() {
    ///     let val = match true {
    ///         true => false,
    ///         _ => foo!()
    ///     };
    /// }
    /// ```
    ///
    /// {{produces}}
    ///
    /// ### Explanation
    ///
    /// Previous, Rust ignored trailing semicolon in a macro
    /// body when a macro was invoked in expression position.
    /// However, this makes the treatment of semicolons in the language
    /// inconsistent, and could lead to unexpected runtime behavior
    /// in some circumstances (e.g. if the macro author expects
    /// a value to be dropped).
    ///
    /// This is a [future-incompatible] lint to transition this
    /// to a hard error in the future. See [issue #79813] for more details.
    ///
    /// [issue #79813]: https://github.com/rust-lang/rust/issues/79813
    /// [future-incompatible]: ../index.md#future-incompatible-lints
    pub SEMICOLON_IN_EXPRESSIONS_FROM_MACROS,
    Deny,
    "trailing semicolon in macro body used as expression",
    @future_incompatible = FutureIncompatibleInfo {
        reason: FutureIncompatibilityReason::FutureReleaseError,
        reference: "issue #79813 <https://github.com/rust-lang/rust/issues/79813>",
        report_in_deps: true,
    };
}

declare_lint! {
    /// The `legacy_derive_helpers` lint detects derive helper attributes
    /// that are used before they are introduced.
    ///
    /// ### Example
    ///
    /// ```rust,ignore (needs extern crate)
    /// #[serde(rename_all = "camelCase")]
    /// #[derive(Deserialize)]
    /// struct S { /* fields */ }
    /// ```
    ///
    /// produces:
    ///
    /// ```text
    /// warning: derive helper attribute is used before it is introduced
    ///   --> $DIR/legacy-derive-helpers.rs:1:3
    ///    |
    ///  1 | #[serde(rename_all = "camelCase")]
    ///    |   ^^^^^
    /// ...
    ///  2 | #[derive(Deserialize)]
    ///    |          ----------- the attribute is introduced here
    /// ```
    ///
    /// ### Explanation
    ///
    /// Attributes like this work for historical reasons, but attribute expansion works in
    /// left-to-right order in general, so, to resolve `#[serde]`, compiler has to try to "look
    /// into the future" at not yet expanded part of the item , but such attempts are not always
    /// reliable.
    ///
    /// To fix the warning place the helper attribute after its corresponding derive.
    /// ```rust,ignore (needs extern crate)
    /// #[derive(Deserialize)]
    /// #[serde(rename_all = "camelCase")]
    /// struct S { /* fields */ }
    /// ```
    pub LEGACY_DERIVE_HELPERS,
    Deny,
    "detects derive helper attributes that are used before they are introduced",
    @future_incompatible = FutureIncompatibleInfo {
        reason: FutureIncompatibilityReason::FutureReleaseError,
        reference: "issue #79202 <https://github.com/rust-lang/rust/issues/79202>",
        report_in_deps: true,
    };
}

declare_lint! {
    /// The `large_assignments` lint detects when objects of large
    /// types are being moved around.
    ///
    /// ### Example
    ///
    /// ```rust,ignore (can crash on some platforms)
    /// let x = [0; 50000];
    /// let y = x;
    /// ```
    ///
    /// produces:
    ///
    /// ```text
    /// warning: moving a large value
    ///   --> $DIR/move-large.rs:1:3
    ///   let y = x;
    ///           - Copied large value here
    /// ```
    ///
    /// ### Explanation
    ///
    /// When using a large type in a plain assignment or in a function
    /// argument, idiomatic code can be inefficient.
    /// Ideally appropriate optimizations would resolve this, but such
    /// optimizations are only done in a best-effort manner.
    /// This lint will trigger on all sites of large moves and thus allow the
    /// user to resolve them in code.
    pub LARGE_ASSIGNMENTS,
    Warn,
    "detects large moves or copies",
}

declare_lint! {
    /// The `unexpected_cfgs` lint detects unexpected conditional compilation conditions.
    ///
    /// ### Example
    ///
    /// ```text
    /// rustc --check-cfg 'cfg()'
    /// ```
    ///
    /// ```rust,ignore (needs command line option)
    /// #[cfg(widnows)]
    /// fn foo() {}
    /// ```
    ///
    /// This will produce:
    ///
    /// ```text
    /// warning: unexpected `cfg` condition name: `widnows`
    ///  --> lint_example.rs:1:7
    ///   |
    /// 1 | #[cfg(widnows)]
    ///   |       ^^^^^^^
    ///   |
    ///   = note: `#[warn(unexpected_cfgs)]` on by default
    /// ```
    ///
    /// ### Explanation
    ///
    /// This lint is only active when [`--check-cfg`][check-cfg] arguments are being
    /// passed to the compiler and triggers whenever an unexpected condition name or value is
    /// used.
    ///
    /// See the [Checking Conditional Configurations][check-cfg] section for more
    /// details.
    ///
    /// See the [Cargo Specifics][unexpected_cfgs_lint_config] section for configuring this lint in
    /// `Cargo.toml`.
    ///
    /// [check-cfg]: https://doc.rust-lang.org/nightly/rustc/check-cfg.html
    /// [unexpected_cfgs_lint_config]: https://doc.rust-lang.org/nightly/rustc/check-cfg/cargo-specifics.html#check-cfg-in-lintsrust-table
    pub UNEXPECTED_CFGS,
    Warn,
    "detects unexpected names and values in `#[cfg]` conditions",
    report_in_external_macro
}

declare_lint! {
    /// The `explicit_builtin_cfgs_in_flags` lint detects builtin cfgs set via the `--cfg` flag.
    ///
    /// ### Example
    ///
    /// ```text
    /// rustc --cfg unix
    /// ```
    ///
    /// ```rust,ignore (needs command line option)
    /// fn main() {}
    /// ```
    ///
    /// This will produce:
    ///
    /// ```text
    /// error: unexpected `--cfg unix` flag
    ///   |
    ///   = note: config `unix` is only supposed to be controlled by `--target`
    ///   = note: manually setting a built-in cfg can and does create incoherent behaviors
    ///   = note: `#[deny(explicit_builtin_cfgs_in_flags)]` on by default
    /// ```
    ///
    /// ### Explanation
    ///
    /// Setting builtin cfgs can and does produce incoherent behavior, it's better to the use
    /// the appropriate `rustc` flag that controls the config. For example setting the `windows`
    /// cfg but on Linux based target.
    pub EXPLICIT_BUILTIN_CFGS_IN_FLAGS,
    Deny,
    "detects builtin cfgs set via the `--cfg`"
}

declare_lint! {
    /// The `repr_transparent_non_zst_fields` lint
    /// detects types marked `#[repr(transparent)]` that (transitively)
    /// contain a type that is not guaranteed to remain a ZST type under all configurations.
    ///
    /// ### Example
    ///
    /// ```rust,ignore (needs external crate)
    /// #![deny(repr_transparent_external_private_fields)]
    /// use foo::NonExhaustiveZst;
    ///
    /// #[repr(C)]
    /// struct CZst([u8; 0]);
    ///
    /// #[repr(transparent)]
    /// struct Bar(u32, ([u32; 0], NonExhaustiveZst));
    /// #[repr(transparent)]
    /// struct Baz(u32, CZst);
    /// ```
    ///
    /// This will produce:
    ///
    /// ```text
    /// error: zero-sized fields in repr(transparent) cannot contain external non-exhaustive types
    ///  --> src/main.rs:5:28
    ///   |
    /// 5 | struct Bar(u32, ([u32; 0], NonExhaustiveZst));
    ///   |                            ^^^^^^^^^^^^^^^^
    ///   |
    /// note: the lint level is defined here
    ///  --> src/main.rs:1:9
    ///   |
    /// 1 | #![deny(repr_transparent_external_private_fields)]
    ///   |         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    ///   = warning: this was previously accepted by the compiler but is being phased out; it will become a hard error in a future release!
    ///   = note: for more information, see issue #78586 <https://github.com/rust-lang/rust/issues/78586>
    ///   = note: this field contains `NonExhaustiveZst`, which is marked with `#[non_exhaustive]`, so it could become non-zero-sized in the future.
    ///
    /// error: zero-sized fields in repr(transparent) cannot contain `#[repr(C)]` types
    ///  --> src/main.rs:5:28
    ///   |
    /// 5 | struct Baz(u32, CZst);
    ///   |                 ^^^^
    ///   = warning: this was previously accepted by the compiler but is being phased out; it will become a hard error in a future release!
    ///   = note: for more information, see issue #78586 <https://github.com/rust-lang/rust/issues/78586>
    ///   = note: this field contains `CZst`, which is a `#[repr(C)]` type, so it is not guaranteed to be zero-sized on all targets.
    /// ```
    ///
    /// ### Explanation
    ///
    /// Previous, Rust accepted fields that contain external private zero-sized types, even though
    /// those types could gain a non-zero-sized field in a future, semver-compatible update.
    ///
    /// Rust also accepted fields that contain `repr(C)` zero-sized types, even though those types
    /// are not guaranteed to be zero-sized on all targets, and even though those types can
    /// make a difference for the ABI (and therefore cannot be ignored by `repr(transparent)`).
    ///
    /// This is a [future-incompatible] lint to transition this
    /// to a hard error in the future. See [issue #78586] for more details.
    ///
    /// [issue #78586]: https://github.com/rust-lang/rust/issues/78586
    /// [future-incompatible]: ../index.md#future-incompatible-lints
    pub REPR_TRANSPARENT_NON_ZST_FIELDS,
    Deny,
    "transparent type contains an external ZST that is marked #[non_exhaustive] or contains private fields",
    @future_incompatible = FutureIncompatibleInfo {
        reason: FutureIncompatibilityReason::FutureReleaseError,
        reference: "issue #78586 <https://github.com/rust-lang/rust/issues/78586>",
        report_in_deps: true,
    };
}

declare_lint! {
    /// The `unstable_syntax_pre_expansion` lint detects the use of unstable
    /// syntax that is discarded during attribute expansion.
    ///
    /// ### Example
    ///
    /// ```rust
    /// #[cfg(FALSE)]
    /// macro foo() {}
    /// ```
    ///
    /// {{produces}}
    ///
    /// ### Explanation
    ///
    /// The input to active attributes such as `#[cfg]` or procedural macro
    /// attributes is required to be valid syntax. Previously, the compiler only
    /// gated the use of unstable syntax features after resolving `#[cfg]` gates
    /// and expanding procedural macros.
    ///
    /// To avoid relying on unstable syntax, move the use of unstable syntax
    /// into a position where the compiler does not parse the syntax, such as a
    /// functionlike macro.
    ///
    /// ```rust
    /// # #![deny(unstable_syntax_pre_expansion)]
    ///
    /// macro_rules! identity {
    ///    ( $($tokens:tt)* ) => { $($tokens)* }
    /// }
    ///
    /// #[cfg(FALSE)]
    /// identity! {
    ///    macro foo() {}
    /// }
    /// ```
    ///
    /// This is a [future-incompatible] lint to transition this
    /// to a hard error in the future. See [issue #65860] for more details.
    ///
    /// [issue #65860]: https://github.com/rust-lang/rust/issues/65860
    /// [future-incompatible]: ../index.md#future-incompatible-lints
    pub UNSTABLE_SYNTAX_PRE_EXPANSION,
    Warn,
    "unstable syntax can change at any point in the future, causing a hard error!",
    @future_incompatible = FutureIncompatibleInfo {
        reason: FutureIncompatibilityReason::FutureReleaseError,
        reference: "issue #65860 <https://github.com/rust-lang/rust/issues/65860>",
    };
}

declare_lint! {
    /// The `ambiguous_glob_reexports` lint detects cases where names re-exported via globs
    /// collide. Downstream users trying to use the same name re-exported from multiple globs
    /// will receive a warning pointing out redefinition of the same name.
    ///
    /// ### Example
    ///
    /// ```rust,compile_fail
    /// #![deny(ambiguous_glob_reexports)]
    /// pub mod foo {
    ///     pub type X = u8;
    /// }
    ///
    /// pub mod bar {
    ///     pub type Y = u8;
    ///     pub type X = u8;
    /// }
    ///
    /// pub use foo::*;
    /// pub use bar::*;
    ///
    ///
    /// pub fn main() {}
    /// ```
    ///
    /// {{produces}}
    ///
    /// ### Explanation
    ///
    /// This was previously accepted but it could silently break a crate's downstream users code.
    /// For example, if `foo::*` and `bar::*` were re-exported before `bar::X` was added to the
    /// re-exports, down stream users could use `this_crate::X` without problems. However, adding
    /// `bar::X` would cause compilation errors in downstream crates because `X` is defined
    /// multiple times in the same namespace of `this_crate`.
    pub AMBIGUOUS_GLOB_REEXPORTS,
    Warn,
    "ambiguous glob re-exports",
}

declare_lint! {
    /// The `hidden_glob_reexports` lint detects cases where glob re-export items are shadowed by
    /// private items.
    ///
    /// ### Example
    ///
    /// ```rust,compile_fail
    /// #![deny(hidden_glob_reexports)]
    ///
    /// pub mod upstream {
    ///     mod inner { pub struct Foo {}; pub struct Bar {}; }
    ///     pub use self::inner::*;
    ///     struct Foo {} // private item shadows `inner::Foo`
    /// }
    ///
    /// // mod downstream {
    /// //     fn test() {
    /// //         let _ = crate::upstream::Foo; // inaccessible
    /// //     }
    /// // }
    ///
    /// pub fn main() {}
    /// ```
    ///
    /// {{produces}}
    ///
    /// ### Explanation
    ///
    /// This was previously accepted without any errors or warnings but it could silently break a
    /// crate's downstream user code. If the `struct Foo` was added, `dep::inner::Foo` would
    /// silently become inaccessible and trigger a "`struct `Foo` is private`" visibility error at
    /// the downstream use site.
    pub HIDDEN_GLOB_REEXPORTS,
    Warn,
    "name introduced by a private item shadows a name introduced by a public glob re-export",
}

declare_lint! {
    /// The `long_running_const_eval` lint is emitted when const
    /// eval is running for a long time to ensure rustc terminates
    /// even if you accidentally wrote an infinite loop.
    ///
    /// ### Example
    ///
    /// ```rust,compile_fail
    /// const FOO: () = loop {};
    /// ```
    ///
    /// {{produces}}
    ///
    /// ### Explanation
    ///
    /// Loops allow const evaluation to compute arbitrary code, but may also
    /// cause infinite loops or just very long running computations.
    /// Users can enable long running computations by allowing the lint
    /// on individual constants or for entire crates.
    ///
    /// ### Unconditional warnings
    ///
    /// Note that regardless of whether the lint is allowed or set to warn,
    /// the compiler will issue warnings if constant evaluation runs significantly
    /// longer than this lint's limit. These warnings are also shown to downstream
    /// users from crates.io or similar registries. If you are above the lint's limit,
    /// both you and downstream users might be exposed to these warnings.
    /// They might also appear on compiler updates, as the compiler makes minor changes
    /// about how complexity is measured: staying below the limit ensures that there
    /// is enough room, and given that the lint is disabled for people who use your
    /// dependency it means you will be the only one to get the warning and can put
    /// out an update in your own time.
    pub LONG_RUNNING_CONST_EVAL,
    Deny,
    "detects long const eval operations",
    report_in_external_macro
}

declare_lint! {
    /// The `unused_associated_type_bounds` lint is emitted when an
    /// associated type bound is added to a trait object, but the associated
    /// type has a `where Self: Sized` bound, and is thus unavailable on the
    /// trait object anyway.
    ///
    /// ### Example
    ///
    /// ```rust
    /// trait Foo {
    ///     type Bar where Self: Sized;
    /// }
    /// type Mop = dyn Foo<Bar = ()>;
    /// ```
    ///
    /// {{produces}}
    ///
    /// ### Explanation
    ///
    /// Just like methods with `Self: Sized` bounds are unavailable on trait
    /// objects, associated types can be removed from the trait object.
    pub UNUSED_ASSOCIATED_TYPE_BOUNDS,
    Warn,
    "detects unused `Foo = Bar` bounds in `dyn Trait<Foo = Bar>`"
}

declare_lint! {
    /// The `unused_doc_comments` lint detects doc comments that aren't used
    /// by `rustdoc`.
    ///
    /// ### Example
    ///
    /// ```rust
    /// /// docs for x
    /// let x = 12;
    /// ```
    ///
    /// {{produces}}
    ///
    /// ### Explanation
    ///
    /// `rustdoc` does not use doc comments in all positions, and so the doc
    /// comment will be ignored. Try changing it to a normal comment with `//`
    /// to avoid the warning.
    pub UNUSED_DOC_COMMENTS,
    Warn,
    "detects doc comments that aren't used by rustdoc"
}

declare_lint! {
    /// The `rust_2021_incompatible_closure_captures` lint detects variables that aren't completely
    /// captured in Rust 2021, such that the `Drop` order of their fields may differ between
    /// Rust 2018 and 2021.
    ///
    /// It can also detect when a variable implements a trait like `Send`, but one of its fields does not,
    /// and the field is captured by a closure and used with the assumption that said field implements
    /// the same trait as the root variable.
    ///
    /// ### Example of drop reorder
    ///
    /// ```rust,edition2018,compile_fail
    /// #![deny(rust_2021_incompatible_closure_captures)]
    /// # #![allow(unused)]
    ///
    /// struct FancyInteger(i32);
    ///
    /// impl Drop for FancyInteger {
    ///     fn drop(&mut self) {
    ///         println!("Just dropped {}", self.0);
    ///     }
    /// }
    ///
    /// struct Point { x: FancyInteger, y: FancyInteger }
    ///
    /// fn main() {
    ///   let p = Point { x: FancyInteger(10), y: FancyInteger(20) };
    ///
    ///   let c = || {
    ///      let x = p.x;
    ///   };
    ///
    ///   c();
    ///
    ///   // ... More code ...
    /// }
    /// ```
    ///
    /// {{produces}}
    ///
    /// ### Explanation
    ///
    /// In the above example, `p.y` will be dropped at the end of `f` instead of
    /// with `c` in Rust 2021.
    ///
    /// ### Example of auto-trait
    ///
    /// ```rust,edition2018,compile_fail
    /// #![deny(rust_2021_incompatible_closure_captures)]
    /// use std::thread;
    ///
    /// struct Pointer(*mut i32);
    /// unsafe impl Send for Pointer {}
    ///
    /// fn main() {
    ///     let mut f = 10;
    ///     let fptr = Pointer(&mut f as *mut i32);
    ///     thread::spawn(move || unsafe {
    ///         *fptr.0 = 20;
    ///     });
    /// }
    /// ```
    ///
    /// {{produces}}
    ///
    /// ### Explanation
    ///
    /// In the above example, only `fptr.0` is captured in Rust 2021.
    /// The field is of type `*mut i32`, which doesn't implement `Send`,
    /// making the code invalid as the field cannot be sent between threads safely.
    pub RUST_2021_INCOMPATIBLE_CLOSURE_CAPTURES,
    Allow,
    "detects closures affected by Rust 2021 changes",
    @future_incompatible = FutureIncompatibleInfo {
        reason: FutureIncompatibilityReason::EditionSemanticsChange(Edition::Edition2021),
        explain_reason: false,
    };
}

declare_lint_pass!(UnusedDocComment => [UNUSED_DOC_COMMENTS]);

declare_lint! {
    /// The `missing_abi` lint detects cases where the ABI is omitted from
    /// `extern` declarations.
    ///
    /// ### Example
    ///
    /// ```rust,compile_fail
    /// #![deny(missing_abi)]
    ///
    /// extern fn foo() {}
    /// ```
    ///
    /// {{produces}}
    ///
    /// ### Explanation
    ///
    /// For historic reasons, Rust implicitly selects `C` as the default ABI for
    /// `extern` declarations. [Other ABIs] like `C-unwind` and `system` have
    /// been added since then, and especially with their addition seeing the ABI
    /// easily makes code review easier.
    ///
    /// [Other ABIs]: https://doc.rust-lang.org/reference/items/external-blocks.html#abi
    pub MISSING_ABI,
    Warn,
    "No declared ABI for extern declaration"
}

declare_lint! {
    /// The `invalid_doc_attributes` lint detects when the `#[doc(...)]` is
    /// misused.
    ///
    /// ### Example
    ///
    /// ```rust,compile_fail
    /// #![deny(warnings)]
    ///
    /// pub mod submodule {
    ///     #![doc(test(no_crate_inject))]
    /// }
    /// ```
    ///
    /// {{produces}}
    ///
    /// ### Explanation
    ///
    /// Previously, incorrect usage of the `#[doc(..)]` attribute was not
    /// being validated. Usually these should be rejected as a hard error,
    /// but this lint was introduced to avoid breaking any existing
    /// crates which included them.
    pub INVALID_DOC_ATTRIBUTES,
    Deny,
    "detects invalid `#[doc(...)]` attributes",
}

declare_lint! {
    /// The `rust_2021_incompatible_or_patterns` lint detects usage of old versions of or-patterns.
    ///
    /// ### Example
    ///
    /// ```rust,edition2018,compile_fail
    /// #![deny(rust_2021_incompatible_or_patterns)]
    ///
    /// macro_rules! match_any {
    ///     ( $expr:expr , $( $( $pat:pat )|+ => $expr_arm:expr ),+ ) => {
    ///         match $expr {
    ///             $(
    ///                 $( $pat => $expr_arm, )+
    ///             )+
    ///         }
    ///     };
    /// }
    ///
    /// fn main() {
    ///     let result: Result<i64, i32> = Err(42);
    ///     let int: i64 = match_any!(result, Ok(i) | Err(i) => i.into());
    ///     assert_eq!(int, 42);
    /// }
    /// ```
    ///
    /// {{produces}}
    ///
    /// ### Explanation
    ///
    /// In Rust 2021, the `pat` matcher will match additional patterns, which include the `|` character.
    pub RUST_2021_INCOMPATIBLE_OR_PATTERNS,
    Allow,
    "detects usage of old versions of or-patterns",
    @future_incompatible = FutureIncompatibleInfo {
        reason: FutureIncompatibilityReason::EditionError(Edition::Edition2021),
        reference: "<https://doc.rust-lang.org/edition-guide/rust-2021/or-patterns-macro-rules.html>",
    };
}

declare_lint! {
    /// The `rust_2021_prelude_collisions` lint detects the usage of trait methods which are ambiguous
    /// with traits added to the prelude in future editions.
    ///
    /// ### Example
    ///
    /// ```rust,edition2018,compile_fail
    /// #![deny(rust_2021_prelude_collisions)]
    ///
    /// trait Foo {
    ///     fn try_into(self) -> Result<String, !>;
    /// }
    ///
    /// impl Foo for &str {
    ///     fn try_into(self) -> Result<String, !> {
    ///         Ok(String::from(self))
    ///     }
    /// }
    ///
    /// fn main() {
    ///     let x: String = "3".try_into().unwrap();
    ///     //                  ^^^^^^^^
    ///     // This call to try_into matches both Foo::try_into and TryInto::try_into as
    ///     // `TryInto` has been added to the Rust prelude in 2021 edition.
    ///     println!("{x}");
    /// }
    /// ```
    ///
    /// {{produces}}
    ///
    /// ### Explanation
    ///
    /// In Rust 2021, one of the important introductions is the [prelude changes], which add
    /// `TryFrom`, `TryInto`, and `FromIterator` into the standard library's prelude. Since this
    /// results in an ambiguity as to which method/function to call when an existing `try_into`
    /// method is called via dot-call syntax or a `try_from`/`from_iter` associated function
    /// is called directly on a type.
    ///
    /// [prelude changes]: https://blog.rust-lang.org/inside-rust/2021/03/04/planning-rust-2021.html#prelude-changes
    pub RUST_2021_PRELUDE_COLLISIONS,
    Allow,
    "detects the usage of trait methods which are ambiguous with traits added to the \
        prelude in future editions",
    @future_incompatible = FutureIncompatibleInfo {
        reason: FutureIncompatibilityReason::EditionError(Edition::Edition2021),
        reference: "<https://doc.rust-lang.org/edition-guide/rust-2021/prelude.html>",
    };
}

declare_lint! {
    /// The `rust_2024_prelude_collisions` lint detects the usage of trait methods which are ambiguous
    /// with traits added to the prelude in future editions.
    ///
    /// ### Example
    ///
    /// ```rust,edition2021,compile_fail
    /// #![deny(rust_2024_prelude_collisions)]
    /// trait Meow {
    ///     fn poll(&self) {}
    /// }
    /// impl<T> Meow for T {}
    ///
    /// fn main() {
    ///     core::pin::pin!(async {}).poll();
    ///     //                        ^^^^^^
    ///     // This call to try_into matches both Future::poll and Meow::poll as
    ///     // `Future` has been added to the Rust prelude in 2024 edition.
    /// }
    /// ```
    ///
    /// {{produces}}
    ///
    /// ### Explanation
    ///
    /// Rust 2024, introduces two new additions to the standard library's prelude:
    /// `Future` and `IntoFuture`. This results in an ambiguity as to which method/function
    /// to call when an existing `poll`/`into_future` method is called via dot-call syntax or
    /// a `poll`/`into_future` associated function is called directly on a type.
    ///
    pub RUST_2024_PRELUDE_COLLISIONS,
    Allow,
    "detects the usage of trait methods which are ambiguous with traits added to the \
        prelude in future editions",
    @future_incompatible = FutureIncompatibleInfo {
        reason: FutureIncompatibilityReason::EditionError(Edition::Edition2024),
        reference: "<https://doc.rust-lang.org/edition-guide/rust-2024/prelude.html>",
    };
}

declare_lint! {
    /// The `rust_2021_prefixes_incompatible_syntax` lint detects identifiers that will be parsed as a
    /// prefix instead in Rust 2021.
    ///
    /// ### Example
    ///
    /// ```rust,edition2018,compile_fail
    /// #![deny(rust_2021_prefixes_incompatible_syntax)]
    ///
    /// macro_rules! m {
    ///     (z $x:expr) => ();
    /// }
    ///
    /// m!(z"hey");
    /// ```
    ///
    /// {{produces}}
    ///
    /// ### Explanation
    ///
    /// In Rust 2015 and 2018, `z"hey"` is two tokens: the identifier `z`
    /// followed by the string literal `"hey"`. In Rust 2021, the `z` is
    /// considered a prefix for `"hey"`.
    ///
    /// This lint suggests to add whitespace between the `z` and `"hey"` tokens
    /// to keep them separated in Rust 2021.
    // Allow this lint -- rustdoc doesn't yet support threading edition into this lint's parser.
    #[allow(rustdoc::invalid_rust_codeblocks)]
    pub RUST_2021_PREFIXES_INCOMPATIBLE_SYNTAX,
    Allow,
    "identifiers that will be parsed as a prefix in Rust 2021",
    @future_incompatible = FutureIncompatibleInfo {
        reason: FutureIncompatibilityReason::EditionError(Edition::Edition2021),
        reference: "<https://doc.rust-lang.org/edition-guide/rust-2021/reserving-syntax.html>",
    };
    crate_level_only
}

declare_lint! {
    /// The `unsupported_calling_conventions` lint is output whenever there is a use of the
    /// `stdcall`, `fastcall`, and `cdecl` calling conventions (or their unwind
    /// variants) on targets that cannot meaningfully be supported for the requested target.
    ///
    /// For example `stdcall` does not make much sense for a x86_64 or, more apparently, powerpc
    /// code, because this calling convention was never specified for those targets.
    ///
    /// Historically MSVC toolchains have fallen back to the regular C calling convention for
    /// targets other than x86, but Rust doesn't really see a similar need to introduce a similar
    /// hack across many more targets.
    ///
    /// ### Example
    ///
    /// ```rust,ignore (needs specific targets)
    /// extern "stdcall" fn stdcall() {}
    /// ```
    ///
    /// This will produce:
    ///
    /// ```text
    /// warning: use of calling convention not supported on this target
    ///   --> $DIR/unsupported.rs:39:1
    ///    |
    /// LL | extern "stdcall" fn stdcall() {}
    ///    | ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    ///    |
    ///    = note: `#[warn(unsupported_calling_conventions)]` on by default
    ///    = warning: this was previously accepted by the compiler but is being phased out;
    ///               it will become a hard error in a future release!
    ///    = note: for more information, see issue ...
    /// ```
    ///
    /// ### Explanation
    ///
    /// On most of the targets the behaviour of `stdcall` and similar calling conventions is not
    /// defined at all, but was previously accepted due to a bug in the implementation of the
    /// compiler.
    pub UNSUPPORTED_CALLING_CONVENTIONS,
    Warn,
    "use of unsupported calling convention",
    @future_incompatible = FutureIncompatibleInfo {
        reason: FutureIncompatibilityReason::FutureReleaseError,
        report_in_deps: false,
        reference: "issue #137018 <https://github.com/rust-lang/rust/issues/137018>",
    };
}

declare_lint! {
    /// The `unsupported_fn_ptr_calling_conventions` lint is output whenever there is a use of
    /// a target dependent calling convention on a target that does not support this calling
    /// convention on a function pointer.
    ///
    /// For example `stdcall` does not make much sense for a x86_64 or, more apparently, powerpc
    /// code, because this calling convention was never specified for those targets.
    ///
    /// ### Example
    ///
    /// ```rust,ignore (needs specific targets)
    /// fn stdcall_ptr(f: extern "stdcall" fn ()) {
    ///     f()
    /// }
    /// ```
    ///
    /// This will produce:
    ///
    /// ```text
    /// warning: the calling convention `"stdcall"` is not supported on this target
    ///   --> $DIR/unsupported.rs:34:15
    ///    |
    /// LL | fn stdcall_ptr(f: extern "stdcall" fn()) {
    ///    |               ^^^^^^^^^^^^^^^^^^^^^^^^
    ///    |
    ///    = warning: this was previously accepted by the compiler but is being phased out; it will become a hard error in a future release!
    ///    = note: for more information, see issue #130260 <https://github.com/rust-lang/rust/issues/130260>
    ///    = note: `#[warn(unsupported_fn_ptr_calling_conventions)]` on by default
    /// ```
    ///
    /// ### Explanation
    ///
    /// On most of the targets the behaviour of `stdcall` and similar calling conventions is not
    /// defined at all, but was previously accepted due to a bug in the implementation of the
    /// compiler.
    pub UNSUPPORTED_FN_PTR_CALLING_CONVENTIONS,
    Warn,
    "use of unsupported calling convention for function pointer",
    @future_incompatible = FutureIncompatibleInfo {
        reason: FutureIncompatibilityReason::FutureReleaseError,
        reference: "issue #130260 <https://github.com/rust-lang/rust/issues/130260>",
        report_in_deps: true,
    };
}

declare_lint! {
    /// The `break_with_label_and_loop` lint detects labeled `break` expressions with
    /// an unlabeled loop as their value expression.
    ///
    /// ### Example
    ///
    /// ```rust
    /// 'label: loop {
    ///     break 'label loop { break 42; };
    /// };
    /// ```
    ///
    /// {{produces}}
    ///
    /// ### Explanation
    ///
    /// In Rust, loops can have a label, and `break` expressions can refer to that label to
    /// break out of specific loops (and not necessarily the innermost one). `break` expressions
    /// can also carry a value expression, which can be another loop. A labeled `break` with an
    /// unlabeled loop as its value expression is easy to confuse with an unlabeled break with
    /// a labeled loop and is thus discouraged (but allowed for compatibility); use parentheses
    /// around the loop expression to silence this warning. Unlabeled `break` expressions with
    /// labeled loops yield a hard error, which can also be silenced by wrapping the expression
    /// in parentheses.
    pub BREAK_WITH_LABEL_AND_LOOP,
    Warn,
    "`break` expression with label and unlabeled loop as value expression"
}

declare_lint! {
    /// The `non_exhaustive_omitted_patterns` lint aims to help consumers of a `#[non_exhaustive]`
    /// struct or enum who want to match all of its fields/variants explicitly.
    ///
    /// The `#[non_exhaustive]` annotation forces matches to use wildcards, so exhaustiveness
    /// checking cannot be used to ensure that all fields/variants are matched explicitly. To remedy
    /// this, this allow-by-default lint warns the user when a match mentions some but not all of
    /// the fields/variants of a `#[non_exhaustive]` struct or enum.
    ///
    /// ### Example
    ///
    /// ```rust,ignore (needs separate crate)
    /// // crate A
    /// #[non_exhaustive]
    /// pub enum Bar {
    ///     A,
    ///     B, // added variant in non breaking change
    /// }
    ///
    /// // in crate B
    /// #![feature(non_exhaustive_omitted_patterns_lint)]
    /// #[warn(non_exhaustive_omitted_patterns)]
    /// match Bar::A {
    ///     Bar::A => {},
    ///     _ => {},
    /// }
    /// ```
    ///
    /// This will produce:
    ///
    /// ```text
    /// warning: some variants are not matched explicitly
    ///    --> $DIR/reachable-patterns.rs:70:9
    ///    |
    /// LL |         match Bar::A {
    ///    |               ^ pattern `Bar::B` not covered
    ///    |
    ///  note: the lint level is defined here
    ///   --> $DIR/reachable-patterns.rs:69:16
    ///    |
    /// LL |         #[warn(non_exhaustive_omitted_patterns)]
    ///    |                ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    ///    = help: ensure that all variants are matched explicitly by adding the suggested match arms
    ///    = note: the matched value is of type `Bar` and the `non_exhaustive_omitted_patterns` attribute was found
    /// ```
    ///
    /// Warning: setting this to `deny` will make upstream non-breaking changes (adding fields or
    /// variants to a `#[non_exhaustive]` struct or enum) break your crate. This goes against
    /// expected semver behavior.
    ///
    /// ### Explanation
    ///
    /// Structs and enums tagged with `#[non_exhaustive]` force the user to add a (potentially
    /// redundant) wildcard when pattern-matching, to allow for future addition of fields or
    /// variants. The `non_exhaustive_omitted_patterns` lint detects when such a wildcard happens to
    /// actually catch some fields/variants. In other words, when the match without the wildcard
    /// would not be exhaustive. This lets the user be informed if new fields/variants were added.
    pub NON_EXHAUSTIVE_OMITTED_PATTERNS,
    Allow,
    "detect when patterns of types marked `non_exhaustive` are missed",
    @feature_gate = non_exhaustive_omitted_patterns_lint;
}

declare_lint! {
    /// The `text_direction_codepoint_in_comment` lint detects Unicode codepoints in comments that
    /// change the visual representation of text on screen in a way that does not correspond to
    /// their on memory representation.
    ///
    /// ### Example
    ///
    /// ```rust,compile_fail
    /// #![deny(text_direction_codepoint_in_comment)]
    /// fn main() {
    #[doc = "    println!(\"{:?}\"); // '\u{202E}');"]
    /// }
    /// ```
    ///
    /// {{produces}}
    ///
    /// ### Explanation
    ///
    /// Unicode allows changing the visual flow of text on screen in order to support scripts that
    /// are written right-to-left, but a specially crafted comment can make code that will be
    /// compiled appear to be part of a comment, depending on the software used to read the code.
    /// To avoid potential problems or confusion, such as in CVE-2021-42574, by default we deny
    /// their use.
    pub TEXT_DIRECTION_CODEPOINT_IN_COMMENT,
    Deny,
    "invisible directionality-changing codepoints in comment",
    crate_level_only
}

declare_lint! {
    /// The `text_direction_codepoint_in_literal` lint detects Unicode codepoints that change the
    /// visual representation of text on screen in a way that does not correspond to their on
    /// memory representation.
    ///
    /// ### Explanation
    ///
    /// The unicode characters `\u{202A}`, `\u{202B}`, `\u{202D}`, `\u{202E}`, `\u{2066}`,
    /// `\u{2067}`, `\u{2068}`, `\u{202C}` and `\u{2069}` make the flow of text on screen change
    /// its direction on software that supports these codepoints. This makes the text "abc" display
    /// as "cba" on screen. By leveraging software that supports these, people can write specially
    /// crafted literals that make the surrounding code seem like it's performing one action, when
    /// in reality it is performing another. Because of this, we proactively lint against their
    /// presence to avoid surprises.
    ///
    /// ### Example
    ///
    /// ```rust,compile_fail
    /// #![deny(text_direction_codepoint_in_literal)]
    /// fn main() {
    // ` - convince tidy that backticks match
    #[doc = "    println!(\"{:?}\", '\u{202E}');"]
    // `
    /// }
    /// ```
    ///
    /// {{produces}}
    ///
    pub TEXT_DIRECTION_CODEPOINT_IN_LITERAL,
    Deny,
    "detect special Unicode codepoints that affect the visual representation of text on screen, \
     changing the direction in which text flows",
    crate_level_only
}

declare_lint! {
    /// The `duplicate_macro_attributes` lint detects when a `#[test]`-like built-in macro
    /// attribute is duplicated on an item. This lint may trigger on `bench`, `cfg_eval`, `test`
    /// and `test_case`.
    ///
    /// ### Example
    ///
    /// ```rust,ignore (needs --test)
    /// #[test]
    /// #[test]
    /// fn foo() {}
    /// ```
    ///
    /// This will produce:
    ///
    /// ```text
    /// warning: duplicated attribute
    ///  --> src/lib.rs:2:1
    ///   |
    /// 2 | #[test]
    ///   | ^^^^^^^
    ///   |
    ///   = note: `#[warn(duplicate_macro_attributes)]` on by default
    /// ```
    ///
    /// ### Explanation
    ///
    /// A duplicated attribute may erroneously originate from a copy-paste and the effect of it
    /// being duplicated may not be obvious or desirable.
    ///
    /// For instance, doubling the `#[test]` attributes registers the test to be run twice with no
    /// change to its environment.
    ///
    /// [issue #90979]: https://github.com/rust-lang/rust/issues/90979
    pub DUPLICATE_MACRO_ATTRIBUTES,
    Warn,
    "duplicated attribute"
}

declare_lint! {
    /// The `deprecated_where_clause_location` lint detects when a where clause in front of the equals
    /// in an associated type.
    ///
    /// ### Example
    ///
    /// ```rust
    /// trait Trait {
    ///   type Assoc<'a> where Self: 'a;
    /// }
    ///
    /// impl Trait for () {
    ///   type Assoc<'a> where Self: 'a = ();
    /// }
    /// ```
    ///
    /// {{produces}}
    ///
    /// ### Explanation
    ///
    /// The preferred location for where clauses on associated types
    /// is after the type. However, for most of generic associated types development,
    /// it was only accepted before the equals. To provide a transition period and
    /// further evaluate this change, both are currently accepted. At some point in
    /// the future, this may be disallowed at an edition boundary; but, that is
    /// undecided currently.
    pub DEPRECATED_WHERE_CLAUSE_LOCATION,
    Warn,
    "deprecated where clause location"
}

declare_lint! {
    /// The `test_unstable_lint` lint tests unstable lints and is perma-unstable.
    ///
    /// ### Example
    ///
    /// ```rust
    /// // This lint is intentionally used to test the compiler's behavior
    /// // when an unstable lint is enabled without the corresponding feature gate.
    /// #![allow(test_unstable_lint)]
    /// ```
    ///
    /// {{produces}}
    ///
    /// ### Explanation
    ///
    /// In order to test the behavior of unstable lints, a permanently-unstable
    /// lint is required. This lint can be used to trigger warnings and errors
    /// from the compiler related to unstable lints.
    pub TEST_UNSTABLE_LINT,
    Deny,
    "this unstable lint is only for testing",
    @feature_gate = test_unstable_lint;
}

declare_lint! {
    /// The `ffi_unwind_calls` lint detects calls to foreign functions or function pointers with
    /// `C-unwind` or other FFI-unwind ABIs.
    ///
    /// ### Example
    ///
    /// ```rust
    /// #![warn(ffi_unwind_calls)]
    ///
    /// unsafe extern "C-unwind" {
    ///     fn foo();
    /// }
    ///
    /// fn bar() {
    ///     unsafe { foo(); }
    ///     let ptr: unsafe extern "C-unwind" fn() = foo;
    ///     unsafe { ptr(); }
    /// }
    /// ```
    ///
    /// {{produces}}
    ///
    /// ### Explanation
    ///
    /// For crates containing such calls, if they are compiled with `-C panic=unwind` then the
    /// produced library cannot be linked with crates compiled with `-C panic=abort`. For crates
    /// that desire this ability it is therefore necessary to avoid such calls.
    pub FFI_UNWIND_CALLS,
    Allow,
    "call to foreign functions or function pointers with FFI-unwind ABI"
}

declare_lint! {
    /// The `linker_messages` lint forwards warnings from the linker.
    ///
    /// ### Example
    ///
    /// ```rust,ignore (needs CLI args, platform-specific)
    /// #[warn(linker_messages)]
    /// extern "C" {
    ///   fn foo();
    /// }
    /// fn main () { unsafe { foo(); } }
    /// ```
    ///
    /// On Linux, using `gcc -Wl,--warn-unresolved-symbols` as a linker, this will produce
    ///
    /// ```text
    /// warning: linker stderr: rust-lld: undefined symbol: foo
    ///          >>> referenced by rust_out.69edbd30df4ae57d-cgu.0
    ///          >>>               rust_out.rust_out.69edbd30df4ae57d-cgu.0.rcgu.o:(rust_out::main::h3a90094b06757803)
    ///   |
    /// note: the lint level is defined here
    ///  --> warn.rs:1:9
    ///   |
    /// 1 | #![warn(linker_messages)]
    ///   |         ^^^^^^^^^^^^^^^
    /// warning: 1 warning emitted
    /// ```
    ///
    /// ### Explanation
    ///
    /// Linkers emit platform-specific and program-specific warnings that cannot be predicted in
    /// advance by the Rust compiler. Such messages are ignored by default for now. While linker
    /// warnings could be very useful they have been ignored for many years by essentially all
    /// users, so we need to do a bit more work than just surfacing their text to produce a clear
    /// and actionable warning of similar quality to our other diagnostics. See this tracking
    /// issue for more details: <https://github.com/rust-lang/rust/issues/136096>.
    pub LINKER_MESSAGES,
    Allow,
    "warnings emitted at runtime by the target-specific linker program"
}

declare_lint! {
    /// The `named_arguments_used_positionally` lint detects cases where named arguments are only
    /// used positionally in format strings. This usage is valid but potentially very confusing.
    ///
    /// ### Example
    ///
    /// ```rust,compile_fail
    /// #![deny(named_arguments_used_positionally)]
    /// fn main() {
    ///     let _x = 5;
    ///     println!("{}", _x = 1); // Prints 1, will trigger lint
    ///
    ///     println!("{}", _x); // Prints 5, no lint emitted
    ///     println!("{_x}", _x = _x); // Prints 5, no lint emitted
    /// }
    /// ```
    ///
    /// {{produces}}
    ///
    /// ### Explanation
    ///
    /// Rust formatting strings can refer to named arguments by their position, but this usage is
    /// potentially confusing. In particular, readers can incorrectly assume that the declaration
    /// of named arguments is an assignment (which would produce the unit type).
    /// For backwards compatibility, this is not a hard error.
    pub NAMED_ARGUMENTS_USED_POSITIONALLY,
    Warn,
    "named arguments in format used positionally"
}

declare_lint! {
    /// The `never_type_fallback_flowing_into_unsafe` lint detects cases where never type fallback
    /// affects unsafe function calls.
    ///
    /// ### Never type fallback
    ///
    /// When the compiler sees a value of type [`!`] it implicitly inserts a coercion (if possible),
    /// to allow type check to infer any type:
    ///
    /// ```ignore (illustrative-and-has-placeholders)
    /// // this
    /// let x: u8 = panic!();
    ///
    /// // is (essentially) turned by the compiler into
    /// let x: u8 = absurd(panic!());
    ///
    /// // where absurd is a function with the following signature
    /// // (it's sound, because `!` always marks unreachable code):
    /// fn absurd<T>(never: !) -> T { ... }
    /// ```
    ///
    /// While it's convenient to be able to use non-diverging code in one of the branches (like
    /// `if a { b } else { return }`) this could lead to compilation errors:
    ///
    /// ```compile_fail
    /// // this
    /// { panic!() };
    ///
    /// // gets turned into this
    /// { absurd(panic!()) }; // error: can't infer the type of `absurd`
    /// ```
    ///
    /// To prevent such errors, compiler remembers where it inserted `absurd` calls, and if it
    /// can't infer their type, it sets the type to fallback. `{ absurd::<Fallback>(panic!()) };`.
    /// This is what is known as "never type fallback".
    ///
    /// ### Example
    ///
    /// ```rust,compile_fail
    /// fn main() {
    ///     if true {
    ///         // return has type `!` which, is some cases, causes never type fallback
    ///         return
    ///     } else {
    ///         // `zeroed` is an unsafe function, which returns an unbounded type
    ///         unsafe { std::mem::zeroed() }
    ///     };
    ///     // depending on the fallback, `zeroed` may create `()` (which is completely sound),
    ///     // or `!` (which is instant undefined behavior)
    /// }
    /// ```
    ///
    /// {{produces}}
    ///
    /// ### Explanation
    ///
    /// Due to historic reasons never type fallback was `()`, meaning that `!` got spontaneously
    /// coerced to `()`. There are plans to change that, but they may make the code such as above
    /// unsound. Instead of depending on the fallback, you should specify the type explicitly:
    /// ```
    /// if true {
    ///     return
    /// } else {
    ///     // type is explicitly specified, fallback can't hurt us no more
    ///     unsafe { std::mem::zeroed::<()>() }
    /// };
    /// ```
    ///
    /// See [Tracking Issue for making `!` fall back to `!`](https://github.com/rust-lang/rust/issues/123748).
    ///
    /// [`!`]: https://doc.rust-lang.org/core/primitive.never.html
    /// [`()`]: https://doc.rust-lang.org/core/primitive.unit.html
    pub NEVER_TYPE_FALLBACK_FLOWING_INTO_UNSAFE,
    Deny,
    "never type fallback affecting unsafe function calls",
    @future_incompatible = FutureIncompatibleInfo {
        reason: FutureIncompatibilityReason::EditionAndFutureReleaseSemanticsChange(Edition::Edition2024),
        reference: "<https://doc.rust-lang.org/edition-guide/rust-2024/never-type-fallback.html>",
        report_in_deps: true,
    };
    @edition Edition2024 => Deny;
    report_in_external_macro
}

declare_lint! {
    /// The `dependency_on_unit_never_type_fallback` lint detects cases where code compiles with
    /// [never type fallback] being [`()`], but will stop compiling with fallback being [`!`].
    ///
    /// [never type fallback]: https://doc.rust-lang.org/nightly/core/primitive.never.html#never-type-fallback
    /// [`!`]: https://doc.rust-lang.org/core/primitive.never.html
    /// [`()`]: https://doc.rust-lang.org/core/primitive.unit.html
    ///
    /// ### Example
    ///
    /// ```rust,compile_fail,edition2021
    /// # #![deny(dependency_on_unit_never_type_fallback)]
    /// fn main() {
    ///     if true {
    ///         // return has type `!` which, is some cases, causes never type fallback
    ///         return
    ///     } else {
    ///         // the type produced by this call is not specified explicitly,
    ///         // so it will be inferred from the previous branch
    ///         Default::default()
    ///     };
    ///     // depending on the fallback, this may compile (because `()` implements `Default`),
    ///     // or it may not (because `!` does not implement `Default`)
    /// }
    /// ```
    ///
    /// {{produces}}
    ///
    /// ### Explanation
    ///
    /// Due to historic reasons never type fallback was `()`, meaning that `!` got spontaneously
    /// coerced to `()`. There are plans to change that, but they may make the code such as above
    /// not compile. Instead of depending on the fallback, you should specify the type explicitly:
    /// ```
    /// if true {
    ///     return
    /// } else {
    ///     // type is explicitly specified, fallback can't hurt us no more
    ///     <() as Default>::default()
    /// };
    /// ```
    ///
    /// See [Tracking Issue for making `!` fall back to `!`](https://github.com/rust-lang/rust/issues/123748).
    pub DEPENDENCY_ON_UNIT_NEVER_TYPE_FALLBACK,
    Deny,
    "never type fallback affecting unsafe function calls",
    @future_incompatible = FutureIncompatibleInfo {
        reason: FutureIncompatibilityReason::EditionAndFutureReleaseError(Edition::Edition2024),
        reference: "<https://doc.rust-lang.org/edition-guide/rust-2024/never-type-fallback.html>",
        report_in_deps: true,
    };
    report_in_external_macro
}

declare_lint! {
    /// The `invalid_macro_export_arguments` lint detects cases where `#[macro_export]` is being used with invalid arguments.
    ///
    /// ### Example
    ///
    /// ```rust,compile_fail
    /// #![deny(invalid_macro_export_arguments)]
    ///
    /// #[macro_export(invalid_parameter)]
    /// macro_rules! myMacro {
    ///    () => {
    ///         // [...]
    ///    }
    /// }
    ///
    /// #[macro_export(too, many, items)]
    /// ```
    ///
    /// {{produces}}
    ///
    /// ### Explanation
    ///
    /// The only valid argument is `#[macro_export(local_inner_macros)]` or no argument (`#[macro_export]`).
    /// You can't have multiple arguments in a `#[macro_export(..)]`, or mention arguments other than `local_inner_macros`.
    ///
    pub INVALID_MACRO_EXPORT_ARGUMENTS,
    Deny,
    "\"invalid_parameter\" isn't a valid argument for `#[macro_export]`",
    @future_incompatible = FutureIncompatibleInfo {
        reason: FutureIncompatibilityReason::FutureReleaseError,
        reference: "issue #57571 <https://github.com/rust-lang/rust/issues/57571>",
        report_in_deps: true,
    };
}

declare_lint! {
    /// The `private_interfaces` lint detects types in a primary interface of an item,
    /// that are more private than the item itself. Primary interface of an item is all
    /// its interface except for bounds on generic parameters and where clauses.
    ///
    /// ### Example
    ///
    /// ```rust,compile_fail
    /// # #![allow(unused)]
    /// #![deny(private_interfaces)]
    /// struct SemiPriv;
    ///
    /// mod m1 {
    ///     struct Priv;
    ///     impl crate::SemiPriv {
    ///         pub fn f(_: Priv) {}
    ///     }
    /// }
    ///
    /// # fn main() {}
    /// ```
    ///
    /// {{produces}}
    ///
    /// ### Explanation
    ///
    /// Having something private in primary interface guarantees that
    /// the item will be unusable from outer modules due to type privacy.
    pub PRIVATE_INTERFACES,
    Warn,
    "private type in primary interface of an item",
}

declare_lint! {
    /// The `private_bounds` lint detects types in a secondary interface of an item,
    /// that are more private than the item itself. Secondary interface of an item consists of
    /// bounds on generic parameters and where clauses, including supertraits for trait items.
    ///
    /// ### Example
    ///
    /// ```rust,compile_fail
    /// # #![allow(unused)]
    /// #![deny(private_bounds)]
    ///
    /// struct PrivTy;
    /// pub struct S
    ///     where PrivTy:
    /// {}
    /// # fn main() {}
    /// ```
    ///
    /// {{produces}}
    ///
    /// ### Explanation
    ///
    /// Having private types or traits in item bounds makes it less clear what interface
    /// the item actually provides.
    pub PRIVATE_BOUNDS,
    Warn,
    "private type in secondary interface of an item",
}

declare_lint! {
    /// The `unnameable_types` lint detects types for which you can get objects of that type,
    /// but cannot name the type itself.
    ///
    /// ### Example
    ///
    /// ```rust,compile_fail
    /// # #![allow(unused)]
    /// #![deny(unnameable_types)]
    /// mod m {
    ///     pub struct S;
    /// }
    ///
    /// pub fn get_unnameable() -> m::S { m::S }
    /// # fn main() {}
    /// ```
    ///
    /// {{produces}}
    ///
    /// ### Explanation
    ///
    /// It is often expected that if you can obtain an object of type `T`, then
    /// you can name the type `T` as well; this lint attempts to enforce this rule.
    /// The recommended action is to either reexport the type properly to make it nameable,
    /// or document that users are not supposed to be able to name it for one reason or another.
    ///
    /// Besides types, this lint applies to traits because traits can also leak through signatures,
    /// and you may obtain objects of their `dyn Trait` or `impl Trait` types.
    pub UNNAMEABLE_TYPES,
    Allow,
    "effective visibility of a type is larger than the area in which it can be named",
}

declare_lint! {
    /// The `malformed_diagnostic_attributes` lint detects malformed diagnostic attributes.
    ///
    /// ### Example
    ///
    /// ```rust
    /// #[diagnostic::do_not_recommend(message = "message")]
    /// trait Trait {}
    /// ```
    ///
    /// {{produces}}
    ///
    /// ### Explanation
    ///
    /// It is usually a mistake to use options or syntax that is not supported. Check the spelling,
    /// and check the diagnostic attribute listing for the correct name and syntax. Also consider if
    /// you are using an old version of the compiler; perhaps the option or syntax is only available
    /// in a newer version. See the [reference] for a list of diagnostic attributes and the syntax
    /// of each.
    ///
    /// [reference]: https://doc.rust-lang.org/nightly/reference/attributes/diagnostics.html#the-diagnostic-tool-attribute-namespace
    pub MALFORMED_DIAGNOSTIC_ATTRIBUTES,
    Warn,
    "detects malformed diagnostic attributes",
}

declare_lint! {
    /// The `misplaced_diagnostic_attributes` lint detects wrongly placed diagnostic attributes.
    ///
    /// ### Example
    ///
    /// ```rust
    /// #[diagnostic::do_not_recommend]
    /// struct NotUserFacing;
    /// ```
    ///
    /// {{produces}}
    ///
    /// ### Explanation
    ///
    /// It is usually a mistake to specify a diagnostic attribute on an item it is not meant for.
    /// For example, `#[diagnostic::do_not_recommend]` can only be placed on trait implementations,
    /// and does nothing if placed elsewhere. See the [reference] for a list of diagnostic
    /// attributes and their correct positions.
    ///
    /// [reference]: https://doc.rust-lang.org/nightly/reference/attributes/diagnostics.html#the-diagnostic-tool-attribute-namespace
    pub MISPLACED_DIAGNOSTIC_ATTRIBUTES,
    Warn,
    "detects diagnostic attributes that are placed on the wrong item",
}

declare_lint! {
    /// The `unknown_diagnostic_attributes` lint detects unknown diagnostic attributes.
    ///
    /// ### Example
    ///
    /// ```rust
    /// #[diagnostic::does_not_exist]
    /// struct Thing;
    /// ```
    ///
    /// {{produces}}
    ///
    /// ### Explanation
    ///
    /// It is usually a mistake to specify a diagnostic attribute that does not exist. Check the
    /// spelling, and check the diagnostic attribute listing for the correct name. Also consider if
    /// you are using an old version of the compiler and the attribute is only available in a newer
    /// version. See the [reference] for the list of diagnostic attributes.
    ///
    /// [reference]: https://doc.rust-lang.org/nightly/reference/attributes/diagnostics.html#the-diagnostic-tool-attribute-namespace
    pub UNKNOWN_DIAGNOSTIC_ATTRIBUTES,
    Warn,
    "detects unknown diagnostic attributes",
}

declare_lint! {
    /// The `malformed_diagnostic_format_literals` lint detects malformed diagnostic format
    /// literals.
    ///
    /// ### Example
    ///
    /// ```rust
    /// #[diagnostic::on_unimplemented(message = "{Self}} does not implement `Trait`")]
    /// trait Trait {}
    /// ```
    ///
    /// {{produces}}
    ///
    /// ### Explanation
    ///
    /// The `#[diagnostic::on_unimplemented]` attribute accepts string literal values that are
    /// similar to `format!`'s string literal. See the [reference] for details on what is permitted
    /// in this string literal.
    ///
    /// [reference]: https://doc.rust-lang.org/nightly/reference/attributes/diagnostics.html#the-diagnostic-tool-attribute-namespace
    pub MALFORMED_DIAGNOSTIC_FORMAT_LITERALS,
    Warn,
    "detects diagnostic attribute with malformed diagnostic format literals",
}
declare_lint! {
    /// The `ambiguous_glob_imports` lint detects glob imports that should report ambiguity
    /// errors, but previously didn't do that due to rustc bugs.
    ///
    /// ### Example
    ///
    /// ```rust,compile_fail
    /// #![deny(ambiguous_glob_imports)]
    /// pub fn foo() -> u32 {
    ///     use sub::*;
    ///     C
    /// }
    ///
    /// mod sub {
    ///     mod mod1 { pub const C: u32 = 1; }
    ///     mod mod2 { pub const C: u32 = 2; }
    ///
    ///     pub use mod1::*;
    ///     pub use mod2::*;
    /// }
    /// ```
    ///
    /// {{produces}}
    ///
    /// ### Explanation
    ///
    /// Previous versions of Rust compile it successfully because it
    /// had lost the ambiguity error when resolve `use sub::mod2::*`.
    ///
    /// This is a [future-incompatible] lint to transition this to a
    /// hard error in the future.
    ///
    /// [future-incompatible]: ../index.md#future-incompatible-lints
    pub AMBIGUOUS_GLOB_IMPORTS,
    Deny,
    "detects certain glob imports that require reporting an ambiguity error",
    @future_incompatible = FutureIncompatibleInfo {
        reason: FutureIncompatibilityReason::FutureReleaseError,
        reference: "issue #114095 <https://github.com/rust-lang/rust/issues/114095>",
        report_in_deps: true,
    };
}

declare_lint! {
    /// The `refining_impl_trait_reachable` lint detects `impl Trait` return
    /// types in method signatures that are refined by a publically reachable
    /// trait implementation, meaning the implementation adds information about
    /// the return type that is not present in the trait.
    ///
    /// ### Example
    ///
    /// ```rust,compile_fail
    /// #![deny(refining_impl_trait)]
    ///
    /// use std::fmt::Display;
    ///
    /// pub trait AsDisplay {
    ///     fn as_display(&self) -> impl Display;
    /// }
    ///
    /// impl<'s> AsDisplay for &'s str {
    ///     fn as_display(&self) -> Self {
    ///         *self
    ///     }
    /// }
    ///
    /// fn main() {
    ///     // users can observe that the return type of
    ///     // `<&str as AsDisplay>::as_display()` is `&str`.
    ///     let _x: &str = "".as_display();
    /// }
    /// ```
    ///
    /// {{produces}}
    ///
    /// ### Explanation
    ///
    /// Callers of methods for types where the implementation is known are
    /// able to observe the types written in the impl signature. This may be
    /// intended behavior, but may also lead to implementation details being
    /// revealed unintentionally. In particular, it may pose a semver hazard
    /// for authors of libraries who do not wish to make stronger guarantees
    /// about the types than what is written in the trait signature.
    ///
    /// `refining_impl_trait` is a lint group composed of two lints:
    ///
    /// * `refining_impl_trait_reachable`, for refinements that are publically
    ///   reachable outside a crate, and
    /// * `refining_impl_trait_internal`, for refinements that are only visible
    ///    within a crate.
    ///
    /// We are seeking feedback on each of these lints; see issue
    /// [#121718](https://github.com/rust-lang/rust/issues/121718) for more
    /// information.
    pub REFINING_IMPL_TRAIT_REACHABLE,
    Warn,
    "impl trait in impl method signature does not match trait method signature",
}

declare_lint! {
    /// The `refining_impl_trait_internal` lint detects `impl Trait` return
    /// types in method signatures that are refined by a trait implementation,
    /// meaning the implementation adds information about the return type that
    /// is not present in the trait.
    ///
    /// ### Example
    ///
    /// ```rust,compile_fail
    /// #![deny(refining_impl_trait)]
    ///
    /// use std::fmt::Display;
    ///
    /// trait AsDisplay {
    ///     fn as_display(&self) -> impl Display;
    /// }
    ///
    /// impl<'s> AsDisplay for &'s str {
    ///     fn as_display(&self) -> Self {
    ///         *self
    ///     }
    /// }
    ///
    /// fn main() {
    ///     // users can observe that the return type of
    ///     // `<&str as AsDisplay>::as_display()` is `&str`.
    ///     let _x: &str = "".as_display();
    /// }
    /// ```
    ///
    /// {{produces}}
    ///
    /// ### Explanation
    ///
    /// Callers of methods for types where the implementation is known are
    /// able to observe the types written in the impl signature. This may be
    /// intended behavior, but may also lead to implementation details being
    /// revealed unintentionally. In particular, it may pose a semver hazard
    /// for authors of libraries who do not wish to make stronger guarantees
    /// about the types than what is written in the trait signature.
    ///
    /// `refining_impl_trait` is a lint group composed of two lints:
    ///
    /// * `refining_impl_trait_reachable`, for refinements that are publically
    ///   reachable outside a crate, and
    /// * `refining_impl_trait_internal`, for refinements that are only visible
    ///    within a crate.
    ///
    /// We are seeking feedback on each of these lints; see issue
    /// [#121718](https://github.com/rust-lang/rust/issues/121718) for more
    /// information.
    pub REFINING_IMPL_TRAIT_INTERNAL,
    Warn,
    "impl trait in impl method signature does not match trait method signature",
}

declare_lint! {
    /// The `elided_lifetimes_in_associated_constant` lint detects elided lifetimes
    /// in associated constants when there are other lifetimes in scope. This was
    /// accidentally supported, and this lint was later relaxed to allow eliding
    /// lifetimes to `'static` when there are no lifetimes in scope.
    ///
    /// ### Example
    ///
    /// ```rust,compile_fail
    /// #![deny(elided_lifetimes_in_associated_constant)]
    ///
    /// struct Foo<'a>(&'a ());
    ///
    /// impl<'a> Foo<'a> {
    ///     const STR: &str = "hello, world";
    /// }
    /// ```
    ///
    /// {{produces}}
    ///
    /// ### Explanation
    ///
    /// Previous version of Rust
    ///
    /// Implicit static-in-const behavior was decided [against] for associated
    /// constants because of ambiguity. This, however, regressed and the compiler
    /// erroneously treats elided lifetimes in associated constants as lifetime
    /// parameters on the impl.
    ///
    /// This is a [future-incompatible] lint to transition this to a
    /// hard error in the future.
    ///
    /// [against]: https://github.com/rust-lang/rust/issues/38831
    /// [future-incompatible]: ../index.md#future-incompatible-lints
    pub ELIDED_LIFETIMES_IN_ASSOCIATED_CONSTANT,
    Deny,
    "elided lifetimes cannot be used in associated constants in impls",
    @future_incompatible = FutureIncompatibleInfo {
        reason: FutureIncompatibilityReason::FutureReleaseError,
        reference: "issue #115010 <https://github.com/rust-lang/rust/issues/115010>",
    };
}

declare_lint! {
    /// The `private_macro_use` lint detects private macros that are imported
    /// with `#[macro_use]`.
    ///
    /// ### Example
    ///
    /// ```rust,ignore (needs extern crate)
    /// // extern_macro.rs
    /// macro_rules! foo_ { () => {}; }
    /// use foo_ as foo;
    ///
    /// // code.rs
    ///
    /// #![deny(private_macro_use)]
    ///
    /// #[macro_use]
    /// extern crate extern_macro;
    ///
    /// fn main() {
    ///     foo!();
    /// }
    /// ```
    ///
    /// This will produce:
    ///
    /// ```text
    /// error: cannot find macro `foo` in this scope
    /// ```
    ///
    /// ### Explanation
    ///
    /// This lint arises from overlooking visibility checks for macros
    /// in an external crate.
    ///
    /// This is a [future-incompatible] lint to transition this to a
    /// hard error in the future.
    ///
    /// [future-incompatible]: ../index.md#future-incompatible-lints
    pub PRIVATE_MACRO_USE,
    Deny,
    "detects certain macro bindings that should not be re-exported",
    @future_incompatible = FutureIncompatibleInfo {
        reason: FutureIncompatibilityReason::FutureReleaseError,
        reference: "issue #120192 <https://github.com/rust-lang/rust/issues/120192>",
        report_in_deps: true,
    };
}

declare_lint! {
    /// The `uncovered_param_in_projection` lint detects a violation of one of Rust's orphan rules for
    /// foreign trait implementations that concerns the use of type parameters inside trait associated
    /// type paths ("projections") whose output may not be a local type that is mistakenly considered
    /// to "cover" said parameters which is **unsound** and which may be rejected by a future version
    /// of the compiler.
    ///
    /// Originally reported in [#99554].
    ///
    /// [#99554]: https://github.com/rust-lang/rust/issues/99554
    ///
    /// ### Example
    ///
    /// ```rust,ignore (dependent)
    /// // dependency.rs
    /// #![crate_type = "lib"]
    ///
    /// pub trait Trait<T, U> {}
    /// ```
    ///
    /// ```edition2021,ignore (needs dependency)
    /// // dependent.rs
    /// trait Identity {
    ///     type Output;
    /// }
    ///
    /// impl<T> Identity for T {
    ///     type Output = T;
    /// }
    ///
    /// struct Local;
    ///
    /// impl<T> dependency::Trait<Local, T> for <T as Identity>::Output {}
    ///
    /// fn main() {}
    /// ```
    ///
    /// This will produce:
    ///
    /// ```text
    /// warning[E0210]: type parameter `T` must be covered by another type when it appears before the first local type (`Local`)
    ///   --> dependent.rs:11:6
    ///    |
    /// 11 | impl<T> dependency::Trait<Local, T> for <T as Identity>::Output {}
    ///    |      ^ type parameter `T` must be covered by another type when it appears before the first local type (`Local`)
    ///    |
    ///    = warning: this was previously accepted by the compiler but is being phased out; it will become a hard error in a future release!
    ///    = note: for more information, see issue #124559 <https://github.com/rust-lang/rust/issues/124559>
    ///    = note: implementing a foreign trait is only possible if at least one of the types for which it is implemented is local, and no uncovered type parameters appear before that first local type
    ///    = note: in this case, 'before' refers to the following order: `impl<..> ForeignTrait<T1, ..., Tn> for T0`, where `T0` is the first and `Tn` is the last
    ///    = note: `#[warn(uncovered_param_in_projection)]` on by default
    /// ```
    ///
    /// ### Explanation
    ///
    /// FIXME(fmease): Write explainer.
    pub UNCOVERED_PARAM_IN_PROJECTION,
    Warn,
    "impl contains type parameters that are not covered",
    @future_incompatible = FutureIncompatibleInfo {
        reason: FutureIncompatibilityReason::FutureReleaseError,
        reference: "issue #124559 <https://github.com/rust-lang/rust/issues/124559>",
    };
}

declare_lint! {
    /// The `deprecated_safe_2024` lint detects unsafe functions being used as
    /// safe functions.
    ///
    /// ### Example
    ///
    /// ```rust,edition2021,compile_fail
    /// #![deny(deprecated_safe)]
    /// // edition 2021
    /// use std::env;
    /// fn enable_backtrace() {
    ///     env::set_var("RUST_BACKTRACE", "1");
    /// }
    /// ```
    ///
    /// {{produces}}
    ///
    /// ### Explanation
    ///
    /// Rust [editions] allow the language to evolve without breaking backward
    /// compatibility. This lint catches code that uses `unsafe` functions that
    /// were declared as safe (non-`unsafe`) in editions prior to Rust 2024. If
    /// you switch the compiler to Rust 2024 without updating the code, then it
    /// will fail to compile if you are using a function previously marked as
    /// safe.
    ///
    /// You can audit the code to see if it suffices the preconditions of the
    /// `unsafe` code, and if it does, you can wrap it in an `unsafe` block. If
    /// you can't fulfill the preconditions, you probably need to switch to a
    /// different way of doing what you want to achieve.
    ///
    /// This lint can automatically wrap the calls in `unsafe` blocks, but this
    /// obviously cannot verify that the preconditions of the `unsafe`
    /// functions are fulfilled, so that is still up to the user.
    ///
    /// The lint is currently "allow" by default, but that might change in the
    /// future.
    ///
    /// [editions]: https://doc.rust-lang.org/edition-guide/
    pub DEPRECATED_SAFE_2024,
    Allow,
    "detects unsafe functions being used as safe functions",
    @future_incompatible = FutureIncompatibleInfo {
        reason: FutureIncompatibilityReason::EditionError(Edition::Edition2024),
        reference: "<https://doc.rust-lang.org/edition-guide/rust-2024/newly-unsafe-functions.html>",
    };
}

declare_lint! {
    /// The `missing_unsafe_on_extern` lint detects missing unsafe keyword on extern declarations.
    ///
    /// ### Example
    ///
    /// ```rust,edition2021
    /// #![warn(missing_unsafe_on_extern)]
    /// #![allow(dead_code)]
    ///
    /// extern "C" {
    ///     fn foo(_: i32);
    /// }
    ///
    /// fn main() {}
    /// ```
    ///
    /// {{produces}}
    ///
    /// ### Explanation
    ///
    /// Declaring extern items, even without ever using them, can cause Undefined Behavior. We
    /// should consider all sources of Undefined Behavior to be unsafe.
    ///
    /// This is a [future-incompatible] lint to transition this to a
    /// hard error in the future.
    ///
    /// [future-incompatible]: ../index.md#future-incompatible-lints
    pub MISSING_UNSAFE_ON_EXTERN,
    Allow,
    "detects missing unsafe keyword on extern declarations",
    @future_incompatible = FutureIncompatibleInfo {
        reason: FutureIncompatibilityReason::EditionError(Edition::Edition2024),
        reference: "<https://doc.rust-lang.org/edition-guide/rust-2024/unsafe-extern.html>",
    };
}

declare_lint! {
    /// The `unsafe_attr_outside_unsafe` lint detects a missing unsafe keyword
    /// on attributes considered unsafe.
    ///
    /// ### Example
    ///
    /// ```rust,edition2021
    /// #![warn(unsafe_attr_outside_unsafe)]
    ///
    /// #[no_mangle]
    /// extern "C" fn foo() {}
    ///
    /// fn main() {}
    /// ```
    ///
    /// {{produces}}
    ///
    /// ### Explanation
    ///
    /// Some attributes (e.g. `no_mangle`, `export_name`, `link_section` -- see
    /// [issue #82499] for a more complete list) are considered "unsafe" attributes.
    /// An unsafe attribute must only be used inside unsafe(...).
    ///
    /// This lint can automatically wrap the attributes in `unsafe(...)` , but this
    /// obviously cannot verify that the preconditions of the `unsafe`
    /// attributes are fulfilled, so that is still up to the user.
    ///
    /// The lint is currently "allow" by default, but that might change in the
    /// future.
    ///
    /// [editions]: https://doc.rust-lang.org/edition-guide/
    /// [issue #82499]: https://github.com/rust-lang/rust/issues/82499
    pub UNSAFE_ATTR_OUTSIDE_UNSAFE,
    Allow,
    "detects unsafe attributes outside of unsafe",
    @future_incompatible = FutureIncompatibleInfo {
        reason: FutureIncompatibilityReason::EditionError(Edition::Edition2024),
        reference: "<https://doc.rust-lang.org/edition-guide/rust-2024/unsafe-attributes.html>",
    };
}

declare_lint! {
    /// The `out_of_scope_macro_calls` lint detects `macro_rules` called when they are not in scope,
    /// above their definition, which may happen in key-value attributes.
    ///
    /// ### Example
    ///
    /// ```rust,compile_fail
    /// #![doc = in_root!()]
    ///
    /// macro_rules! in_root { () => { "" } }
    ///
    /// fn main() {}
    /// ```
    ///
    /// {{produces}}
    ///
    /// ### Explanation
    ///
    /// The scope in which a `macro_rules` item is visible starts at that item and continues
    /// below it. This is more similar to `let` than to other items, which are in scope both above
    /// and below their definition.
    /// Due to a bug `macro_rules` were accidentally in scope inside some key-value attributes
    /// above their definition. The lint catches such cases.
    /// To address the issue turn the `macro_rules` into a regularly scoped item by importing it
    /// with `use`.
    ///
    /// This is a [future-incompatible] lint to transition this to a
    /// hard error in the future.
    ///
    /// [future-incompatible]: ../index.md#future-incompatible-lints
    pub OUT_OF_SCOPE_MACRO_CALLS,
    Deny,
    "detects out of scope calls to `macro_rules` in key-value attributes",
    @future_incompatible = FutureIncompatibleInfo {
        reason: FutureIncompatibilityReason::FutureReleaseError,
        reference: "issue #124535 <https://github.com/rust-lang/rust/issues/124535>",
        report_in_deps: true,
    };
}

declare_lint! {
    /// The `supertrait_item_shadowing_usage` lint detects when the
    /// usage of an item that is provided by both a subtrait and supertrait
    /// is shadowed, preferring the subtrait.
    ///
    /// ### Example
    ///
    /// ```rust,compile_fail
    /// #![feature(supertrait_item_shadowing)]
    /// #![deny(supertrait_item_shadowing_usage)]
    ///
    /// trait Upstream {
    ///     fn hello(&self) {}
    /// }
    /// impl<T> Upstream for T {}
    ///
    /// trait Downstream: Upstream {
    ///     fn hello(&self) {}
    /// }
    /// impl<T> Downstream for T {}
    ///
    /// struct MyType;
    /// MyType.hello();
    /// ```
    ///
    /// {{produces}}
    ///
    /// ### Explanation
    ///
    /// RFC 3624 specified a heuristic in which a supertrait item would be
    /// shadowed by a subtrait item when ambiguity occurs during item
    /// selection. In order to mitigate side-effects of this happening
    /// silently, this lint detects these cases when users want to deny them
    /// or fix the call sites.
    pub SUPERTRAIT_ITEM_SHADOWING_USAGE,
    // FIXME(supertrait_item_shadowing): It is not decided if this should
    // warn by default at the call site.
    Allow,
    "detects when a supertrait item is shadowed by a subtrait item",
    @feature_gate = supertrait_item_shadowing;
}

declare_lint! {
    /// The `supertrait_item_shadowing_definition` lint detects when the
    /// definition of an item that is provided by both a subtrait and
    /// supertrait is shadowed, preferring the subtrait.
    ///
    /// ### Example
    ///
    /// ```rust,compile_fail
    /// #![feature(supertrait_item_shadowing)]
    /// #![deny(supertrait_item_shadowing_definition)]
    ///
    /// trait Upstream {
    ///     fn hello(&self) {}
    /// }
    /// impl<T> Upstream for T {}
    ///
    /// trait Downstream: Upstream {
    ///     fn hello(&self) {}
    /// }
    /// impl<T> Downstream for T {}
    /// ```
    ///
    /// {{produces}}
    ///
    /// ### Explanation
    ///
    /// RFC 3624 specified a heuristic in which a supertrait item would be
    /// shadowed by a subtrait item when ambiguity occurs during item
    /// selection. In order to mitigate side-effects of this happening
    /// silently, this lint detects these cases when users want to deny them
    /// or fix their trait definitions.
    pub SUPERTRAIT_ITEM_SHADOWING_DEFINITION,
    // FIXME(supertrait_item_shadowing): It is not decided if this should
    // warn by default at the usage site.
    Allow,
    "detects when a supertrait item is shadowed by a subtrait item",
    @feature_gate = supertrait_item_shadowing;
}

declare_lint! {
    /// The `tail_expr_drop_order` lint looks for those values generated at the tail expression location,
    /// that runs a custom `Drop` destructor.
    /// Some of them may be dropped earlier in Edition 2024 that they used to in Edition 2021 and prior.
    /// This lint detects those cases and provides you information on those values and their custom destructor implementations.
    /// Your discretion on this information is required.
    ///
    /// ### Example
    /// ```rust,edition2021
    /// #![warn(tail_expr_drop_order)]
    /// struct Droppy(i32);
    /// impl Droppy {
    ///     fn get(&self) -> i32 {
    ///         self.0
    ///     }
    /// }
    /// impl Drop for Droppy {
    ///     fn drop(&mut self) {
    ///         // This is a custom destructor and it induces side-effects that is observable
    ///         // especially when the drop order at a tail expression changes.
    ///         println!("loud drop {}", self.0);
    ///     }
    /// }
    /// fn edition_2021() -> i32 {
    ///     let another_droppy = Droppy(0);
    ///     Droppy(1).get()
    /// }
    /// fn main() {
    ///     edition_2021();
    /// }
    /// ```
    ///
    /// {{produces}}
    ///
    /// ### Explanation
    ///
    /// In tail expression of blocks or function bodies,
    /// values of type with significant `Drop` implementation has an ill-specified drop order
    /// before Edition 2024 so that they are dropped only after dropping local variables.
    /// Edition 2024 introduces a new rule with drop orders for them,
    /// so that they are dropped first before dropping local variables.
    ///
    /// A significant `Drop::drop` destructor here refers to an explicit, arbitrary
    /// implementation of the `Drop` trait on the type, with exceptions including `Vec`,
    /// `Box`, `Rc`, `BTreeMap` and `HashMap` that are marked by the compiler otherwise
    /// so long that the generic types have no significant destructor recursively.
    /// In other words, a type has a significant drop destructor when it has a `Drop` implementation
    /// or its destructor invokes a significant destructor on a type.
    /// Since we cannot completely reason about the change by just inspecting the existence of
    /// a significant destructor, this lint remains only a suggestion and is set to `allow` by default.
    ///
    /// This lint only points out the issue with `Droppy`, which will be dropped before `another_droppy`
    /// does in Edition 2024.
    /// No fix will be proposed by this lint.
    /// However, the most probable fix is to hoist `Droppy` into its own local variable binding.
    /// ```rust
    /// struct Droppy(i32);
    /// impl Droppy {
    ///     fn get(&self) -> i32 {
    ///         self.0
    ///     }
    /// }
    /// fn edition_2024() -> i32 {
    ///     let value = Droppy(0);
    ///     let another_droppy = Droppy(1);
    ///     value.get()
    /// }
    /// ```
    pub TAIL_EXPR_DROP_ORDER,
    Allow,
    "Detect and warn on significant change in drop order in tail expression location",
    @future_incompatible = FutureIncompatibleInfo {
        reason: FutureIncompatibilityReason::EditionSemanticsChange(Edition::Edition2024),
        reference: "<https://doc.rust-lang.org/edition-guide/rust-2024/temporary-tail-expr-scope.html>",
    };
}

declare_lint! {
    /// The `rust_2024_guarded_string_incompatible_syntax` lint detects `#` tokens
    /// that will be parsed as part of a guarded string literal in Rust 2024.
    ///
    /// ### Example
    ///
    /// ```rust,edition2021,compile_fail
    /// #![deny(rust_2024_guarded_string_incompatible_syntax)]
    ///
    /// macro_rules! m {
    ///     (# $x:expr #) => ();
    ///     (# $x:expr) => ();
    /// }
    ///
    /// m!(#"hey"#);
    /// m!(#"hello");
    /// ```
    ///
    /// {{produces}}
    ///
    /// ### Explanation
    ///
    /// Prior to Rust 2024, `#"hey"#` is three tokens: the first `#`
    /// followed by the string literal `"hey"` then the final `#`.
    /// In Rust 2024, the whole sequence is considered a single token.
    ///
    /// This lint suggests to add whitespace between the leading `#`
    /// and the string to keep them separated in Rust 2024.
    // Allow this lint -- rustdoc doesn't yet support threading edition into this lint's parser.
    #[allow(rustdoc::invalid_rust_codeblocks)]
    pub RUST_2024_GUARDED_STRING_INCOMPATIBLE_SYNTAX,
    Allow,
    "will be parsed as a guarded string in Rust 2024",
    @future_incompatible = FutureIncompatibleInfo {
        reason: FutureIncompatibilityReason::EditionError(Edition::Edition2024),
        reference: "<https://doc.rust-lang.org/edition-guide/rust-2024/reserved-syntax.html>",
    };
    crate_level_only
}

declare_lint! {
    /// The `aarch64_softfloat_neon` lint detects usage of `#[target_feature(enable = "neon")]` on
    /// softfloat aarch64 targets. Enabling this target feature causes LLVM to alter the ABI of
    /// function calls, making this attribute unsound to use.
    ///
    /// ### Example
    ///
    /// ```rust,ignore (needs aarch64-unknown-none-softfloat)
    /// #[target_feature(enable = "neon")]
    /// fn with_neon() {}
    /// ```
    ///
    /// This will produce:
    ///
    /// ```text
    /// error: enabling the `neon` target feature on the current target is unsound due to ABI issues
    ///   --> $DIR/abi-incompatible-target-feature-attribute-fcw.rs:11:18
    ///    |
    ///    | #[target_feature(enable = "neon")]
    ///    |                  ^^^^^^^^^^^^^^^
    ///    |
    ///    = warning: this was previously accepted by the compiler but is being phased out; it will become a hard error in a future release!
    ///    = note: for more information, see issue #134375 <https://github.com/rust-lang/rust/issues/134375>
    /// ```
    ///
    /// ### Explanation
    ///
    /// If a function like `with_neon` above ends up containing calls to LLVM builtins, those will
    /// not use the correct ABI. This is caused by a lack of support in LLVM for mixing code with
    /// and without the `neon` target feature. The target feature should never have been stabilized
    /// on this target due to this issue, but the problem was not known at the time of
    /// stabilization.
    pub AARCH64_SOFTFLOAT_NEON,
    Warn,
    "detects code that could be affected by ABI issues on aarch64 softfloat targets",
    @future_incompatible = FutureIncompatibleInfo {
        reason: FutureIncompatibilityReason::FutureReleaseError,
        reference: "issue #134375 <https://github.com/rust-lang/rust/issues/134375>",
        report_in_deps: true,
    };
}

declare_lint! {
    /// The `tail_call_track_caller` lint detects usage of `become` attempting to tail call
    /// a function marked with `#[track_caller]`.
    ///
    /// ### Example
    ///
    /// ```rust
    /// #![feature(explicit_tail_calls)]
    /// #![expect(incomplete_features)]
    ///
    /// #[track_caller]
    /// fn f() {}
    ///
    /// fn g() {
    ///     become f();
    /// }
    ///
    /// g();
    /// ```
    ///
    /// {{produces}}
    ///
    /// ### Explanation
    ///
    /// Due to implementation details of tail calls and `#[track_caller]` attribute, calls to
    /// functions marked with `#[track_caller]` cannot become tail calls. As such using `become`
    /// is no different than a normal call (except for changes in drop order).
    pub TAIL_CALL_TRACK_CALLER,
    Warn,
    "detects tail calls of functions marked with `#[track_caller]`",
    @feature_gate = explicit_tail_calls;
}
declare_lint! {
    /// The `inline_always_mismatching_target_features` lint will trigger when a
    /// function with the `#[inline(always)]` and `#[target_feature(enable = "...")]`
    /// attributes is called and cannot be inlined due to missing target features in the caller.
    ///
    /// ### Example
    ///
    /// ```rust,ignore (fails on x86_64)
    /// #[inline(always)]
    /// #[target_feature(enable = "fp16")]
    /// unsafe fn callee() {
    ///     // operations using fp16 types
    /// }
    ///
    /// // Caller does not enable the required target feature
    /// fn caller() {
    ///     unsafe { callee(); }
    /// }
    ///
    /// fn main() {
    ///     caller();
    /// }
    /// ```
    ///
    /// This will produce:
    ///
    /// ```text
    /// warning: call to `#[inline(always)]`-annotated `callee` requires the same target features. Function will not have `alwaysinline` attribute applied
    ///   --> $DIR/builtin.rs:5192:14
    ///    |
    /// 10 |     unsafe { callee(); }
    ///    |              ^^^^^^^^
    ///    |
    /// note: `fp16` target feature enabled in `callee` here but missing from `caller`
    ///   --> $DIR/builtin.rs:5185:1
    ///    |
    /// 3  | #[target_feature(enable = "fp16")]
    ///    | ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    /// 4  | unsafe fn callee() {
    ///    | ------------------
    ///    = note: `#[warn(inline_always_mismatching_target_features)]` on by default
    /// warning: 1 warning emitted
    /// ```
    ///
    /// ### Explanation
    ///
    /// Inlining a function with a target feature attribute into a caller that
    /// lacks the corresponding target feature can lead to unsound behavior.
    /// LLVM may select the wrong instructions or registers, or reorder
    /// operations, potentially resulting in runtime errors.
    pub INLINE_ALWAYS_MISMATCHING_TARGET_FEATURES,
    Warn,
    r#"detects when a function annotated with `#[inline(always)]` and `#[target_feature(enable = "..")]` is inlined into a caller without the required target feature"#,
}

declare_lint! {
    /// The `repr_c_enums_larger_than_int` lint detects `repr(C)` enums with discriminant
    /// values that do not fit into a C `int` or `unsigned int`.
    ///
    /// ### Example
    ///
    /// ```rust,ignore (only errors on 64bit)
    /// #[repr(C)]
    /// enum E {
    ///     V = 9223372036854775807, // i64::MAX
    /// }
    /// ```
    ///
    /// This will produce:
    ///
    /// ```text
    /// error: `repr(C)` enum discriminant does not fit into C `int` nor into C `unsigned int`
    ///   --> $DIR/repr-c-big-discriminant1.rs:16:5
    ///    |
    /// LL |     A = 9223372036854775807, // i64::MAX
    ///    |     ^
    ///    |
    ///    = note: `repr(C)` enums with big discriminants are non-portable, and their size in Rust might not match their size in C
    ///    = help: use `repr($int_ty)` instead to explicitly set the size of this enum
    /// ```
    ///
    /// ### Explanation
    ///
    /// In C, enums with discriminants that do not all fit into an `int` or all fit into an
    /// `unsigned int` are a portability hazard: such enums are only permitted since C23, and not
    /// supported e.g. by MSVC.
    ///
    /// Furthermore, Rust interprets the discriminant values of `repr(C)` enums as expressions of
    /// type `isize`. This makes it impossible to implement the C23 behavior of enums where the enum
    /// discriminants have no predefined type and instead the enum uses a type large enough to hold
    /// all discriminants.
    ///
    /// Therefore, `repr(C)` enums in Rust require that either all discriminants to fit into a C
    /// `int` or they all fit into an `unsigned int`.
    pub REPR_C_ENUMS_LARGER_THAN_INT,
    Warn,
    "repr(C) enums with discriminant values that do not fit into a C int",
    @future_incompatible = FutureIncompatibleInfo {
        reason: FutureIncompatibilityReason::FutureReleaseError,
        reference: "issue #124403 <https://github.com/rust-lang/rust/issues/124403>",
        report_in_deps: false,
    };
}

declare_lint! {
    /// The `varargs_without_pattern` lint detects when `...` is used as an argument to a
    /// non-foreign function without any pattern being specified.
    ///
    /// ### Example
    ///
    /// ```rust
    /// // Using `...` in non-foreign function definitions is unstable, however stability is
    /// // currently only checked after attributes are expanded, so using `#[cfg(false)]` here will
    /// // allow this to compile on stable Rust.
    /// #[cfg(false)]
    /// fn foo(...) {
    ///
    /// }
    /// ```
    ///
    /// {{produces}}
    ///
    /// ### Explanation
    ///
    /// Patterns are currently required for all non-`...` arguments in function definitions (with
    /// some exceptions in the 2015 edition). Requiring `...` arguments to have patterns in
    /// non-foreign function definitions makes the language more consistent, and removes a source of
    /// confusion for the unstable C variadic feature. `...` arguments without a pattern are already
    /// stable and widely used in foreign function definitions; this lint only affects non-foreign
    /// function definitions.
    ///
    /// Using `...` (C varargs) in a non-foreign function definition is currently unstable. However,
    /// stability checking for the `...` syntax in non-foreign function definitions is currently
    /// implemented after attributes have been expanded, meaning that if the attribute removes the
    /// use of the unstable syntax (e.g. `#[cfg(false)]`, or a procedural macro), the code will
    /// compile on stable Rust; this is the only situation where this lint affects code that
    /// compiles on stable Rust.
    ///
    /// This is a [future-incompatible] lint to transition this to a hard error in the future.
    ///
    /// [future-incompatible]: ../index.md#future-incompatible-lints
    pub VARARGS_WITHOUT_PATTERN,
    Warn,
    "detects usage of `...` arguments without a pattern in non-foreign items",
    @future_incompatible = FutureIncompatibleInfo {
        reason: FutureIncompatibilityReason::FutureReleaseError,
        reference: "issue #145544 <https://github.com/rust-lang/rust/issues/145544>",
        report_in_deps: false,
    };
}

```

**💡 建议：**
Ensure Drop implementations never panic

#### 漏洞 #4：Potential panic in Drop implementation detected

**详情：**
- **Type:** `drop-panic`
- **Severity:** `Critical`
- **Confidence:** `90.0%`
- **Location:** `d:\漏洞挖掘\detector\project\rust-main\library\std\src\io\buffered\bufwriter.rs:0`
- **检测方法：** `StaticAnalysis`

**解释：**
Drop implementation may panic, which can cause undefined behavior

**代码：**
```rust
impl < W : ? Sized + Write > BufWriter < W > { # [doc = " Send data in our local buffer into the inner writer, looping as"] # [doc = " necessary until either it's all been sent or an error occurs."] # [doc = ""] # [doc = " Because all the data in the buffer has been reported to our owner as"] # [doc = " \"successfully written\" (by returning nonzero success values from"] # [doc = " `write`), any 0-length writes from `inner` must be reported as i/o"] # [doc = " errors from this method."] pub (in crate :: io) fn flush_buf (& mut self) -> io :: Result < () > { # [doc = " Helper struct to ensure the buffer is updated after all the writes"] # [doc = " are complete. It tracks the number of written bytes and drains them"] # [doc = " all from the front of the buffer when dropped."] struct BufGuard < 'a > { buffer : & 'a mut Vec < u8 > , written : usize , } impl < 'a > BufGuard < 'a > { fn new (buffer : & 'a mut Vec < u8 >) -> Self { Self { buffer , written : 0 } } # [doc = " The unwritten part of the buffer"] fn remaining (& self) -> & [u8] { & self . buffer [self . written ..] } # [doc = " Flag some bytes as removed from the front of the buffer"] fn consume (& mut self , amt : usize) { self . written += amt ; } # [doc = " true if all of the bytes have been written"] fn done (& self) -> bool { self . written >= self . buffer . len () } } impl Drop for BufGuard < '_ > { fn drop (& mut self) { if self . written > 0 { self . buffer . drain (.. self . written) ; } } } let mut guard = BufGuard :: new (& mut self . buf) ; while ! guard . done () { self . panicked = true ; let r = self . inner . write (guard . remaining ()) ; self . panicked = false ; match r { Ok (0) => { return Err (io :: const_error ! (ErrorKind :: WriteZero , "failed to write the buffered data" ,)) ; } Ok (n) => guard . consume (n) , Err (ref e) if e . is_interrupted () => { } Err (e) => return Err (e) , } } Ok (()) } # [doc = " Buffer some data without flushing it, regardless of the size of the"] # [doc = " data. Writes as much as possible without exceeding capacity. Returns"] # [doc = " the number of bytes written."] pub (super) fn write_to_buf (& mut self , buf : & [u8]) -> usize { let available = self . spare_capacity () ; let amt_to_buffer = available . min (buf . len ()) ; unsafe { self . write_to_buffer_unchecked (& buf [.. amt_to_buffer]) ; } amt_to_buffer } # [doc = " Gets a reference to the underlying writer."] # [doc = ""] # [doc = " # Examples"] # [doc = ""] # [doc = " ```no_run"] # [doc = " use std::io::BufWriter;"] # [doc = " use std::net::TcpStream;"] # [doc = ""] # [doc = " let mut buffer = BufWriter::new(TcpStream::connect(\"127.0.0.1:34254\").unwrap());"] # [doc = ""] # [doc = " // we can use reference just like buffer"] # [doc = " let reference = buffer.get_ref();"] # [doc = " ```"] # [stable (feature = "rust1" , since = "1.0.0")] pub fn get_ref (& self) -> & W { & self . inner } # [doc = " Gets a mutable reference to the underlying writer."] # [doc = ""] # [doc = " It is inadvisable to directly write to the underlying writer."] # [doc = ""] # [doc = " # Examples"] # [doc = ""] # [doc = " ```no_run"] # [doc = " use std::io::BufWriter;"] # [doc = " use std::net::TcpStream;"] # [doc = ""] # [doc = " let mut buffer = BufWriter::new(TcpStream::connect(\"127.0.0.1:34254\").unwrap());"] # [doc = ""] # [doc = " // we can use reference just like buffer"] # [doc = " let reference = buffer.get_mut();"] # [doc = " ```"] # [stable (feature = "rust1" , since = "1.0.0")] pub fn get_mut (& mut self) -> & mut W { & mut self . inner } # [doc = " Returns a reference to the internally buffered data."] # [doc = ""] # [doc = " # Examples"] # [doc = ""] # [doc = " ```no_run"] # [doc = " use std::io::BufWriter;"] # [doc = " use std::net::TcpStream;"] # [doc = ""] # [doc = " let buf_writer = BufWriter::new(TcpStream::connect(\"127.0.0.1:34254\").unwrap());"] # [doc = ""] # [doc = " // See how many bytes are currently buffered"] # [doc = " let bytes_buffered = buf_writer.buffer().len();"] # [doc = " ```"] # [stable (feature = "bufreader_buffer" , since = "1.37.0")] pub fn buffer (& self) -> & [u8] { & self . buf } # [doc = " Returns a mutable reference to the internal buffer."] # [doc = ""] # [doc = " This can be used to write data directly into the buffer without triggering writers"] # [doc = " to the underlying writer."] # [doc = ""] # [doc = " That the buffer is a `Vec` is an implementation detail."] # [doc = " Callers should not modify the capacity as there currently is no public API to do so"] # [doc = " and thus any capacity changes would be unexpected by the user."] pub (in crate :: io) fn buffer_mut (& mut self) -> & mut Vec < u8 > { & mut self . buf } # [doc = " Returns the number of bytes the internal buffer can hold without flushing."] # [doc = ""] # [doc = " # Examples"] # [doc = ""] # [doc = " ```no_run"] # [doc = " use std::io::BufWriter;"] # [doc = " use std::net::TcpStream;"] # [doc = ""] # [doc = " let buf_writer = BufWriter::new(TcpStream::connect(\"127.0.0.1:34254\").unwrap());"] # [doc = ""] # [doc = " // Check the capacity of the inner buffer"] # [doc = " let capacity = buf_writer.capacity();"] # [doc = " // Calculate how many bytes can be written without flushing"] # [doc = " let without_flush = capacity - buf_writer.buffer().len();"] # [doc = " ```"] # [stable (feature = "buffered_io_capacity" , since = "1.46.0")] pub fn capacity (& self) -> usize { self . buf . capacity () } # [cold] # [inline (never)] fn write_cold (& mut self , buf : & [u8]) -> io :: Result < usize > { if buf . len () > self . spare_capacity () { self . flush_buf () ? ; } if buf . len () >= self . buf . capacity () { self . panicked = true ; let r = self . get_mut () . write (buf) ; self . panicked = false ; r } else { unsafe { self . write_to_buffer_unchecked (buf) ; } Ok (buf . len ()) } } # [cold] # [inline (never)] fn write_all_cold (& mut self , buf : & [u8]) -> io :: Result < () > { if buf . len () > self . spare_capacity () { self . flush_buf () ? ; } if buf . len () >= self . buf . capacity () { self . panicked = true ; let r = self . get_mut () . write_all (buf) ; self . panicked = false ; r } else { unsafe { self . write_to_buffer_unchecked (buf) ; } Ok (()) } } # [inline] unsafe fn write_to_buffer_unchecked (& mut self , buf : & [u8]) { debug_assert ! (buf . len () <= self . spare_capacity ()) ; let old_len = self . buf . len () ; let buf_len = buf . len () ; let src = buf . as_ptr () ; unsafe { let dst = self . buf . as_mut_ptr () . add (old_len) ; ptr :: copy_nonoverlapping (src , dst , buf_len) ; self . buf . set_len (old_len + buf_len) ; } } # [inline] fn spare_capacity (& self) -> usize { self . buf . capacity () - self . buf . len () } }
```

**💡 建议：**
Ensure Drop implementations never panic

#### 漏洞 #5：Potential panic in Drop implementation detected

**详情：**
- **Type:** `drop-panic`
- **Severity:** `Critical`
- **Confidence:** `90.0%`
- **Location:** `d:\漏洞挖掘\detector\project\rust-main\library\std\src\io\mod.rs:0`
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

#### 漏洞 #6：Potential panic in Drop implementation detected

**详情：**
- **Type:** `drop-panic`
- **Severity:** `Critical`
- **Confidence:** `90.0%`
- **Location:** `d:\漏洞挖掘\detector\project\rust-main\library\std\src\sys\env\windows.rs:0`
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

#### 漏洞 #7：Potential panic in Drop implementation detected

**详情：**
- **Type:** `drop-panic`
- **Severity:** `Critical`
- **Confidence:** `90.0%`
- **Location:** `d:\漏洞挖掘\detector\project\rust-main\library\std\src\sys\fs\vexos.rs:0`
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

#### 漏洞 #8：Potential panic in Drop implementation detected

**详情：**
- **Type:** `drop-panic`
- **Severity:** `Critical`
- **Confidence:** `90.0%`
- **Location:** `d:\漏洞挖掘\detector\project\rust-main\library\std\src\sys\pal\unix\stack_overflow\thread_info.rs:0`
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

#### 漏洞 #9：Potential panic in Drop implementation detected

**详情：**
- **Type:** `drop-panic`
- **Severity:** `Critical`
- **Confidence:** `90.0%`
- **Location:** `d:\漏洞挖掘\detector\project\rust-main\library\std\src\sys\pal\unix\stack_overflow.rs:0`
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

#### 漏洞 #10：Potential panic in Drop implementation detected

**详情：**
- **Type:** `drop-panic`
- **Severity:** `Critical`
- **Confidence:** `90.0%`
- **Location:** `d:\漏洞挖掘\detector\project\rust-main\library\std\src\sys\pal\unix\sync\mutex.rs:0`
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

#### 漏洞 #11：Potential panic in Drop implementation detected

**详情：**
- **Type:** `drop-panic`
- **Severity:** `Critical`
- **Confidence:** `90.0%`
- **Location:** `d:\漏洞挖掘\detector\project\rust-main\library\std\src\sys\platform_version\darwin\core_foundation.rs:0`
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

#### 漏洞 #12：Potential panic in Drop implementation detected

**详情：**
- **Type:** `drop-panic`
- **Severity:** `Critical`
- **Confidence:** `90.0%`
- **Location:** `d:\漏洞挖掘\detector\project\rust-main\library\std\src\sys\process\uefi.rs:0`
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

#### 漏洞 #13：Potential panic in Drop implementation detected

**详情：**
- **Type:** `drop-panic`
- **Severity:** `Critical`
- **Confidence:** `90.0%`
- **Location:** `d:\漏洞挖掘\detector\project\rust-main\library\std\src\sys\sync\mutex\xous.rs:0`
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

#### 漏洞 #14：Potential panic in Drop implementation detected

**详情：**
- **Type:** `drop-panic`
- **Severity:** `Critical`
- **Confidence:** `90.0%`
- **Location:** `d:\漏洞挖掘\detector\project\rust-main\library\std\src\sys\sync\once\queue.rs:0`
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

#### 漏洞 #15：Potential panic in Drop implementation detected

**详情：**
- **Type:** `drop-panic`
- **Severity:** `Critical`
- **Confidence:** `90.0%`
- **Location:** `d:\漏洞挖掘\detector\project\rust-main\library\std\src\sys\thread\teeos.rs:0`
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

#### 漏洞 #16：Potential panic in Drop implementation detected

**详情：**
- **Type:** `drop-panic`
- **Severity:** `Critical`
- **Confidence:** `90.0%`
- **Location:** `d:\漏洞挖掘\detector\project\rust-main\library\std\src\sys\thread\wasip1.rs:0`
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

#### 漏洞 #17：Potential panic in Drop implementation detected

**详情：**
- **Type:** `drop-panic`
- **Severity:** `Critical`
- **Confidence:** `90.0%`
- **Location:** `d:\漏洞挖掘\detector\project\rust-main\src\tools\rust-analyzer\crates\hir-ty\src\next_solver\interner.rs:0`
- **检测方法：** `StaticAnalysis`

**解释：**
Drop implementation may panic, which can cause undefined behavior

**代码：**
```rust
//! Things related to the Interner in the next-trait-solver.

use std::{fmt, ops::ControlFlow};

pub use tls_cache::clear_tls_solver_cache;
pub use tls_db::{attach_db, attach_db_allow_change, with_attached_db};

use base_db::Crate;
use hir_def::{
    AdtId, AttrDefId, BlockId, CallableDefId, DefWithBodyId, EnumVariantId, ItemContainerId,
    StructId, UnionId, VariantId,
    lang_item::LangItem,
    signatures::{FieldData, FnFlags, ImplFlags, StructFlags, TraitFlags},
};
use la_arena::Idx;
use rustc_abi::{ReprFlags, ReprOptions};
use rustc_hash::FxHashSet;
use rustc_index::bit_set::DenseBitSet;
use rustc_type_ir::{
    AliasTermKind, AliasTyKind, BoundVar, CollectAndApply, CoroutineWitnessTypes, DebruijnIndex,
    EarlyBinder, FlagComputation, Flags, GenericArgKind, ImplPolarity, InferTy, Interner, TraitRef,
    TypeVisitableExt, UniverseIndex, Upcast, Variance,
    elaborate::elaborate,
    error::TypeError,
    inherent::{self, GenericsOf, IntoKind, SliceLike as _, Span as _, Ty as _},
    lang_items::{SolverAdtLangItem, SolverLangItem, SolverTraitLangItem},
    solve::SizedTraitKind,
};

use crate::{
    FnAbi,
    db::{HirDatabase, InternedCoroutine, InternedCoroutineId},
    method_resolution::{ALL_FLOAT_FPS, ALL_INT_FPS, TyFingerprint},
    next_solver::{
        AdtIdWrapper, BoundConst, CallableIdWrapper, CanonicalVarKind, ClosureIdWrapper,
        CoroutineIdWrapper, Ctor, FnSig, FxIndexMap, ImplIdWrapper, OpaqueTypeKey,
        RegionAssumptions, SolverContext, SolverDefIds, TraitIdWrapper, TypeAliasIdWrapper,
        util::{ContainsTypeErrors, explicit_item_bounds, for_trait_impls},
    },
};

use super::{
    Binder, BoundExistentialPredicates, BoundTy, BoundTyKind, Clause, ClauseKind, Clauses, Const,
    ErrorGuaranteed, ExprConst, ExternalConstraints, GenericArg, GenericArgs, ParamConst, ParamEnv,
    ParamTy, PlaceholderConst, PlaceholderTy, PredefinedOpaques, Predicate, SolverDefId, Term, Ty,
    TyKind, Tys, Valtree, ValueConst,
    abi::Safety,
    fold::{BoundVarReplacer, BoundVarReplacerDelegate, FnMutDelegate},
    generics::{Generics, generics},
    region::{
        BoundRegion, BoundRegionKind, EarlyParamRegion, LateParamRegion, PlaceholderRegion, Region,
    },
    util::sizedness_constraint_for_ty,
};

#[derive(PartialEq, Eq, Hash, PartialOrd, Ord, Clone)]
pub struct InternedWrapperNoDebug<T>(pub(crate) T);

#[macro_export]
#[doc(hidden)]
macro_rules! _interned_vec_nolifetime_salsa {
    ($name:ident, $ty:ty) => {
        interned_vec_nolifetime_salsa!($name, $ty, nofold);

        impl<'db> rustc_type_ir::TypeFoldable<DbInterner<'db>> for $name<'db> {
            fn try_fold_with<F: rustc_type_ir::FallibleTypeFolder<DbInterner<'db>>>(
                self,
                folder: &mut F,
            ) -> Result<Self, F::Error> {
                use rustc_type_ir::inherent::SliceLike as _;
                let inner: smallvec::SmallVec<[_; 2]> =
                    self.iter().map(|v| v.try_fold_with(folder)).collect::<Result<_, _>>()?;
                Ok($name::new_(folder.cx().db(), inner))
            }
            fn fold_with<F: rustc_type_ir::TypeFolder<DbInterner<'db>>>(
                self,
                folder: &mut F,
            ) -> Self {
                use rustc_type_ir::inherent::SliceLike as _;
                let inner: smallvec::SmallVec<[_; 2]> =
                    self.iter().map(|v| v.fold_with(folder)).collect();
                $name::new_(folder.cx().db(), inner)
            }
        }

        impl<'db> rustc_type_ir::TypeVisitable<DbInterner<'db>> for $name<'db> {
            fn visit_with<V: rustc_type_ir::TypeVisitor<DbInterner<'db>>>(
                &self,
                visitor: &mut V,
            ) -> V::Result {
                use rustc_ast_ir::visit::VisitorResult;
                use rustc_type_ir::inherent::SliceLike as _;
                rustc_ast_ir::walk_visitable_list!(visitor, self.as_slice().iter());
                V::Result::output()
            }
        }
    };
    ($name:ident, $ty:ty, nofold) => {
        #[salsa::interned(constructor = new_)]
        pub struct $name {
            #[returns(ref)]
            inner_: smallvec::SmallVec<[$ty; 2]>,
        }

        impl<'db> $name<'db> {
            pub fn new_from_iter(
                interner: DbInterner<'db>,
                data: impl IntoIterator<Item = $ty>,
            ) -> Self {
                $name::new_(interner.db(), data.into_iter().collect::<smallvec::SmallVec<[_; 2]>>())
            }

            pub fn inner(&self) -> &smallvec::SmallVec<[$ty; 2]> {
                // SAFETY: ¯\_(ツ)_/¯
                $crate::with_attached_db(|db| {
                    let inner = self.inner_(db);
                    unsafe { std::mem::transmute(inner) }
                })
            }
        }

        impl<'db> std::fmt::Debug for $name<'db> {
            fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                self.as_slice().fmt(fmt)
            }
        }

        impl<'db> rustc_type_ir::inherent::SliceLike for $name<'db> {
            type Item = $ty;

            type IntoIter = <smallvec::SmallVec<[$ty; 2]> as IntoIterator>::IntoIter;

            fn iter(self) -> Self::IntoIter {
                self.inner().clone().into_iter()
            }

            fn as_slice(&self) -> &[Self::Item] {
                self.inner().as_slice()
            }
        }

        impl<'db> IntoIterator for $name<'db> {
            type Item = $ty;
            type IntoIter = <Self as rustc_type_ir::inherent::SliceLike>::IntoIter;

            fn into_iter(self) -> Self::IntoIter {
                rustc_type_ir::inherent::SliceLike::iter(self)
            }
        }

        impl<'db> Default for $name<'db> {
            fn default() -> Self {
                $name::new_from_iter(DbInterner::conjure(), [])
            }
        }
    };
}

pub use crate::_interned_vec_nolifetime_salsa as interned_vec_nolifetime_salsa;

#[macro_export]
#[doc(hidden)]
macro_rules! _interned_vec_db {
    ($name:ident, $ty:ident) => {
        interned_vec_db!($name, $ty, nofold);

        impl<'db> rustc_type_ir::TypeFoldable<DbInterner<'db>> for $name<'db> {
            fn try_fold_with<F: rustc_type_ir::FallibleTypeFolder<DbInterner<'db>>>(
                self,
                folder: &mut F,
            ) -> Result<Self, F::Error> {
                use rustc_type_ir::inherent::SliceLike as _;
                let inner: smallvec::SmallVec<[_; 2]> =
                    self.iter().map(|v| v.try_fold_with(folder)).collect::<Result<_, _>>()?;
                Ok($name::new_(folder.cx().db(), inner))
            }
            fn fold_with<F: rustc_type_ir::TypeFolder<DbInterner<'db>>>(
                self,
                folder: &mut F,
            ) -> Self {
                use rustc_type_ir::inherent::SliceLike as _;
                let inner: smallvec::SmallVec<[_; 2]> =
                    self.iter().map(|v| v.fold_with(folder)).collect();
                $name::new_(folder.cx().db(), inner)
            }
        }

        impl<'db> rustc_type_ir::TypeVisitable<DbInterner<'db>> for $name<'db> {
            fn visit_with<V: rustc_type_ir::TypeVisitor<DbInterner<'db>>>(
                &self,
                visitor: &mut V,
            ) -> V::Result {
                use rustc_ast_ir::visit::VisitorResult;
                use rustc_type_ir::inherent::SliceLike as _;
                rustc_ast_ir::walk_visitable_list!(visitor, self.as_slice().iter());
                V::Result::output()
            }
        }
    };
    ($name:ident, $ty:ident, nofold) => {
        #[salsa::interned(constructor = new_)]
        pub struct $name<'db> {
            #[returns(ref)]
            inner_: smallvec::SmallVec<[$ty<'db>; 2]>,
        }

        impl<'db> std::fmt::Debug for $name<'db> {
            fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                self.as_slice().fmt(fmt)
            }
        }

        impl<'db> $name<'db> {
            pub fn new_from_iter(
                interner: DbInterner<'db>,
                data: impl IntoIterator<Item = $ty<'db>>,
            ) -> Self {
                $name::new_(interner.db(), data.into_iter().collect::<smallvec::SmallVec<[_; 2]>>())
            }

            pub fn inner(&self) -> &smallvec::SmallVec<[$ty<'db>; 2]> {
                // SAFETY: ¯\_(ツ)_/¯
                $crate::with_attached_db(|db| {
                    let inner = self.inner_(db);
                    unsafe { std::mem::transmute(inner) }
                })
            }
        }

        impl<'db> rustc_type_ir::inherent::SliceLike for $name<'db> {
            type Item = $ty<'db>;

            type IntoIter = <smallvec::SmallVec<[$ty<'db>; 2]> as IntoIterator>::IntoIter;

            fn iter(self) -> Self::IntoIter {
                self.inner().clone().into_iter()
            }

            fn as_slice(&self) -> &[Self::Item] {
                self.inner().as_slice()
            }
        }

        impl<'db> IntoIterator for $name<'db> {
            type Item = $ty<'db>;
            type IntoIter = <Self as rustc_type_ir::inherent::SliceLike>::IntoIter;

            fn into_iter(self) -> Self::IntoIter {
                rustc_type_ir::inherent::SliceLike::iter(self)
            }
        }

        impl<'db> Default for $name<'db> {
            fn default() -> Self {
                $name::new_from_iter(DbInterner::conjure(), [])
            }
        }
    };
}

pub use crate::_interned_vec_db as interned_vec_db;

#[derive(Debug, Copy, Clone)]
pub struct DbInterner<'db> {
    pub(crate) db: &'db dyn HirDatabase,
    pub(crate) krate: Option<Crate>,
    pub(crate) block: Option<BlockId>,
}

// FIXME: very wrong, see https://github.com/rust-lang/rust/pull/144808
unsafe impl Send for DbInterner<'_> {}
unsafe impl Sync for DbInterner<'_> {}

impl<'db> DbInterner<'db> {
    // FIXME(next-solver): remove this method
    pub fn conjure() -> DbInterner<'db> {
        crate::with_attached_db(|db| DbInterner {
            db: unsafe { std::mem::transmute::<&dyn HirDatabase, &'db dyn HirDatabase>(db) },
            krate: None,
            block: None,
        })
    }

    pub fn new_with(
        db: &'db dyn HirDatabase,
        krate: Option<Crate>,
        block: Option<BlockId>,
    ) -> DbInterner<'db> {
        DbInterner { db, krate, block }
    }

    #[inline]
    pub fn db(&self) -> &'db dyn HirDatabase {
        self.db
    }
}

// This is intentionally left as `()`
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub struct Span(());

impl<'db> inherent::Span<DbInterner<'db>> for Span {
    fn dummy() -> Self {
        Span(())
    }
}

interned_vec_nolifetime_salsa!(BoundVarKinds, BoundVarKind, nofold);

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub enum BoundVarKind {
    Ty(BoundTyKind),
    Region(BoundRegionKind),
    Const,
}

impl BoundVarKind {
    pub fn expect_region(self) -> BoundRegionKind {
        match self {
            BoundVarKind::Region(lt) => lt,
            _ => panic!("expected a region, but found another kind"),
        }
    }

    pub fn expect_ty(self) -> BoundTyKind {
        match self {
            BoundVarKind::Ty(ty) => ty,
            _ => panic!("expected a type, but found another kind"),
        }
    }

    pub fn expect_const(self) {
        match self {
            BoundVarKind::Const => (),
            _ => panic!("expected a const, but found another kind"),
        }
    }
}

interned_vec_db!(CanonicalVars, CanonicalVarKind, nofold);

pub struct DepNodeIndex;

#[derive(Debug)]
pub struct Tracked<T: fmt::Debug + Clone>(T);

#[derive(Copy, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Placeholder<T> {
    pub universe: UniverseIndex,
    pub bound: T,
}

impl<T: std::fmt::Debug> std::fmt::Debug for Placeholder<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> fmt::Result {
        if self.universe == UniverseIndex::ROOT {
            write!(f, "!{:?}", self.bound)
        } else {
            write!(f, "!{}_{:?}", self.universe.index(), self.bound)
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub struct AllocId;

interned_vec_nolifetime_salsa!(VariancesOf, Variance, nofold);

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct VariantIdx(usize);

// FIXME: could/should store actual data?
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub enum VariantDef {
    Struct(StructId),
    Union(UnionId),
    Enum(EnumVariantId),
}

impl VariantDef {
    pub fn id(&self) -> VariantId {
        match self {
            VariantDef::Struct(struct_id) => VariantId::StructId(*struct_id),
            VariantDef::Union(union_id) => VariantId::UnionId(*union_id),
            VariantDef::Enum(enum_variant_id) => VariantId::EnumVariantId(*enum_variant_id),
        }
    }

    pub fn fields(&self, db: &dyn HirDatabase) -> Vec<(Idx<FieldData>, FieldData)> {
        let id: VariantId = match self {
            VariantDef::Struct(it) => (*it).into(),
            VariantDef::Union(it) => (*it).into(),
            VariantDef::Enum(it) => (*it).into(),
        };
        id.fields(db).fields().iter().map(|(id, data)| (id, data.clone())).collect()
    }
}

/*
/// Definition of a variant -- a struct's fields or an enum variant.
#[derive(Debug, HashStable, TyEncodable, TyDecodable)]
pub struct VariantDef {
    /// `DefId` that identifies the variant itself.
    /// If this variant belongs to a struct or union, then this is a copy of its `DefId`.
    pub def_id: DefId,
    /// `DefId` that identifies the variant's constructor.
    /// If this variant is a struct variant, then this is `None`.
    pub ctor: Option<(CtorKind, DefId)>,
    /// Variant or struct name, maybe empty for anonymous adt (struct or union).
    pub name: Symbol,
    /// Discriminant of this variant.
    pub discr: VariantDiscr,
    /// Fields of this variant.
    pub fields: IndexVec<FieldIdx, FieldDef>,
    /// The error guarantees from parser, if any.
    tainted: Option<ErrorGuaranteed>,
    /// Flags of the variant (e.g. is field list non-exhaustive)?
    flags: VariantFlags,
}
*/

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct AdtFlags {
    is_enum: bool,
    is_union: bool,
    is_struct: bool,
    is_phantom_data: bool,
    is_fundamental: bool,
    is_box: bool,
    is_manually_drop: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdtDefInner {
    pub id: AdtId,
    variants: Vec<(VariantIdx, VariantDef)>,
    flags: AdtFlags,
    repr: ReprOptions,
}

// We're gonna cheat a little bit and implement `Hash` on only the `DefId` and
// accept there might be collisions for def ids from different crates (or across
// different tests, oh my).
impl std::hash::Hash for AdtDefInner {
    #[inline]
    fn hash<H: std::hash::Hasher>(&self, s: &mut H) {
        self.id.hash(s)
    }
}

#[salsa::interned(no_lifetime, constructor = new_)]
pub struct AdtDef {
    #[returns(ref)]
    data_: AdtDefInner,
}

impl AdtDef {
    pub fn new<'db>(def_id: AdtId, interner: DbInterner<'db>) -> Self {
        let db = interner.db();
        let (flags, variants, repr) = match def_id {
            AdtId::StructId(struct_id) => {
                let data = db.struct_signature(struct_id);

                let flags = AdtFlags {
                    is_enum: false,
                    is_union: false,
                    is_struct: true,
                    is_phantom_data: data.flags.contains(StructFlags::IS_PHANTOM_DATA),
                    is_fundamental: data.flags.contains(StructFlags::FUNDAMENTAL),
                    is_box: data.flags.contains(StructFlags::IS_BOX),
                    is_manually_drop: data.flags.contains(StructFlags::IS_MANUALLY_DROP),
                };

                let variants = vec![(VariantIdx(0), VariantDef::Struct(struct_id))];

                let mut repr = ReprOptions::default();
                repr.align = data.repr.and_then(|r| r.align);
                repr.pack = data.repr.and_then(|r| r.pack);
                repr.int = data.repr.and_then(|r| r.int);

                let mut repr_flags = ReprFlags::empty();
                if flags.is_box {
                    repr_flags.insert(ReprFlags::IS_LINEAR);
                }
                if data.repr.is_some_and(|r| r.c()) {
                    repr_flags.insert(ReprFlags::IS_C);
                }
                if data.repr.is_some_and(|r| r.simd()) {
                    repr_flags.insert(ReprFlags::IS_SIMD);
                }
                repr.flags = repr_flags;

                (flags, variants, repr)
            }
            AdtId::UnionId(union_id) => {
                let data = db.union_signature(union_id);

                let flags = AdtFlags {
                    is_enum: false,
                    is_union: true,
                    is_struct: false,
                    is_phantom_data: false,
                    is_fundamental: false,
                    is_box: false,
                    is_manually_drop: false,
                };

                let variants = vec![(VariantIdx(0), VariantDef::Union(union_id))];

                let mut repr = ReprOptions::default();
                repr.align = data.repr.and_then(|r| r.align);
                repr.pack = data.repr.and_then(|r| r.pack);
                repr.int = data.repr.and_then(|r| r.int);

                let mut repr_flags = ReprFlags::empty();
                if flags.is_box {
                    repr_flags.insert(ReprFlags::IS_LINEAR);
                }
                if data.repr.is_some_and(|r| r.c()) {
                    repr_flags.insert(ReprFlags::IS_C);
                }
                if data.repr.is_some_and(|r| r.simd()) {
                    repr_flags.insert(ReprFlags::IS_SIMD);
                }
                repr.flags = repr_flags;

                (flags, variants, repr)
            }
            AdtId::EnumId(enum_id) => {
                let flags = AdtFlags {
                    is_enum: true,
                    is_union: false,
                    is_struct: false,
                    is_phantom_data: false,
                    is_fundamental: false,
                    is_box: false,
                    is_manually_drop: false,
                };

                let variants = enum_id
                    .enum_variants(db)
                    .variants
                    .iter()
                    .enumerate()
                    .map(|(idx, v)| (VariantIdx(idx), v))
                    .map(|(idx, v)| (idx, VariantDef::Enum(v.0)))
                    .collect();

                let data = db.enum_signature(enum_id);

                let mut repr = ReprOptions::default();
                repr.align = data.repr.and_then(|r| r.align);
                repr.pack = data.repr.and_then(|r| r.pack);
                repr.int = data.repr.and_then(|r| r.int);

                let mut repr_flags = ReprFlags::empty();
                if flags.is_box {
                    repr_flags.insert(ReprFlags::IS_LINEAR);
                }
                if data.repr.is_some_and(|r| r.c()) {
                    repr_flags.insert(ReprFlags::IS_C);
                }
                if data.repr.is_some_and(|r| r.simd()) {
                    repr_flags.insert(ReprFlags::IS_SIMD);
                }
                repr.flags = repr_flags;

                (flags, variants, repr)
            }
        };

        AdtDef::new_(db, AdtDefInner { id: def_id, variants, flags, repr })
    }

    pub fn inner(&self) -> &AdtDefInner {
        crate::with_attached_db(|db| {
            let inner = self.data_(db);
            // SAFETY: ¯\_(ツ)_/¯
            unsafe { std::mem::transmute(inner) }
        })
    }

    pub fn is_enum(&self) -> bool {
        self.inner().flags.is_enum
    }

    #[inline]
    pub fn repr(self) -> ReprOptions {
        self.inner().repr
    }

    /// Asserts this is a struct or union and returns its unique variant.
    pub fn non_enum_variant(self) -> VariantDef {
        assert!(self.inner().flags.is_struct || self.inner().flags.is_union);
        self.inner().variants[0].1.clone()
    }
}

impl<'db> inherent::AdtDef<DbInterner<'db>> for AdtDef {
    fn def_id(self) -> AdtIdWrapper {
        self.inner().id.into()
    }

    fn is_struct(self) -> bool {
        self.inner().flags.is_struct
    }

    fn is_phantom_data(self) -> bool {
        self.inner().flags.is_phantom_data
    }

    fn is_fundamental(self) -> bool {
        self.inner().flags.is_fundamental
    }

    fn struct_tail_ty(
        self,
        interner: DbInterner<'db>,
    ) -> Option<EarlyBinder<DbInterner<'db>, Ty<'db>>> {
        let hir_def::AdtId::StructId(struct_id) = self.inner().id else {
            return None;
        };
        let id: VariantId = struct_id.into();
        let field_types = interner.db().field_types(id);

        field_types.iter().last().map(|f| *f.1)
    }

    fn all_field_tys(
        self,
        interner: DbInterner<'db>,
    ) -> EarlyBinder<DbInterner<'db>, impl IntoIterator<Item = Ty<'db>>> {
        let db = interner.db();
        // FIXME: this is disabled just to match the behavior with chalk right now
        let _field_tys = |id: VariantId| {
            db.field_types(id).iter().map(|(_, ty)| ty.skip_binder()).collect::<Vec<_>>()
        };
        let field_tys = |_id: VariantId| vec![];
        let tys: Vec<_> = match self.inner().id {
            hir_def::AdtId::StructId(id) => field_tys(id.into()),
            hir_def::AdtId::UnionId(id) => field_tys(id.into()),
            hir_def::AdtId::EnumId(id) => id
                .enum_variants(db)
                .variants
                .iter()
                .flat_map(|&(variant_id, _, _)| field_tys(variant_id.into()))
                .collect(),
        };

        EarlyBinder::bind(tys)
    }

    fn sizedness_constraint(
        self,
        interner: DbInterner<'db>,
        sizedness: SizedTraitKind,
    ) -> Option<EarlyBinder<DbInterner<'db>, Ty<'db>>> {
        if self.is_struct() {
            let tail_ty = self.all_field_tys(interner).skip_binder().into_iter().last()?;

            let constraint_ty = sizedness_constraint_for_ty(interner, sizedness, tail_ty)?;

            Some(EarlyBinder::bind(constraint_ty))
        } else {
            None
        }
    }

    fn destructor(
        self,
        _interner: DbInterner<'db>,
    ) -> Option<rustc_type_ir::solve::AdtDestructorKind> {
        // FIXME(next-solver)
        None
    }

    fn is_manually_drop(self) -> bool {
        self.inner().flags.is_manually_drop
    }
}

impl fmt::Debug for AdtDef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        crate::with_attached_db(|db| match self.inner().id {
            AdtId::StructId(struct_id) => {
                let data = db.struct_signature(struct_id);
                f.write_str(data.name.as_str())
            }
            AdtId::UnionId(union_id) => {
                let data = db.union_signature(union_id);
                f.write_str(data.name.as_str())
            }
            AdtId::EnumId(enum_id) => {
                let data = db.enum_signature(enum_id);
                f.write_str(data.name.as_str())
            }
        })
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub struct Features;

impl<'db> inherent::Features<DbInterner<'db>> for Features {
    fn generic_const_exprs(self) -> bool {
        false
    }

    fn coroutine_clone(self) -> bool {
        false
    }

    fn associated_const_equality(self) -> bool {
        false
    }

    fn feature_bound_holds_in_crate(self, _symbol: ()) -> bool {
        false
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct UnsizingParams(pub(crate) DenseBitSet<u32>);

impl std::ops::Deref for UnsizingParams {
    type Target = DenseBitSet<u32>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

pub type PatternKind<'db> = rustc_type_ir::PatternKind<DbInterner<'db>>;

#[salsa::interned(constructor = new_, debug)]
pub struct Pattern<'db> {
    #[returns(ref)]
    kind_: InternedWrapperNoDebug<PatternKind<'db>>,
}

impl<'db> std::fmt::Debug for InternedWrapperNoDebug<PatternKind<'db>> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl<'db> Pattern<'db> {
    pub fn new(interner: DbInterner<'db>, kind: PatternKind<'db>) -> Self {
        Pattern::new_(interner.db(), InternedWrapperNoDebug(kind))
    }

    pub fn inner(&self) -> &PatternKind<'db> {
        crate::with_attached_db(|db| {
            let inner = &self.kind_(db).0;
            // SAFETY: The caller already has access to a `Ty<'db>`, so borrowchecking will
            // make sure that our returned value is valid for the lifetime `'db`.
            unsafe { std::mem::transmute(inner) }
        })
    }
}

impl<'db> Flags for Pattern<'db> {
    fn flags(&self) -> rustc_type_ir::TypeFlags {
        match self.inner() {
            PatternKind::Range { start, end } => {
                FlagComputation::for_const_kind(&start.kind()).flags
                    | FlagComputation::for_const_kind(&end.kind()).flags
            }
            PatternKind::Or(pats) => {
                let mut flags = pats.as_slice()[0].flags();
                for pat in pats.as_slice()[1..].iter() {
                    flags |= pat.flags();
                }
                flags
            }
        }
    }

    fn outer_exclusive_binder(&self) -> rustc_type_ir::DebruijnIndex {
        match self.inner() {
            PatternKind::Range { start, end } => {
                start.outer_exclusive_binder().max(end.outer_exclusive_binder())
            }
            PatternKind::Or(pats) => {
                let mut idx = pats.as_slice()[0].outer_exclusive_binder();
                for pat in pats.as_slice()[1..].iter() {
                    idx = idx.max(pat.outer_exclusive_binder());
                }
                idx
            }
        }
    }
}

impl<'db> rustc_type_ir::inherent::IntoKind for Pattern<'db> {
    type Kind = rustc_type_ir::PatternKind<DbInterner<'db>>;
    fn kind(self) -> Self::Kind {
        *self.inner()
    }
}

impl<'db> rustc_type_ir::relate::Relate<DbInterner<'db>> for Pattern<'db> {
    fn relate<R: rustc_type_ir::relate::TypeRelation<DbInterner<'db>>>(
        relation: &mut R,
        a: Self,
        b: Self,
    ) -> rustc_type_ir::relate::RelateResult<DbInterner<'db>, Self> {
        let tcx = relation.cx();
        match (a.kind(), b.kind()) {
            (
                PatternKind::Range { start: start_a, end: end_a },
                PatternKind::Range { start: start_b, end: end_b },
            ) => {
                let start = relation.relate(start_a, start_b)?;
                let end = relation.relate(end_a, end_b)?;
                Ok(Pattern::new(tcx, PatternKind::Range { start, end }))
            }
            (PatternKind::Or(a), PatternKind::Or(b)) => {
                if a.len() != b.len() {
                    return Err(TypeError::Mismatch);
                }
                let pats = CollectAndApply::collect_and_apply(
                    std::iter::zip(a.iter(), b.iter()).map(|(a, b)| relation.relate(a, b)),
                    |g| PatList::new_from_iter(tcx, g.iter().cloned()),
                )?;
                Ok(Pattern::new(tcx, PatternKind::Or(pats)))
            }
            (PatternKind::Range { .. } | PatternKind::Or(_), _) => Err(TypeError::Mismatch),
        }
    }
}

interned_vec_db!(PatList, Pattern);

macro_rules! as_lang_item {
    (
        $solver_enum:ident, $var:ident;

        ignore = {
            $( $ignore:ident ),* $(,)?
        }

        $( $variant:ident ),* $(,)?
    ) => {{
        // Ensure exhaustiveness.
        if let Some(it) = None::<$solver_enum> {
            match it {
                $( $solver_enum::$variant => {} )*
                $( $solver_enum::$ignore => {} )*
            }
        }
        match $var {
            $( LangItem::$variant => Some($solver_enum::$variant), )*
            _ => None
        }
    }};
}

impl<'db> Interner for DbInterner<'db> {
    type DefId = SolverDefId;
    type LocalDefId = SolverDefId;
    type LocalDefIds = SolverDefIds<'db>;
    type TraitId = TraitIdWrapper;
    type ForeignId = TypeAliasIdWrapper;
    type FunctionId = CallableIdWrapper;
    type ClosureId = ClosureIdWrapper;
    type CoroutineClosureId = CoroutineIdWrapper;
    type CoroutineId = CoroutineIdWrapper;
    type AdtId = AdtIdWrapper;
    type ImplId = ImplIdWrapper;
    type Span = Span;

    type GenericArgs = GenericArgs<'db>;
    type GenericArgsSlice = GenericArgs<'db>;
    type GenericArg = GenericArg<'db>;

    type Term = Term<'db>;

    type BoundVarKinds = BoundVarKinds<'db>;
    type BoundVarKind = BoundVarKind;

    type PredefinedOpaques = PredefinedOpaques<'db>;

    fn mk_predefined_opaques_in_body(
        self,
        data: &[(OpaqueTypeKey<'db>, Self::Ty)],
    ) -> Self::PredefinedOpaques {
        PredefinedOpaques::new_from_iter(self, data.iter().cloned())
    }

    type CanonicalVarKinds = CanonicalVars<'db>;

    fn mk_canonical_var_kinds(
        self,
        kinds: &[rustc_type_ir::CanonicalVarKind<Self>],
    ) -> Self::CanonicalVarKinds {
        CanonicalVars::new_from_iter(self, kinds.iter().cloned())
    }

    type ExternalConstraints = ExternalConstraints<'db>;

    fn mk_external_constraints(
        self,
        data: rustc_type_ir::solve::ExternalConstraintsData<Self>,
    ) -> Self::ExternalConstraints {
        ExternalConstraints::new(self, data)
    }

    type DepNodeIndex = DepNodeIndex;

    type Tracked<T: fmt::Debug + Clone> = Tracked<T>;

    type Ty = Ty<'db>;
    type Tys = Tys<'db>;
    type FnInputTys = Tys<'db>;
    type ParamTy = ParamTy;
    type BoundTy = BoundTy;
    type PlaceholderTy = PlaceholderTy;
    type Symbol = ();

    type ErrorGuaranteed = ErrorGuaranteed;
    type BoundExistentialPredicates = BoundExistentialPredicates<'db>;
    type AllocId = AllocId;
    type Pat = Pattern<'db>;
    type PatList = PatList<'db>;
    type Safety = Safety;
    type Abi = FnAbi;

    type Const = Const<'db>;
    type PlaceholderConst = PlaceholderConst;
    type ParamConst = ParamConst;
    type BoundConst = BoundConst;
    type ValueConst = ValueConst<'db>;
    type ValTree = Valtree<'db>;
    type ExprConst = ExprConst;

    type Region = Region<'db>;
    type EarlyParamRegion = EarlyParamRegion;
    type LateParamRegion = LateParamRegion;
    type BoundRegion = BoundRegion;
    type PlaceholderRegion = PlaceholderRegion;

    type RegionAssumptions = RegionAssumptions<'db>;

    type ParamEnv = ParamEnv<'db>;
    type Predicate = Predicate<'db>;
    type Clause = Clause<'db>;
    type Clauses = Clauses<'db>;

    type GenericsOf = Generics;

    type VariancesOf = VariancesOf<'db>;

    type AdtDef = AdtDef;

    type Features = Features;

    fn mk_args(self, args: &[Self::GenericArg]) -> Self::GenericArgs {
        GenericArgs::new_from_iter(self, args.iter().cloned())
    }

    fn mk_args_from_iter<I, T>(self, args: I) -> T::Output
    where
        I: Iterator<Item = T>,
        T: rustc_type_ir::CollectAndApply<Self::GenericArg, Self::GenericArgs>,
    {
        CollectAndApply::collect_and_apply(args, |g| {
            GenericArgs::new_from_iter(self, g.iter().cloned())
        })
    }

    type UnsizingParams = UnsizingParams;

    fn mk_tracked<T: fmt::Debug + Clone>(
        self,
        data: T,
        _dep_node: Self::DepNodeIndex,
    ) -> Self::Tracked<T> {
        Tracked(data)
    }

    fn get_tracked<T: fmt::Debug + Clone>(self, tracked: &Self::Tracked<T>) -> T {
        tracked.0.clone()
    }

    fn with_cached_task<T>(self, task: impl FnOnce() -> T) -> (T, Self::DepNodeIndex) {
        (task(), DepNodeIndex)
    }

    fn with_global_cache<R>(
        self,
        f: impl FnOnce(&mut rustc_type_ir::search_graph::GlobalCache<Self>) -> R,
    ) -> R {
        tls_cache::with_cache(self.db, f)
    }

    fn canonical_param_env_cache_get_or_insert<R>(
        self,
        _param_env: Self::ParamEnv,
        f: impl FnOnce() -> rustc_type_ir::CanonicalParamEnvCacheEntry<Self>,
        from_entry: impl FnOnce(&rustc_type_ir::CanonicalParamEnvCacheEntry<Self>) -> R,
    ) -> R {
        from_entry(&f())
    }

    fn assert_evaluation_is_concurrent(&self) {
        panic!("evaluation shouldn't be concurrent yet")
    }

    fn expand_abstract_consts<T: rustc_type_ir::TypeFoldable<Self>>(self, _: T) -> T {
        unreachable!("only used by the old trait solver in rustc");
    }

    fn generics_of(self, def_id: Self::DefId) -> Self::GenericsOf {
        generics(self.db(), def_id)
    }

    fn variances_of(self, def_id: Self::DefId) -> Self::VariancesOf {
        let generic_def = match def_id {
            SolverDefId::Ctor(Ctor::Enum(def_id)) | SolverDefId::EnumVariantId(def_id) => {
                def_id.loc(self.db).parent.into()
            }
            SolverDefId::InternedOpaqueTyId(_def_id) => {
                // FIXME(next-solver): track variances
                //
                // We compute them based on the only `Ty` level info in rustc,
                // move `variances_of_opaque` into `rustc_next_trait_solver` for reuse.
                return VariancesOf::new_from_iter(
                    self,
                    (0..self.generics_of(def_id).count()).map(|_| Variance::Invariant),
                );
            }
            SolverDefId::Ctor(Ctor::Struct(def_id)) => def_id.into(),
            SolverDefId::AdtId(def_id) => def_id.into(),
            SolverDefId::FunctionId(def_id) => def_id.into(),
            SolverDefId::ConstId(_)
            | SolverDefId::StaticId(_)
            | SolverDefId::TraitId(_)
            | SolverDefId::TypeAliasId(_)
            | SolverDefId::ImplId(_)
            | SolverDefId::InternedClosureId(_)
            | SolverDefId::InternedCoroutineId(_) => {
                return VariancesOf::new_from_iter(self, []);
            }
        };
        self.db.variances_of(generic_def)
    }

    fn type_of(self, def_id: Self::DefId) -> EarlyBinder<Self, Self::Ty> {
        match def_id {
            SolverDefId::TypeAliasId(id) => {
                use hir_def::Lookup;
                match id.lookup(self.db()).container {
                    ItemContainerId::ImplId(it) => it,
                    _ => panic!("assoc ty value should be in impl"),
                };
                self.db().ty(id.into())
            }
            SolverDefId::AdtId(id) => self.db().ty(id.into()),
            // FIXME(next-solver): This uses the types of `query mir_borrowck` in rustc.
            //
            // We currently always use the type from HIR typeck which ignores regions. This
            // should be fine.
            SolverDefId::InternedOpaqueTyId(_) => self.type_of_opaque_hir_typeck(def_id),
            SolverDefId::FunctionId(id) => self.db.value_ty(id.into()).unwrap(),
            SolverDefId::Ctor(id) => {
                let id = match id {
                    Ctor::Struct(id) => id.into(),
                    Ctor::Enum(id) => id.into(),
                };
                self.db.value_ty(id).expect("`SolverDefId::Ctor` should have a function-like ctor")
            }
            _ => panic!("Unexpected def_id `{def_id:?}` provided for `type_of`"),
        }
    }

    fn adt_def(self, def_id: Self::AdtId) -> Self::AdtDef {
        AdtDef::new(def_id.0, self)
    }

    fn alias_ty_kind(self, alias: rustc_type_ir::AliasTy<Self>) -> AliasTyKind {
        match alias.def_id {
            SolverDefId::InternedOpaqueTyId(_) => AliasTyKind::Opaque,
            SolverDefId::TypeAliasId(type_alias) => match type_alias.loc(self.db).container {
                ItemContainerId::ImplId(impl_)
                    if self.db.impl_signature(impl_).target_trait.is_none() =>
                {
                    AliasTyKind::Inherent
                }
                ItemContainerId::TraitId(_) | ItemContainerId::ImplId(_) => AliasTyKind::Projection,
                _ => AliasTyKind::Free,
            },
            _ => unimplemented!("Unexpected alias: {:?}", alias.def_id),
        }
    }

    fn alias_term_kind(
        self,
        alias: rustc_type_ir::AliasTerm<Self>,
    ) -> rustc_type_ir::AliasTermKind {
        match alias.def_id {
            SolverDefId::InternedOpaqueTyId(_) => AliasTermKind::OpaqueTy,
            SolverDefId::TypeAliasId(type_alias) => match type_alias.loc(self.db).container {
                ItemContainerId::ImplId(impl_)
                    if self.db.impl_signature(impl_).target_trait.is_none() =>
                {
                    AliasTermKind::InherentTy
                }
                ItemContainerId::TraitId(_) | ItemContainerId::ImplId(_) => {
                    AliasTermKind::ProjectionTy
                }
                _ => AliasTermKind::FreeTy,
            },
            // rustc creates an `AnonConst` for consts, and evaluates them with CTFE (normalizing projections
            // via selection, similar to ours `find_matching_impl()`, and not with the trait solver), so mimic it.
            SolverDefId::ConstId(_) => AliasTermKind::UnevaluatedConst,
            _ => unimplemented!("Unexpected alias: {:?}", alias.def_id),
        }
    }

    fn trait_ref_and_own_args_for_alias(
        self,
        def_id: Self::DefId,
        args: Self::GenericArgs,
    ) -> (rustc_type_ir::TraitRef<Self>, Self::GenericArgsSlice) {
        let trait_def_id = self.parent(def_id);
        let trait_generics = self.generics_of(trait_def_id);
        let trait_args = GenericArgs::new_from_iter(
            self,
            args.as_slice()[0..trait_generics.own_params.len()].iter().cloned(),
        );
        let alias_args =
            GenericArgs::new_from_iter(self, args.iter().skip(trait_generics.own_params.len()));
        (TraitRef::new_from_args(self, trait_def_id.try_into().unwrap(), trait_args), alias_args)
    }

    fn check_args_compatible(self, _def_id: Self::DefId, _args: Self::GenericArgs) -> bool {
        // FIXME
        true
    }

    fn debug_assert_args_compatible(self, _def_id: Self::DefId, _args: Self::GenericArgs) {}

    fn debug_assert_existential_args_compatible(
        self,
        _def_id: Self::DefId,
        _args: Self::GenericArgs,
    ) {
    }

    fn mk_type_list_from_iter<I, T>(self, args: I) -> T::Output
    where
        I: Iterator<Item = T>,
        T: rustc_type_ir::CollectAndApply<Self::Ty, Self::Tys>,
    {
        CollectAndApply::collect_and_apply(args, |g| Tys::new_from_iter(self, g.iter().cloned()))
    }

    fn parent(self, def_id: Self::DefId) -> Self::DefId {
        use hir_def::Lookup;

        let container = match def_id {
            SolverDefId::FunctionId(it) => it.lookup(self.db()).container,
            SolverDefId::TypeAliasId(it) => it.lookup(self.db()).container,
            SolverDefId::ConstId(it) => it.lookup(self.db()).container,
            SolverDefId::InternedClosureId(it) => {
                return self
                    .db()
                    .lookup_intern_closure(it)
                    .0
                    .as_generic_def_id(self.db())
                    .unwrap()
                    .into();
            }
            SolverDefId::InternedCoroutineId(it) => {
                return self
                    .db()
                    .lookup_intern_coroutine(it)
                    .0
                    .as_generic_def_id(self.db())
                    .unwrap()
                    .into();
            }
            SolverDefId::StaticId(_)
            | SolverDefId::AdtId(_)
            | SolverDefId::TraitId(_)
            | SolverDefId::ImplId(_)
            | SolverDefId::EnumVariantId(..)
            | SolverDefId::Ctor(..)
            | SolverDefId::InternedOpaqueTyId(..) => panic!(),
        };

        match container {
            ItemContainerId::ImplId(it) => it.into(),
            ItemContainerId::TraitId(it) => it.into(),
            ItemContainerId::ModuleId(_) | ItemContainerId::ExternBlockId(_) => panic!(),
        }
    }

    fn recursion_limit(self) -> usize {
        50
    }

    fn features(self) -> Self::Features {
        Features
    }

    fn fn_sig(
        self,
        def_id: Self::FunctionId,
    ) -> EarlyBinder<Self, rustc_type_ir::Binder<Self, rustc_type_ir::FnSig<Self>>> {
        self.db().callable_item_signature(def_id.0)
    }

    fn coroutine_movability(self, def_id: Self::CoroutineId) -> rustc_ast_ir::Movability {
        // FIXME: Make this a query? I don't believe this can be accessed from bodies other than
        // the current infer query, except with revealed opaques - is it rare enough to not matter?
        let InternedCoroutine(owner, expr_id) = def_id.0.loc(self.db);
        let body = self.db.body(owner);
        let expr = &body[expr_id];
        match *expr {
            hir_def::hir::Expr::Closure { closure_kind, .. } => match closure_kind {
                hir_def::hir::ClosureKind::Coroutine(movability) => match movability {
                    hir_def::hir::Movability::Static => rustc_ast_ir::Movability::Static,
                    hir_def::hir::Movability::Movable => rustc_ast_ir::Movability::Movable,
                },
                hir_def::hir::ClosureKind::Async => rustc_ast_ir::Movability::Static,
                _ => panic!("unexpected expression for a coroutine: {expr:?}"),
            },
            hir_def::hir::Expr::Async { .. } => rustc_ast_ir::Movability::Static,
            _ => panic!("unexpected expression for a coroutine: {expr:?}"),
        }
    }

    fn coroutine_for_closure(self, def_id: Self::CoroutineClosureId) -> Self::CoroutineId {
        def_id
    }

    fn generics_require_sized_self(self, def_id: Self::DefId) -> bool {
        let sized_trait =
            LangItem::Sized.resolve_trait(self.db(), self.krate.expect("Must have self.krate"));
        let Some(sized_id) = sized_trait else {
            return false; /* No Sized trait, can't require it! */
        };
        let sized_def_id = sized_id.into();

        // Search for a predicate like `Self : Sized` amongst the trait bounds.
        let predicates = self.predicates_of(def_id);
        elaborate(self, predicates.iter_identity()).any(|pred| match pred.kind().skip_binder() {
            ClauseKind::Trait(ref trait_pred) => {
                trait_pred.def_id() == sized_def_id
                    && matches!(
                        trait_pred.self_ty().kind(),
                        TyKind::Param(ParamTy { index: 0, .. })
                    )
            }
            ClauseKind::RegionOutlives(_)
            | ClauseKind::TypeOutlives(_)
            | ClauseKind::Projection(_)
            | ClauseKind::ConstArgHasType(_, _)
            | ClauseKind::WellFormed(_)
            | ClauseKind::ConstEvaluatable(_)
            | ClauseKind::HostEffect(..)
            | ClauseKind::UnstableFeature(_) => false,
        })
    }

    #[tracing::instrument(skip(self), ret)]
    fn item_bounds(
        self,
        def_id: Self::DefId,
    ) -> EarlyBinder<Self, impl IntoIterator<Item = Self::Clause>> {
        explicit_item_bounds(self, def_id).map_bound(|bounds| {
            Clauses::new_from_iter(self, elaborate(self, bounds).collect::<Vec<_>>())
        })
    }

    #[tracing::instrument(skip(self), ret)]
    fn item_self_bounds(
        self,
        def_id: Self::DefId,
    ) -> EarlyBinder<Self, impl IntoIterator<Item = Self::Clause>> {
        explicit_item_bounds(self, def_id).map_bound(|bounds| {
            Clauses::new_from_iter(
                self,
                elaborate(self, bounds).filter_only_self().collect::<Vec<_>>(),
            )
        })
    }

    fn item_non_self_bounds(
        self,
        def_id: Self::DefId,
    ) -> EarlyBinder<Self, impl IntoIterator<Item = Self::Clause>> {
        let all_bounds: FxHashSet<_> = self.item_bounds(def_id).skip_binder().into_iter().collect();
        let own_bounds: FxHashSet<_> =
            self.item_self_bounds(def_id).skip_binder().into_iter().collect();
        if all_bounds.len() == own_bounds.len() {
            EarlyBinder::bind(Clauses::new_from_iter(self, []))
        } else {
            EarlyBinder::bind(Clauses::new_from_iter(
                self,
                all_bounds.difference(&own_bounds).cloned(),
            ))
        }
    }

    #[tracing::instrument(level = "debug", skip(self), ret)]
    fn predicates_of(
        self,
        def_id: Self::DefId,
    ) -> EarlyBinder<Self, impl IntoIterator<Item = Self::Clause>> {
        let predicates = self.db().generic_predicates(def_id.try_into().unwrap());
        let predicates: Vec<_> = predicates.iter().cloned().collect();
        EarlyBinder::bind(predicates.into_iter())
    }

    #[tracing::instrument(level = "debug", skip(self), ret)]
    fn own_predicates_of(
        self,
        def_id: Self::DefId,
    ) -> EarlyBinder<Self, impl IntoIterator<Item = Self::Clause>> {
        let predicates = self.db().generic_predicates_without_parent(def_id.try_into().unwrap());
        let predicates: Vec<_> = predicates.iter().cloned().collect();
        EarlyBinder::bind(predicates.into_iter())
    }

    #[tracing::instrument(skip(self), ret)]
    fn explicit_super_predicates_of(
        self,
        def_id: Self::TraitId,
    ) -> EarlyBinder<Self, impl IntoIterator<Item = (Self::Clause, Self::Span)>> {
        let is_self = |ty: Ty<'db>| match ty.kind() {
            rustc_type_ir::TyKind::Param(param) => param.index == 0,
            _ => false,
        };

        let predicates: Vec<(Clause<'db>, Span)> = self
            .db()
            .generic_predicates(def_id.0.into())
            .iter()
            .filter(|p| match p.kind().skip_binder() {
                // rustc has the following assertion:
                // https://github.com/rust-lang/rust/blob/52618eb338609df44978b0ca4451ab7941fd1c7a/compiler/rustc_hir_analysis/src/hir_ty_lowering/bounds.rs#L525-L608
                rustc_type_ir::ClauseKind::Trait(it) => is_self(it.self_ty()),
                rustc_type_ir::ClauseKind::TypeOutlives(it) => is_self(it.0),
                rustc_type_ir::ClauseKind::Projection(it) => is_self(it.self_ty()),
                rustc_type_ir::ClauseKind::HostEffect(it) => is_self(it.self_ty()),
                _ => false,
            })
            .cloned()
            .map(|p| (p, Span::dummy()))
            .collect();
        EarlyBinder::bind(predicates)
    }

    #[tracing::instrument(skip(self), ret)]
    fn explicit_implied_predicates_of(
        self,
        def_id: Self::DefId,
    ) -> EarlyBinder<Self, impl IntoIterator<Item = (Self::Clause, Self::Span)>> {
        fn is_self_or_assoc(ty: Ty<'_>) -> bool {
            match ty.kind() {
                rustc_type_ir::TyKind::Param(param) => param.index == 0,
                rustc_type_ir::TyKind::Alias(rustc_type_ir::AliasTyKind::Projection, alias) => {
                    is_self_or_assoc(alias.self_ty())
                }
                _ => false,
            }
        }

        let predicates: Vec<(Clause<'db>, Span)> = self
            .db()
            .generic_predicates(def_id.try_into().unwrap())
            .iter()
            .filter(|p| match p.kind().skip_binder() {
                rustc_type_ir::ClauseKind::Trait(it) => is_self_or_assoc(it.self_ty()),
                rustc_type_ir::ClauseKind::TypeOutlives(it) => is_self_or_assoc(it.0),
                rustc_type_ir::ClauseKind::Projection(it) => is_self_or_assoc(it.self_ty()),
                rustc_type_ir::ClauseKind::HostEffect(it) => is_self_or_assoc(it.self_ty()),
                // FIXME: Not sure is this correct to allow other clauses but we might replace
                // `generic_predicates_ns` query here with something closer to rustc's
                // `implied_bounds_with_filter`, which is more granular lowering than this
                // "lower at once and then filter" implementation.
                _ => true,
            })
            .cloned()
            .map(|p| (p, Span::dummy()))
            .collect();
        EarlyBinder::bind(predicates)
    }

    fn impl_super_outlives(
        self,
        impl_id: Self::ImplId,
    ) -> EarlyBinder<Self, impl IntoIterator<Item = Self::Clause>> {
        let trait_ref = self.db().impl_trait(impl_id.0).expect("expected an impl of trait");
        trait_ref.map_bound(|trait_ref| {
            let clause: Clause<'_> = trait_ref.upcast(self);
            Clauses::new_from_iter(
                self,
                rustc_type_ir::elaborate::elaborate(self, [clause]).filter(|clause| {
                    matches!(
                        clause.kind().skip_binder(),
                        ClauseKind::TypeOutlives(_) | ClauseKind::RegionOutlives(_)
                    )
                }),
            )
        })
    }

    #[expect(unreachable_code)]
    fn const_conditions(
        self,
        _def_id: Self::DefId,
    ) -> EarlyBinder<
        Self,
        impl IntoIterator<Item = rustc_type_ir::Binder<Self, rustc_type_ir::TraitRef<Self>>>,
    > {
        EarlyBinder::bind([unimplemented!()])
    }

    fn has_target_features(self, _def_id: Self::FunctionId) -> bool {
        false
    }

    fn require_lang_item(self, lang_item: SolverLangItem) -> Self::DefId {
        let lang_item = match lang_item {
            SolverLangItem::AsyncFnKindUpvars => unimplemented!(),
            SolverLangItem::AsyncFnOnceOutput => LangItem::AsyncFnOnceOutput,
            SolverLangItem::CallOnceFuture => LangItem::CallOnceFuture,
            SolverLangItem::CallRefFuture => LangItem::CallRefFuture,
            SolverLangItem::CoroutineReturn => LangItem::CoroutineReturn,
            SolverLangItem::CoroutineYield => LangItem::CoroutineYield,
            SolverLangItem::DynMetadata => LangItem::DynMetadata,
            SolverLangItem::FutureOutput => LangItem::FutureOutput,
            SolverLangItem::Metadata => LangItem::Metadata,
        };
        let target = hir_def::lang_item::lang_item(
            self.db(),
            self.krate.expect("Must have self.krate"),
            lang_item,
        )
        .unwrap_or_else(|| panic!("Lang item {lang_item:?} required but not found."));
        match target {
            hir_def::lang_item::LangItemTarget::EnumId(enum_id) => enum_id.into(),
            hir_def::lang_item::LangItemTarget::Function(function_id) => function_id.into(),
            hir_def::lang_item::LangItemTarget::ImplDef(impl_id) => impl_id.into(),
            hir_def::lang_item::LangItemTarget::Static(static_id) => static_id.into(),
            hir_def::lang_item::LangItemTarget::Struct(struct_id) => struct_id.into(),
            hir_def::lang_item::LangItemTarget::Union(union_id) => union_id.into(),
            hir_def::lang_item::LangItemTarget::TypeAlias(type_alias_id) => type_alias_id.into(),
            hir_def::lang_item::LangItemTarget::Trait(trait_id) => trait_id.into(),
            hir_def::lang_item::LangItemTarget::EnumVariant(_) => unimplemented!(),
        }
    }

    fn require_trait_lang_item(self, lang_item: SolverTraitLangItem) -> TraitIdWrapper {
        let lang_item = match lang_item {
            SolverTraitLangItem::AsyncFn => LangItem::AsyncFn,
            SolverTraitLangItem::AsyncFnKindHelper => unimplemented!(),
            SolverTraitLangItem::AsyncFnMut => LangItem::AsyncFnMut,
            SolverTraitLangItem::AsyncFnOnce => LangItem::AsyncFnOnce,
            SolverTraitLangItem::AsyncFnOnceOutput => LangItem::AsyncFnOnceOutput,
            SolverTraitLangItem::AsyncIterator => unimplemented!(),
            SolverTraitLangItem::Clone => LangItem::Clone,
            SolverTraitLangItem::Copy => LangItem::Copy,
            SolverTraitLangItem::Coroutine => LangItem::Coroutine,
            SolverTraitLangItem::Destruct => LangItem::Destruct,
            SolverTraitLangItem::DiscriminantKind => LangItem::DiscriminantKind,
            SolverTraitLangItem::Drop => LangItem::Drop,
            SolverTraitLangItem::Fn => LangItem::Fn,
            SolverTraitLangItem::FnMut => LangItem::FnMut,
            SolverTraitLangItem::FnOnce => LangItem::FnOnce,
            SolverTraitLangItem::FnPtrTrait => LangItem::FnPtrTrait,
            SolverTraitLangItem::FusedIterator => unimplemented!(),
            SolverTraitLangItem::Future => LangItem::Future,
            SolverTraitLangItem::Iterator => LangItem::Iterator,
            SolverTraitLangItem::PointeeTrait => LangItem::PointeeTrait,
            SolverTraitLangItem::Sized => LangItem::Sized,
            SolverTraitLangItem::MetaSized => LangItem::MetaSized,
            SolverTraitLangItem::PointeeSized => LangItem::PointeeSized,
            SolverTraitLangItem::TransmuteTrait => LangItem::TransmuteTrait,
            SolverTraitLangItem::Tuple => LangItem::Tuple,
            SolverTraitLangItem::Unpin => LangItem::Unpin,
            SolverTraitLangItem::Unsize => LangItem::Unsize,
            SolverTraitLangItem::BikeshedGuaranteedNoDrop => {
                unimplemented!()
            }
        };
        lang_item
            .resolve_trait(self.db(), self.krate.expect("Must have self.krate"))
            .unwrap_or_else(|| panic!("Lang item {lang_item:?} required but not found."))
            .into()
    }

    fn require_adt_lang_item(self, lang_item: SolverAdtLangItem) -> AdtIdWrapper {
        let lang_item = match lang_item {
            SolverAdtLangItem::Option => LangItem::Option,
            SolverAdtLangItem::Poll => LangItem::Poll,
        };
        lang_item
            .resolve_adt(self.db(), self.krate.expect("Must have self.krate"))
            .unwrap_or_else(|| panic!("Lang item {lang_item:?} required but not found."))
            .into()
    }

    fn is_lang_item(self, def_id: Self::DefId, lang_item: SolverLangItem) -> bool {
        self.as_lang_item(def_id)
            .map_or(false, |l| std::mem::discriminant(&l) == std::mem::discriminant(&lang_item))
    }

    fn is_trait_lang_item(self, def_id: Self::TraitId, lang_item: SolverTraitLangItem) -> bool {
        self.as_trait_lang_item(def_id)
            .map_or(false, |l| std::mem::discriminant(&l) == std::mem::discriminant(&lang_item))
    }

    fn is_adt_lang_item(self, def_id: Self::AdtId, lang_item: SolverAdtLangItem) -> bool {
        // FIXME: derive PartialEq on SolverTraitLangItem
        self.as_adt_lang_item(def_id)
            .map_or(false, |l| std::mem::discriminant(&l) == std::mem::discriminant(&lang_item))
    }

    fn as_lang_item(self, def_id: Self::DefId) -> Option<SolverLangItem> {
        let def_id: AttrDefId = match def_id {
            SolverDefId::TraitId(id) => id.into(),
            SolverDefId::TypeAliasId(id) => id.into(),
            SolverDefId::AdtId(id) => id.into(),
            _ => panic!("Unexpected SolverDefId in as_lang_item"),
        };
        let lang_item = self.db().lang_attr(def_id)?;
        as_lang_item!(
            SolverLangItem, lang_item;

            ignore = {
                AsyncFnKindUpvars,
            }

            Metadata,
            DynMetadata,
            CoroutineReturn,
            CoroutineYield,
            FutureOutput,
            CallRefFuture,
            CallOnceFuture,
            AsyncFnOnceOutput,
        )
    }

    fn as_trait_lang_item(self, def_id: Self::TraitId) -> Option<SolverTraitLangItem> {
        let def_id: AttrDefId = def_id.0.into();
        let lang_item = self.db().lang_attr(def_id)?;
        as_lang_item!(
            SolverTraitLangItem, lang_item;

            ignore = {
                AsyncFnKindHelper,
                AsyncIterator,
                BikeshedGuaranteedNoDrop,
                FusedIterator,
            }

            Sized,
            MetaSized,
            PointeeSized,
            Unsize,
            Copy,
            Clone,
            DiscriminantKind,
            PointeeTrait,
            FnPtrTrait,
            Drop,
            Destruct,
            TransmuteTrait,
            Fn,
            FnMut,
            FnOnce,
            Future,
            Coroutine,
            Unpin,
            Tuple,
            Iterator,
            AsyncFn,
            AsyncFnMut,
            AsyncFnOnce,
            AsyncFnOnceOutput,
        )
    }

    fn as_adt_lang_item(self, def_id: Self::AdtId) -> Option<SolverAdtLangItem> {
        let def_id: AttrDefId = def_id.0.into();
        let lang_item = self.db().lang_attr(def_id)?;
        as_lang_item!(
            SolverAdtLangItem, lang_item;

            ignore = {}

            Option,
            Poll,
        )
    }

    fn associated_type_def_ids(self, def_id: Self::DefId) -> impl IntoIterator<Item = Self::DefId> {
        let trait_ = match def_id {
            SolverDefId::TraitId(id) => id,
            _ => unreachable!(),
        };
        trait_.trait_items(self.db()).associated_types().map(|id| id.into())
    }

    fn for_each_relevant_impl(
        self,
        trait_: Self::TraitId,
        self_ty: Self::Ty,
        mut f: impl FnMut(Self::ImplId),
    ) {
        let trait_ = trait_.0;
        let self_ty_fp = TyFingerprint::for_trait_impl(self_ty);
        let fps: &[TyFingerprint] = match self_ty.kind() {
            TyKind::Infer(InferTy::IntVar(..)) => &ALL_INT_FPS,
            TyKind::Infer(InferTy::FloatVar(..)) => &ALL_FLOAT_FPS,
            _ => self_ty_fp.as_slice(),
        };

        if fps.is_empty() {
            _ = for_trait_impls(
                self.db(),
                self.krate.expect("Must have self.krate"),
                self.block,
                trait_,
                self_ty_fp,
                |impls| {
                    for i in impls.for_trait(trait_) {
                        use rustc_type_ir::TypeVisitable;
                        let contains_errors = self.db().impl_trait(i).map_or(false, |b| {
                            b.skip_binder().visit_with(&mut ContainsTypeErrors).is_break()
                        });
                        if contains_errors {
                            continue;
                        }

                        f(i.into());
                    }
                    ControlFlow::Continue(())
                },
            );
        } else {
            _ = for_trait_impls(
                self.db(),
                self.krate.expect("Must have self.krate"),
                self.block,
                trait_,
                self_ty_fp,
                |impls| {
                    for fp in fps {
                        for i in impls.for_trait_and_self_ty(trait_, *fp) {
                            use rustc_type_ir::TypeVisitable;
                            let contains_errors = self.db().impl_trait(i).map_or(false, |b| {
                                b.skip_binder().visit_with(&mut ContainsTypeErrors).is_break()
                            });
                            if contains_errors {
                                continue;
                            }

                            f(i.into());
                        }
                    }
                    ControlFlow::Continue(())
                },
            );
        }
    }

    fn for_each_blanket_impl(self, trait_def_id: Self::TraitId, mut f: impl FnMut(Self::ImplId)) {
        let Some(krate) = self.krate else { return };

        for impls in self.db.trait_impls_in_deps(krate).iter() {
            for impl_id in impls.for_trait(trait_def_id.0) {
                let impl_data = self.db.impl_signature(impl_id);
                let self_ty_ref = &impl_data.store[impl_data.self_ty];
                if matches!(self_ty_ref, hir_def::type_ref::TypeRef::TypeParam(_)) {
                    f(impl_id.into());
                }
            }
        }
    }

    fn has_item_definition(self, _def_id: Self::DefId) -> bool {
        // FIXME(next-solver): should check if the associated item has a value.
        true
    }

    fn impl_is_default(self, impl_def_id: Self::ImplId) -> bool {
        self.db.impl_signature(impl_def_id.0).is_default()
    }

    #[tracing::instrument(skip(self), ret)]
    fn impl_trait_ref(
        self,
        impl_id: Self::ImplId,
    ) -> EarlyBinder<Self, rustc_type_ir::TraitRef<Self>> {
        let db = self.db();
        db.impl_trait(impl_id.0)
            // ImplIds for impls where the trait ref can't be resolved should never reach trait solving
            .expect("invalid impl passed to trait solver")
    }

    fn impl_polarity(self, impl_id: Self::ImplId) -> rustc_type_ir::ImplPolarity {
        let impl_data = self.db().impl_signature(impl_id.0);
        if impl_data.flags.contains(ImplFlags::NEGATIVE) {
            ImplPolarity::Negative
        } else {
            ImplPolarity::Positive
        }
    }

    fn trait_is_auto(self, trait_: Self::TraitId) -> bool {
        let trait_data = self.db().trait_signature(trait_.0);
        trait_data.flags.contains(TraitFlags::AUTO)
    }

    fn trait_is_alias(self, trait_: Self::TraitId) -> bool {
        let trait_data = self.db().trait_signature(trait_.0);
        trait_data.flags.contains(TraitFlags::ALIAS)
    }

    fn trait_is_dyn_compatible(self, trait_: Self::TraitId) -> bool {
        crate::dyn_compatibility::dyn_compatibility(self.db(), trait_.0).is_none()
    }

    fn trait_is_fundamental(self, trait_: Self::TraitId) -> bool {
        let trait_data = self.db().trait_signature(trait_.0);
        trait_data.flags.contains(TraitFlags::FUNDAMENTAL)
    }

    fn trait_may_be_implemented_via_object(self, _trait_def_id: Self::TraitId) -> bool {
        // FIXME(next-solver): should check the `TraitFlags` for
        // the `#[rustc_do_not_implement_via_object]` flag
        true
    }

    fn is_impl_trait_in_trait(self, _def_id: Self::DefId) -> bool {
        // FIXME(next-solver)
        false
    }

    fn delay_bug(self, msg: impl ToString) -> Self::ErrorGuaranteed {
        panic!("Bug encountered in next-trait-solver: {}", msg.to_string())
    }

    fn is_general_coroutine(self, def_id: Self::CoroutineId) -> bool {
        // FIXME: Make this a query? I don't believe this can be accessed from bodies other than
        // the current infer query, except with revealed opaques - is it rare enough to not matter?
        let InternedCoroutine(owner, expr_id) = def_id.0.loc(self.db);
        let body = self.db.body(owner);
        matches!(
            body[expr_id],
            hir_def::hir::Expr::Closure {
                closure_kind: hir_def::hir::ClosureKind::Coroutine(_),
                ..
            }
        )
    }

    fn coroutine_is_async(self, def_id: Self::CoroutineId) -> bool {
        // FIXME: Make this a query? I don't believe this can be accessed from bodies other than
        // the current infer query, except with revealed opaques - is it rare enough to not matter?
        let InternedCoroutine(owner, expr_id) = def_id.0.loc(self.db);
        let body = self.db.body(owner);
        matches!(
            body[expr_id],
            hir_def::hir::Expr::Closure { closure_kind: hir_def::hir::ClosureKind::Async, .. }
                | hir_def::hir::Expr::Async { .. }
        )
    }

    fn coroutine_is_gen(self, _coroutine_def_id: Self::CoroutineId) -> bool {
        // We don't handle gen coroutines yet.
        false
    }

    fn coroutine_is_async_gen(self, _coroutine_def_id: Self::CoroutineId) -> bool {
        // We don't handle gen coroutines yet.
        false
    }

    fn unsizing_params_for_adt(self, id: Self::AdtId) -> Self::UnsizingParams {
        let def = AdtDef::new(id.0, self);
        let num_params = self.generics_of(id.into()).count();

        let maybe_unsizing_param_idx = |arg: GenericArg<'db>| match arg.kind() {
            GenericArgKind::Type(ty) => match ty.kind() {
                rustc_type_ir::TyKind::Param(p) => Some(p.index),
                _ => None,
            },
            GenericArgKind::Lifetime(_) => None,
            GenericArgKind::Const(ct) => match ct.kind() {
                rustc_type_ir::ConstKind::Param(p) => Some(p.index),
                _ => None,
            },
        };

        // The last field of the structure has to exist and contain type/const parameters.
        let variant = def.non_enum_variant();
        let fields = variant.fields(self.db());
        let Some((tail_field, prefix_fields)) = fields.split_last() else {
            return UnsizingParams(DenseBitSet::new_empty(num_params));
        };

        let field_types = self.db().field_types(variant.id());
        let mut unsizing_params = DenseBitSet::new_empty(num_params);
        let ty = field_types[tail_field.0];
        for arg in ty.instantiate_identity().walk() {
            if let Some(i) = maybe_unsizing_param_idx(arg) {
                unsizing_params.insert(i);
            }
        }

        // Ensure none of the other fields mention the parameters used
        // in unsizing.
        for field in prefix_fields {
            for arg in field_types[field.0].instantiate_identity().walk() {
                if let Some(i) = maybe_unsizing_param_idx(arg) {
                    unsizing_params.remove(i);
                }
            }
        }

        UnsizingParams(unsizing_params)
    }

    fn anonymize_bound_vars<T: rustc_type_ir::TypeFoldable<Self>>(
        self,
        value: rustc_type_ir::Binder<Self, T>,
    ) -> rustc_type_ir::Binder<Self, T> {
        struct Anonymize<'a, 'db> {
            interner: DbInterner<'db>,
            map: &'a mut FxIndexMap<BoundVar, BoundVarKind>,
        }
        impl<'db> BoundVarReplacerDelegate<'db> for Anonymize<'_, 'db> {
            fn replace_region(&mut self, br: BoundRegion) -> Region<'db> {
                let entry = self.map.entry(br.var);
                let index = entry.index();
                let var = BoundVar::from_usize(index);
                let kind = (*entry.or_insert_with(|| BoundVarKind::Region(BoundRegionKind::Anon)))
                    .expect_region();
                let br = BoundRegion { var, kind };
                Region::new_bound(self.interner, DebruijnIndex::ZERO, br)
            }
            fn replace_ty(&mut self, bt: BoundTy) -> Ty<'db> {
                let entry = self.map.entry(bt.var);
                let index = entry.index();
                let var = BoundVar::from_usize(index);
                let kind =
                    (*entry.or_insert_with(|| BoundVarKind::Ty(BoundTyKind::Anon))).expect_ty();
                Ty::new_bound(self.interner, DebruijnIndex::ZERO, BoundTy { var, kind })
            }
            fn replace_const(&mut self, bv: BoundConst) -> Const<'db> {
                let entry = self.map.entry(bv.var);
                let index = entry.index();
                let var = BoundVar::from_usize(index);
                let () = (*entry.or_insert_with(|| BoundVarKind::Const)).expect_const();
                Const::new_bound(self.interner, DebruijnIndex::ZERO, BoundConst { var })
            }
        }

        let mut map = Default::default();
        let delegate = Anonymize { interner: self, map: &mut map };
        let inner = self.replace_escaping_bound_vars_uncached(value.skip_binder(), delegate);
        let bound_vars = CollectAndApply::collect_and_apply(map.into_values(), |xs| {
            BoundVarKinds::new_from_iter(self, xs.iter().cloned())
        });
        Binder::bind_with_vars(inner, bound_vars)
    }

    fn opaque_types_defined_by(self, def_id: Self::LocalDefId) -> Self::LocalDefIds {
        let Ok(def_id) = DefWithBodyId::try_from(def_id) else {
            return SolverDefIds::default();
        };
        let mut result = Vec::new();
        crate::opaques::opaque_types_defined_by(self.db, def_id, &mut result);
        SolverDefIds::new_from_iter(self, result)
    }

    fn opaque_types_and_coroutines_defined_by(self, def_id: Self::LocalDefId) -> Self::LocalDefIds {
        let Ok(def_id) = DefWithBodyId::try_from(def_id) else {
            return SolverDefIds::default();
        };
        let mut result = Vec::new();

        crate::opaques::opaque_types_defined_by(self.db, def_id, &mut result);

        // Collect coroutines.
        let body = self.db.body(def_id);
        body.exprs().for_each(|(expr_id, expr)| {
            if matches!(
                expr,
                hir_def::hir::Expr::Async { .. }
                    | hir_def::hir::Expr::Closure {
                        closure_kind: hir_def::hir::ClosureKind::Async
                            | hir_def::hir::ClosureKind::Coroutine(_),
                        ..
                    }
            ) {
                let coroutine =
                    InternedCoroutineId::new(self.db, InternedCoroutine(def_id, expr_id));
                result.push(coroutine.into());
            }
        });

        SolverDefIds::new_from_iter(self, result)
    }

    fn alias_has_const_conditions(self, _def_id: Self::DefId) -> bool {
        // FIXME(next-solver)
        false
    }

    fn explicit_implied_const_bounds(
        self,
        _def_id: Self::DefId,
    ) -> EarlyBinder<
        Self,
        impl IntoIterator<Item = rustc_type_ir::Binder<Self, rustc_type_ir::TraitRef<Self>>>,
    > {
        // FIXME(next-solver)
        EarlyBinder::bind([])
    }

    fn fn_is_const(self, id: Self::FunctionId) -> bool {
        let id = match id.0 {
            CallableDefId::FunctionId(id) => id,
            _ => return false,
        };
        self.db().function_signature(id).flags.contains(FnFlags::CONST)
    }

    fn impl_is_const(self, _def_id: Self::ImplId) -> bool {
        false
    }

    fn opt_alias_variances(
        self,
        _kind: impl Into<rustc_type_ir::AliasTermKind>,
        _def_id: Self::DefId,
    ) -> Option<Self::VariancesOf> {
        None
    }

    fn type_of_opaque_hir_typeck(self, def_id: Self::LocalDefId) -> EarlyBinder<Self, Self::Ty> {
        match def_id {
            SolverDefId::InternedOpaqueTyId(opaque) => {
                let impl_trait_id = self.db().lookup_intern_impl_trait_id(opaque);
                match impl_trait_id {
                    crate::ImplTraitId::ReturnTypeImplTrait(func, idx) => {
                        crate::opaques::rpit_hidden_types(self.db, func)[idx]
                    }
                    crate::ImplTraitId::TypeAliasImplTrait(type_alias, idx) => {
                        crate::opaques::tait_hidden_types(self.db, type_alias)[idx]
                    }
                }
            }
            _ => panic!("Unexpected SolverDefId in type_of_opaque_hir_typeck"),
        }
    }

    fn coroutine_hidden_types(
        self,
        _def_id: Self::CoroutineId,
    ) -> EarlyBinder<Self, Binder<'db, CoroutineWitnessTypes<Self>>> {
        // FIXME: Actually implement this.
        EarlyBinder::bind(Binder::dummy(CoroutineWitnessTypes {
            types: Tys::default(),
            assumptions: RegionAssumptions::default(),
        }))
    }

    fn is_default_trait(self, def_id: Self::TraitId) -> bool {
        self.as_trait_lang_item(def_id).map_or(false, |l| matches!(l, SolverTraitLangItem::Sized))
    }

    fn trait_is_coinductive(self, trait_: Self::TraitId) -> bool {
        self.db().trait_signature(trait_.0).flags.contains(TraitFlags::COINDUCTIVE)
    }

    fn trait_is_unsafe(self, trait_: Self::TraitId) -> bool {
        self.db().trait_signature(trait_.0).flags.contains(TraitFlags::UNSAFE)
    }

    fn impl_self_is_guaranteed_unsized(self, _def_id: Self::ImplId) -> bool {
        false
    }

    fn impl_specializes(
        self,
        specializing_impl_def_id: Self::ImplId,
        parent_impl_def_id: Self::ImplId,
    ) -> bool {
        crate::specialization::specializes(
            self.db,
            specializing_impl_def_id.0,
            parent_impl_def_id.0,
        )
    }

    fn next_trait_solver_globally(self) -> bool {
        true
    }

    type Probe = rustc_type_ir::solve::inspect::Probe<DbInterner<'db>>;
    fn mk_probe(self, probe: rustc_type_ir::solve::inspect::Probe<Self>) -> Self::Probe {
        probe
    }
    fn evaluate_root_goal_for_proof_tree_raw(
        self,
        canonical_goal: rustc_type_ir::solve::CanonicalInput<Self>,
    ) -> (rustc_type_ir::solve::QueryResult<Self>, Self::Probe) {
        rustc_next_trait_solver::solve::evaluate_root_goal_for_proof_tree_raw_provider::<
            SolverContext<'db>,
            Self,
        >(self, canonical_goal)
    }

    fn is_sizedness_trait(self, def_id: Self::TraitId) -> bool {
        matches!(
            self.as_trait_lang_item(def_id),
            Some(SolverTraitLangItem::Sized | SolverTraitLangItem::MetaSized)
        )
    }
}

impl<'db> DbInterner<'db> {
    pub fn shift_bound_var_indices<T>(self, bound_vars: usize, value: T) -> T
    where
        T: rustc_type_ir::TypeFoldable<Self>,
    {
        let shift_bv = |bv: BoundVar| BoundVar::from_usize(bv.as_usize() + bound_vars);
        self.replace_escaping_bound_vars_uncached(
            value,
            FnMutDelegate {
                regions: &mut |r: BoundRegion| {
                    Region::new_bound(
                        self,
                        DebruijnIndex::ZERO,
                        BoundRegion { var: shift_bv(r.var), kind: r.kind },
                    )
                },
                types: &mut |t: BoundTy| {
                    Ty::new_bound(
                        self,
                        DebruijnIndex::ZERO,
                        BoundTy { var: shift_bv(t.var), kind: t.kind },
                    )
                },
                consts: &mut |c| {
                    Const::new_bound(self, DebruijnIndex::ZERO, BoundConst { var: shift_bv(c.var) })
                },
            },
        )
    }

    pub fn replace_escaping_bound_vars_uncached<T: rustc_type_ir::TypeFoldable<DbInterner<'db>>>(
        self,
        value: T,
        delegate: impl BoundVarReplacerDelegate<'db>,
    ) -> T {
        if !value.has_escaping_bound_vars() {
            value
        } else {
            let mut replacer = BoundVarReplacer::new(self, delegate);
            value.fold_with(&mut replacer)
        }
    }

    pub fn replace_bound_vars_uncached<T: rustc_type_ir::TypeFoldable<DbInterner<'db>>>(
        self,
        value: Binder<'db, T>,
        delegate: impl BoundVarReplacerDelegate<'db>,
    ) -> T {
        self.replace_escaping_bound_vars_uncached(value.skip_binder(), delegate)
    }

    pub fn mk_fn_sig<I>(
        self,
        inputs: I,
        output: Ty<'db>,
        c_variadic: bool,
        safety: Safety,
        abi: FnAbi,
    ) -> FnSig<'db>
    where
        I: IntoIterator<Item = Ty<'db>>,
    {
        FnSig {
            inputs_and_output: Tys::new_from_iter(
                self,
                inputs.into_iter().chain(std::iter::once(output)),
            ),
            c_variadic,
            safety,
            abi,
        }
    }
}

macro_rules! TrivialTypeTraversalImpls {
    ($($ty:ty,)+) => {
        $(
            impl<'db> rustc_type_ir::TypeFoldable<DbInterner<'db>> for $ty {
                fn try_fold_with<F: rustc_type_ir::FallibleTypeFolder<DbInterner<'db>>>(
                    self,
                    _: &mut F,
                ) -> ::std::result::Result<Self, F::Error> {
                    Ok(self)
                }

                #[inline]
                fn fold_with<F: rustc_type_ir::TypeFolder<DbInterner<'db>>>(
                    self,
                    _: &mut F,
                ) -> Self {
                    self
                }
            }

            impl<'db> rustc_type_ir::TypeVisitable<DbInterner<'db>> for $ty {
                #[inline]
                fn visit_with<F: rustc_type_ir::TypeVisitor<DbInterner<'db>>>(
                    &self,
                    _: &mut F)
                    -> F::Result
                {
                    <F::Result as rustc_ast_ir::visit::VisitorResult>::output()
                }
            }
        )+
    };
}

TrivialTypeTraversalImpls! {
    SolverDefId,
    TraitIdWrapper,
    TypeAliasIdWrapper,
    CallableIdWrapper,
    ClosureIdWrapper,
    CoroutineIdWrapper,
    AdtIdWrapper,
    ImplIdWrapper,
    Pattern<'db>,
    Safety,
    FnAbi,
    Span,
    ParamConst,
    ParamTy,
    BoundRegion,
    BoundVar,
    Placeholder<BoundRegion>,
    Placeholder<BoundTy>,
    Placeholder<BoundVar>,
}

mod tls_db {
    use std::{cell::Cell, ptr::NonNull};

    use crate::db::HirDatabase;

    struct Attached {
        database: Cell<Option<NonNull<dyn HirDatabase>>>,
    }

    impl Attached {
        #[inline]
        fn attach<R>(&self, db: &dyn HirDatabase, op: impl FnOnce() -> R) -> R {
            struct DbGuard<'s> {
                state: Option<&'s Attached>,
            }

            impl<'s> DbGuard<'s> {
                #[inline]
                fn new(attached: &'s Attached, db: &dyn HirDatabase) -> Self {
                    match attached.database.get() {
                        Some(current_db) => {
                            let new_db = NonNull::from(db);
                            if !std::ptr::addr_eq(current_db.as_ptr(), new_db.as_ptr()) {
                                panic!(
                                    "Cannot change attached database. This is likely a bug.\n\
                                    If this is not a bug, you can use `attach_db_allow_change()`."
                                );
                            }
                            Self { state: None }
                        }
                        None => {
                            // Otherwise, set the database.
                            attached.database.set(Some(NonNull::from(db)));
                            Self { state: Some(attached) }
                        }
                    }
                }
            }

            impl Drop for DbGuard<'_> {
                #[inline]
                fn drop(&mut self) {
                    // Reset database to null if we did anything in `DbGuard::new`.
                    if let Some(attached) = self.state {
                        attached.database.set(None);
                    }
                }
            }

            let _guard = DbGuard::new(self, db);
            op()
        }

        #[inline]
        fn attach_allow_change<R>(&self, db: &dyn HirDatabase, op: impl FnOnce() -> R) -> R {
            struct DbGuard<'s> {
                state: &'s Attached,
                prev: Option<NonNull<dyn HirDatabase>>,
            }

            impl<'s> DbGuard<'s> {
                #[inline]
                fn new(attached: &'s Attached, db: &dyn HirDatabase) -> Self {
                    let prev = attached.database.replace(Some(NonNull::from(db)));
                    Self { state: attached, prev }
                }
            }

            impl Drop for DbGuard<'_> {
                #[inline]
                fn drop(&mut self) {
                    self.state.database.set(self.prev);
                }
            }

            let _guard = DbGuard::new(self, db);
            op()
        }

        #[inline]
        fn with<R>(&self, op: impl FnOnce(&dyn HirDatabase) -> R) -> R {
            let db = self.database.get().expect("Try to use attached db, but not db is attached");

            // SAFETY: The db is attached, so it must be valid.
            op(unsafe { db.as_ref() })
        }
    }

    thread_local! {
        static GLOBAL_DB: Attached = const { Attached { database: Cell::new(None) } };
    }

    #[inline]
    pub fn attach_db<R>(db: &dyn HirDatabase, op: impl FnOnce() -> R) -> R {
        GLOBAL_DB.with(|global_db| global_db.attach(db, op))
    }

    #[inline]
    pub fn attach_db_allow_change<R>(db: &dyn HirDatabase, op: impl FnOnce() -> R) -> R {
        GLOBAL_DB.with(|global_db| global_db.attach_allow_change(db, op))
    }

    #[inline]
    pub fn with_attached_db<R>(op: impl FnOnce(&dyn HirDatabase) -> R) -> R {
        GLOBAL_DB.with(
            #[inline]
            |a| a.with(op),
        )
    }
}

mod tls_cache {
    use crate::db::HirDatabase;

    use super::DbInterner;
    use base_db::Nonce;
    use rustc_type_ir::search_graph::GlobalCache;
    use salsa::Revision;
    use std::cell::RefCell;

    struct Cache {
        cache: GlobalCache<DbInterner<'static>>,
        revision: Revision,
        db_nonce: Nonce,
    }

    thread_local! {
        static GLOBAL_CACHE: RefCell<Option<Cache>> = const { RefCell::new(None) };
    }

    pub(super) fn with_cache<'db, T>(
        db: &'db dyn HirDatabase,
        f: impl FnOnce(&mut GlobalCache<DbInterner<'db>>) -> T,
    ) -> T {
        GLOBAL_CACHE.with_borrow_mut(|handle| {
            let (db_nonce, revision) = db.nonce_and_revision();
            let handle = match handle {
                Some(handle) => {
                    if handle.revision != revision || db_nonce != handle.db_nonce {
                        *handle = Cache { cache: GlobalCache::default(), revision, db_nonce };
                    }
                    handle
                }
                None => handle.insert(Cache { cache: GlobalCache::default(), revision, db_nonce }),
            };

            // SAFETY: No idea
            f(unsafe {
                std::mem::transmute::<
                    &mut GlobalCache<DbInterner<'static>>,
                    &mut GlobalCache<DbInterner<'db>>,
                >(&mut handle.cache)
            })
        })
    }

    /// Clears the thread-local trait solver cache.
    ///
    /// Should be called before getting memory usage estimations, as the solver cache
    /// is per-revision and usually should be excluded from estimations.
    pub fn clear_tls_solver_cache() {
        GLOBAL_CACHE.with_borrow_mut(|handle| *handle = None);
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
- **Location:** `d:\漏洞挖掘\detector\project\rust-main\library\core\src\mem\mod.rs:712`
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
- **Location:** `d:\漏洞挖掘\detector\project\rust-main\library\std\src\sys\stdio\windows.rs:286`
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
- **Location:** `d:\漏洞挖掘\detector\project\rust-main\library\test\src\term\win.rs:119`
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

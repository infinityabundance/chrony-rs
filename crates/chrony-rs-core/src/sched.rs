//! Timer-queue and event scheduler — a complete port of chrony 4.5 `sched.c`
//! (all 22 functions): the scheduling loop and timeout queue at the heart of the
//! daemon.
//!
//! # What this module is
//!
//! `sched.c` maintains an ordered queue of timeouts (each with an expiry instant, a
//! handler, and a *class* used for spacing similar events) and a table of
//! file-descriptor handlers, and runs the main loop: dispatch any expired timeouts,
//! compute how long until the next one, `select()` on the registered descriptors
//! with that timeout, then dispatch whichever descriptors became ready. It also
//! tracks the time of the last event (cooked, raw, and a monotonic low-precision
//! value) and shifts the whole queue when the clock steps.
//!
//! # Adaptations (documented, not silent)
//!
//! * **Host boundaries injected.** The raw clock (`LCL_ReadRawTime`), the cook step
//!   (`LCL_CookTime`), the randomness (`UTI_GetRandomBytes`), and — crucially —
//!   `select()` itself are injected as closures. The injected `select` may advance
//!   the (shared) clock, exactly as real time passes while a real `select` waits;
//!   this makes the loop fully deterministic and testable.
//! * **`fd_set` → explicit fd lists.** The kernel `fd_set`/`FD_*` bitset becomes
//!   ordered `Vec<usize>` of descriptors per event; the injected `select` reports
//!   which became ready. The logic (build sets from registered events, dispatch
//!   ready handlers in fd order, the exception-clears-read rule) is preserved.
//! * **Linked list + free-list → sorted `Vec`.** chrony hand-rolls a doubly-linked
//!   queue with a `TimerQueueEntry` slab allocator (`allocate_tqe`/`release_tqe`);
//!   the port keeps a `Vec<TimerQueueEntry>` sorted by expiry. Insertion position,
//!   tie-breaking (new entry after equal-time entries), and removal-by-id match.
//! * **Re-entrant handlers.** chrony's handlers run against global state and may
//!   add/remove timeouts. Here a handler is `FnMut(&mut Scheduler)`; a timeout's
//!   handler is *removed from the queue before it runs* (as chrony does), so it can
//!   be called with `&mut Scheduler` without aliasing.
//!
//! # Oracle
//!
//! Differential-tested against the **real compiled `sched.c`**: a C generator drives
//! the real timer queue through `SCH_MainLoop` with a clock-advancing stubbed
//! `select`, recording the dispatch order and fire times across ordering/tie/
//! by-delay/in-class(+separation,+randomness)/remove and a clock-step scenario
//! (`research/oracle/sched-c-vectors.txt`). The port replays the identical scenarios
//! (same injected clock/select/LCG) and matches every fired tag and time. The
//! file-handler path is covered by an independent Rust test. See the tests.

/// chrony `SCH_TimeoutClass`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TimeoutClass {
    /// `SCH_ReservedTimeoutValue` — used for plain (non-class) timeouts.
    Reserved = 0,
    /// `SCH_NtpClientClass`.
    NtpClient = 1,
    /// `SCH_NtpPeerClass`.
    NtpPeer = 2,
    /// `SCH_NtpBroadcastClass`.
    NtpBroadcast = 3,
    /// `SCH_PhcPollClass`.
    PhcPoll = 4,
}

/// chrony `SCH_NumberOfClasses`.
const NUMBER_OF_CLASSES: usize = 5;

/// chrony `SCH_FILE_INPUT`.
pub const SCH_FILE_INPUT: i32 = 1;
/// chrony `SCH_FILE_OUTPUT`.
pub const SCH_FILE_OUTPUT: i32 = 2;
/// chrony `SCH_FILE_EXCEPTION`.
pub const SCH_FILE_EXCEPTION: i32 = 4;

/// chrony `LCL_ChangeType` (the cases this module distinguishes).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ChangeType {
    /// A slew adjustment (`LCL_ChangeAdjust`).
    Adjust,
    /// A known step (`LCL_ChangeStep`).
    Step,
    /// An unknown step (`LCL_ChangeUnknownStep`).
    UnknownStep,
}

const NSEC_PER_SEC: i64 = 1_000_000_000;
const TS_MONO_PRECISION_NS: u32 = 10_000_000;
const JUMP_DETECT_THRESHOLD: i64 = 10;

/// A `struct timespec` with chrony's exact integer-nanosecond arithmetic.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Timespec {
    /// Seconds.
    pub tv_sec: i64,
    /// Nanoseconds.
    pub tv_nsec: i64,
}

impl Timespec {
    /// Construct from seconds and nanoseconds.
    pub fn new(tv_sec: i64, tv_nsec: i64) -> Self {
        Timespec { tv_sec, tv_nsec }
    }
    /// Build from floating-point seconds the way the test clock does.
    pub fn from_seconds(t: f64) -> Self {
        let sec = t as i64;
        Timespec { tv_sec: sec, tv_nsec: ((t - sec as f64) * 1.0e9) as i64 }
    }
    /// Seconds as `f64`.
    pub fn as_seconds(self) -> f64 {
        self.tv_sec as f64 + self.tv_nsec as f64 * 1.0e-9
    }
    fn normalise(&mut self) {
        if self.tv_nsec >= NSEC_PER_SEC || self.tv_nsec < 0 {
            self.tv_sec += self.tv_nsec / NSEC_PER_SEC;
            self.tv_nsec %= NSEC_PER_SEC;
            if self.tv_nsec < 0 {
                self.tv_sec -= 1;
                self.tv_nsec += NSEC_PER_SEC;
            }
        }
    }
    /// chrony `UTI_CompareTimespecs(self, b)`.
    fn compare(self, b: Timespec) -> i32 {
        if self.tv_sec < b.tv_sec {
            -1
        } else if self.tv_sec > b.tv_sec {
            1
        } else if self.tv_nsec < b.tv_nsec {
            -1
        } else if self.tv_nsec > b.tv_nsec {
            1
        } else {
            0
        }
    }
    /// chrony `UTI_AddDoubleToTimespec`.
    fn add_double(self, increment: f64) -> Timespec {
        let int_part = increment as i64;
        let mut end = Timespec {
            tv_sec: self.tv_sec + int_part,
            tv_nsec: self.tv_nsec + (1.0e9 * (increment - int_part as f64)) as i64,
        };
        end.normalise();
        end
    }
    /// chrony `UTI_DiffTimespecs(self, b)` = `self - b`, normalised.
    fn diff(self, b: Timespec) -> Timespec {
        let mut r = Timespec { tv_sec: self.tv_sec - b.tv_sec, tv_nsec: self.tv_nsec - b.tv_nsec };
        r.normalise();
        r
    }
    /// chrony `UTI_DiffTimespecsToDouble(self, b)`.
    fn diff_to_double(self, b: Timespec) -> f64 {
        (self.tv_sec as f64 - b.tv_sec as f64) + 1.0e-9 * (self.tv_nsec - b.tv_nsec) as f64
    }
    /// chrony `UTI_TimespecToDouble`.
    fn to_double(self) -> f64 {
        self.tv_sec as f64 + 1.0e-9 * self.tv_nsec as f64
    }
    /// Microsecond-truncated `(sec, usec)`, as `UTI_TimespecToTimeval`.
    fn to_timeval(self) -> (i64, i64) {
        (self.tv_sec, self.tv_nsec / 1000)
    }
}

/// What the injected `select` reports: the status (`>0` ready, `0` timeout, `<0`
/// error) and which descriptors are ready for each event.
pub struct SelectResult {
    /// `select()` return value.
    pub status: i32,
    /// Descriptors ready for reading.
    pub ready_read: Vec<usize>,
    /// Descriptors ready for writing.
    pub ready_write: Vec<usize>,
    /// Descriptors with an exception.
    pub ready_except: Vec<usize>,
}

/// The injected `select` primitive: given the requested descriptor sets and an
/// optional timeout (seconds; `None` ⇒ block), wait and report readiness. It may
/// advance the shared clock (as real time passes during a real `select`).
type SelectFn = Box<
    dyn FnMut(Option<f64>, &[usize], &[usize], &[usize]) -> SelectResult,
>;

/// A file-descriptor handler: `(scheduler, fd, event)`.
pub type FileHandler = Box<dyn FnMut(&mut Scheduler, i32, i32)>;

/// A timeout handler: `(scheduler)`.
pub type TimeoutHandler = Box<dyn FnMut(&mut Scheduler)>;

/// A registered file-descriptor handler.
struct FileHandlerEntry {
    handler: Option<FileHandler>,
    events: i32,
}

/// A queued timeout (chrony `TimerQueueEntry`).
struct TimerQueueEntry {
    ts: Timespec,
    id: u32,
    class: TimeoutClass,
    handler: TimeoutHandler,
}

/// The scheduler (chrony's `sched.c` module state) over injected host primitives.
pub struct Scheduler {
    initialised: bool,
    file_handlers: Vec<FileHandlerEntry>,
    one_highest_fd: usize,
    /// Timeout queue, kept sorted ascending by `ts`.
    timer_queue: Vec<TimerQueueEntry>,
    next_tqe_id: u32,
    last_class_dispatch: [Timespec; NUMBER_OF_CLASSES],
    need_to_exit: bool,
    last_select_ts: Timespec,
    last_select_ts_raw: Timespec,
    last_select_ts_err: f64,
    last_select_ts_mono: f64,
    last_select_ts_mono_ns: u32,
    raw_clock: Box<dyn FnMut() -> Timespec>,
    cook_time: Box<dyn FnMut(Timespec) -> (Timespec, f64)>,
    rng: Box<dyn FnMut() -> u32>,
    select_fn: SelectFn,
}

impl Scheduler {
    /// chrony `SCH_Initialise`.
    pub fn new(
        mut raw_clock: Box<dyn FnMut() -> Timespec>,
        cook_time: Box<dyn FnMut(Timespec) -> (Timespec, f64)>,
        rng: Box<dyn FnMut() -> u32>,
        select_fn: SelectFn,
    ) -> Self {
        let raw = raw_clock();
        Scheduler {
            initialised: true,
            file_handlers: Vec::new(),
            one_highest_fd: 0,
            timer_queue: Vec::new(),
            next_tqe_id: 0,
            last_class_dispatch: [Timespec::default(); NUMBER_OF_CLASSES],
            need_to_exit: false,
            last_select_ts: raw,
            last_select_ts_raw: raw,
            last_select_ts_err: 0.0,
            last_select_ts_mono: 0.0,
            last_select_ts_mono_ns: 0,
            raw_clock,
            cook_time,
            rng,
            select_fn,
        }
    }

    /// chrony `SCH_Finalise`.
    pub fn finalise(&mut self) {
        self.file_handlers.clear();
        self.timer_queue.clear();
        self.initialised = false;
    }

    fn read_raw_time(&mut self) -> Timespec {
        (self.raw_clock)()
    }

    // ---- file handlers ----

    /// chrony `SCH_AddFileHandler`.
    pub fn add_file_handler(
        &mut self,
        fd: usize,
        events: i32,
        handler: FileHandler,
    ) {
        assert!(self.initialised);
        assert!(events != 0);
        while self.file_handlers.len() <= fd {
            self.file_handlers.push(FileHandlerEntry { handler: None, events: 0 });
        }
        // chrony forbids double-registration without removal.
        assert!(self.file_handlers[fd].handler.is_none());
        self.file_handlers[fd] = FileHandlerEntry { handler: Some(handler), events };
        if self.one_highest_fd < fd + 1 {
            self.one_highest_fd = fd + 1;
        }
    }

    /// chrony `SCH_RemoveFileHandler`.
    pub fn remove_file_handler(&mut self, fd: usize) {
        assert!(self.initialised);
        assert!(self.file_handlers[fd].handler.is_some());
        self.file_handlers[fd].handler = None;
        self.file_handlers[fd].events = 0;
        while self.one_highest_fd > 0 {
            if self.file_handlers[self.one_highest_fd - 1].handler.is_some() {
                break;
            }
            self.one_highest_fd -= 1;
        }
    }

    /// chrony `SCH_SetFileHandlerEvent`.
    pub fn set_file_handler_event(&mut self, fd: usize, event: i32, enable: bool) {
        let e = &mut self.file_handlers[fd].events;
        if enable {
            *e |= event;
        } else {
            *e &= !event;
        }
    }

    // ---- last-event time ----

    /// chrony `SCH_GetLastEventTime`: `(cooked, err, raw)`.
    pub fn get_last_event_time(&self) -> (Timespec, f64, Timespec) {
        (self.last_select_ts, self.last_select_ts_err, self.last_select_ts_raw)
    }

    /// chrony `SCH_GetLastEventMonoTime`.
    pub fn get_last_event_mono_time(&self) -> f64 {
        self.last_select_ts_mono
    }

    // ---- timer queue ----

    /// chrony `get_new_tqe_id`: smallest unused non-zero id.
    fn get_new_tqe_id(&mut self) -> u32 {
        loop {
            self.next_tqe_id = self.next_tqe_id.wrapping_add(1);
            if self.next_tqe_id == 0 {
                continue;
            }
            if self.timer_queue.iter().all(|e| e.id != self.next_tqe_id) {
                return self.next_tqe_id;
            }
        }
    }

    /// Insert a fully-built entry at the chrony position: before the first entry
    /// strictly greater (so equal-time entries keep insertion order). This is the
    /// `allocate_tqe` + list-splice of chrony, over a sorted `Vec`.
    fn insert_entry(&mut self, entry: TimerQueueEntry) -> u32 {
        let id = entry.id;
        let pos = self
            .timer_queue
            .iter()
            .position(|e| entry.ts.compare(e.ts) == -1)
            .unwrap_or(self.timer_queue.len());
        self.timer_queue.insert(pos, entry);
        id
    }

    /// chrony `SCH_AddTimeout`.
    pub fn add_timeout(&mut self, ts: Timespec, handler: TimeoutHandler) -> u32 {
        assert!(self.initialised);
        let id = self.get_new_tqe_id();
        self.insert_entry(TimerQueueEntry { ts, id, class: TimeoutClass::Reserved, handler })
    }

    /// chrony `SCH_AddTimeoutByDelay`: relative to the current raw time.
    pub fn add_timeout_by_delay(
        &mut self,
        delay: f64,
        handler: TimeoutHandler,
    ) -> u32 {
        assert!(self.initialised);
        assert!(delay >= 0.0);
        let now = self.read_raw_time();
        let then = now.add_double(delay);
        assert!(now.compare(then) <= 0, "timeout overflow");
        self.add_timeout(then, handler)
    }

    /// chrony `SCH_AddTimeoutInClass`: schedule keeping at least `separation` from
    /// other timeouts of the same class and from the last dispatch of that class.
    pub fn add_timeout_in_class(
        &mut self,
        mut min_delay: f64,
        mut separation: f64,
        randomness: f64,
        class: TimeoutClass,
        handler: TimeoutHandler,
    ) -> u32 {
        assert!(self.initialised);
        assert!(min_delay >= 0.0);

        if randomness > 0.0 {
            let rnd = (self.rng)();
            let r = rnd as f64 * (randomness / u32::MAX as f64) + 1.0;
            min_delay *= r;
            separation *= r;
        }

        let now = self.read_raw_time();
        let mut new_min_delay = min_delay;

        // Separation from the last dispatch of this class.
        let diff = now.diff_to_double(self.last_class_dispatch[class as usize]);
        if diff < separation && diff >= 0.0 && diff + new_min_delay < separation {
            new_min_delay = separation - diff;
        }

        // Keep separation from existing entries in the same class.
        for e in &self.timer_queue {
            if e.class == class {
                let diff = e.ts.diff_to_double(now);
                if new_min_delay > diff {
                    if new_min_delay - diff < separation {
                        new_min_delay = diff + separation;
                    }
                } else if diff - new_min_delay < separation {
                    new_min_delay = diff + separation;
                }
            }
        }

        // Locate the insertion point (first entry later than new_min_delay).
        let pos = self
            .timer_queue
            .iter()
            .position(|e| e.ts.diff_to_double(now) > new_min_delay)
            .unwrap_or(self.timer_queue.len());

        let id = self.get_new_tqe_id();
        let entry = TimerQueueEntry { ts: now.add_double(new_min_delay), id, class, handler };
        self.timer_queue.insert(pos, entry);
        id
    }

    /// chrony `SCH_RemoveTimeout`.
    pub fn remove_timeout(&mut self, id: u32) {
        assert!(self.initialised);
        if id == 0 {
            return;
        }
        let pos = self.timer_queue.iter().position(|e| e.id == id);
        match pos {
            Some(p) => {
                self.timer_queue.remove(p);
            }
            None => panic!("SCH_RemoveTimeout: invalid id {id}"),
        }
    }

    /// chrony `dispatch_timeouts`: fire all expired timeouts, re-reading the clock
    /// each iteration. Returns the last raw time read.
    fn dispatch_timeouts(&mut self) -> Timespec {
        let n_entries_on_start = self.timer_queue.len() as u64;
        let mut n_done: u64 = 0;
        let mut now;
        loop {
            now = self.read_raw_time();
            if self.timer_queue.is_empty() || now.compare(self.timer_queue[0].ts) < 0 {
                break;
            }

            let class = self.timer_queue[0].class;
            self.last_class_dispatch[class as usize] = now;

            // Remove the entry before dispatching (chrony does the same), so the
            // owned handler can mutate the scheduler re-entrantly.
            let mut entry = self.timer_queue.remove(0);
            (entry.handler)(self);
            n_done += 1;

            // Infinite-loop safety (chrony): a flood of zero-delay timeouts.
            if n_done > 20
                && n_done > 4 * n_entries_on_start.max(self.timer_queue.len() as u64)
                && (now.diff_to_double(self.last_select_ts_raw)).abs() / (n_done as f64) < 0.01
            {
                panic!("possible infinite loop in scheduling");
            }

            if self.need_to_exit {
                break;
            }
        }
        now
    }

    /// chrony `handle_slew`: on a step, shift all raw timestamps; always re-anchor
    /// the cooked last-select time.
    pub fn handle_slew(
        &mut self,
        cooked: Timespec,
        dfreq: f64,
        doffset: f64,
        change_type: ChangeType,
    ) {
        if change_type != ChangeType::Adjust {
            for e in &mut self.timer_queue {
                e.ts = e.ts.add_double(-doffset);
            }
            for d in &mut self.last_class_dispatch {
                *d = d.add_double(-doffset);
            }
            self.last_select_ts_raw = self.last_select_ts_raw.add_double(-doffset);
        }
        // UTI_AdjustTimespec(last_select_ts, cooked, &out, &delta, dfreq, doffset).
        let elapsed = cooked.diff_to_double(self.last_select_ts);
        let delta = elapsed * dfreq - doffset;
        self.last_select_ts = self.last_select_ts.add_double(delta);
    }

    /// chrony `fill_fd_sets`: the descriptors wanting read/write/except events.
    fn fill_fd_sets(&self) -> (Vec<usize>, Vec<usize>, Vec<usize>) {
        let (mut rd, mut wr, mut ex) = (Vec::new(), Vec::new(), Vec::new());
        for (fd, h) in self.file_handlers.iter().enumerate() {
            if h.events == 0 {
                continue;
            }
            if h.events & SCH_FILE_INPUT != 0 {
                rd.push(fd);
            }
            if h.events & SCH_FILE_OUTPUT != 0 {
                wr.push(fd);
            }
            if h.events & SCH_FILE_EXCEPTION != 0 {
                ex.push(fd);
            }
        }
        (rd, wr, ex)
    }

    /// Invoke the handler registered for `fd` with `event`, taking it out across the
    /// call so it can mutate the scheduler, then restoring it if still registered.
    fn dispatch_one(&mut self, fd: usize, event: i32) {
        if fd >= self.file_handlers.len() {
            return;
        }
        let Some(mut handler) = self.file_handlers[fd].handler.take() else {
            return;
        };
        handler(self, fd as i32, event);
        // Restore unless the handler removed/replaced itself during the call.
        if fd < self.file_handlers.len() && self.file_handlers[fd].handler.is_none() {
            self.file_handlers[fd].handler = Some(handler);
        }
    }

    /// chrony `dispatch_filehandlers`: fire ready descriptors in fd order. An
    /// exception clears a pending read for that fd.
    fn dispatch_filehandlers(&mut self, res: &SelectResult) {
        for fd in 0..self.one_highest_fd {
            let has_except = res.ready_except.contains(&fd);
            let mut has_read = res.ready_read.contains(&fd);
            let has_write = res.ready_write.contains(&fd);

            if has_except {
                self.dispatch_one(fd, SCH_FILE_EXCEPTION);
                has_read = false; // don't read from it now
            }
            if has_read {
                self.dispatch_one(fd, SCH_FILE_INPUT);
            }
            if has_write {
                self.dispatch_one(fd, SCH_FILE_OUTPUT);
            }
        }
    }

    /// chrony `update_monotonic_time`.
    fn update_monotonic_time(&mut self, now: Timespec, before: Timespec) {
        let diff = now.diff(before);
        if diff.tv_sec == 0 {
            self.last_select_ts_mono_ns += diff.tv_nsec as u32;
        } else {
            self.last_select_ts_mono +=
                (diff.to_double() + self.last_select_ts_mono_ns as f64 / 1.0e9).abs();
            self.last_select_ts_mono_ns = 0;
        }
        if self.last_select_ts_mono_ns > TS_MONO_PRECISION_NS {
            self.last_select_ts_mono += self.last_select_ts_mono_ns as f64 / 1.0e9;
            self.last_select_ts_mono_ns = 0;
        }
    }

    /// chrony `check_current_time`: detect an unexpected clock jump. Returns whether
    /// the time looks sane (`true`). `orig`/`rem` are the original/remaining select
    /// timeouts (microsecond `(sec, usec)`); `timeout` is whether select timed out.
    fn check_current_time(
        &mut self,
        prev_raw: Timespec,
        raw: Timespec,
        timeout: bool,
        orig: Option<(i64, i64)>,
        rem: Option<(i64, i64)>,
    ) -> bool {
        let orig_ts = orig.map(|(s, u)| Timespec::new(s, u * 1000)).unwrap_or_default();
        let (elapsed_min, elapsed_max);
        if timeout {
            elapsed_min = orig_ts;
            elapsed_max = orig_ts;
        } else if let Some((rs, ru)) = rem.filter(|&(rs, ru)| {
            let (os, ou) = orig.unwrap();
            rs >= 0 && rs <= os && (rs != os || ru != ou)
        }) {
            let rem_ts = Timespec::new(rs, ru * 1000);
            elapsed_min = orig_ts.diff(rem_ts);
            elapsed_max = elapsed_min;
        } else if rem.is_some() {
            elapsed_max = orig_ts;
            elapsed_min = Timespec::default();
        } else {
            elapsed_max = raw.diff(prev_raw);
            elapsed_min = Timespec::default();
        }

        if self.last_select_ts_raw.tv_sec + elapsed_min.tv_sec
            > raw.tv_sec + JUMP_DETECT_THRESHOLD
            || prev_raw.tv_sec + elapsed_max.tv_sec + JUMP_DETECT_THRESHOLD < raw.tv_sec
        {
            // A jump: chrony notifies LCL of an external step. The injected cook
            // closure already reflects the clock, so nothing else to do here.
            return false;
        }
        true
    }

    /// chrony `SCH_MainLoop`.
    pub fn main_loop(&mut self) {
        assert!(self.initialised);
        while !self.need_to_exit {
            let saved_now = self.dispatch_timeouts();
            if self.need_to_exit {
                break;
            }

            // Time to the next timeout (microsecond-truncated, as chrony's timeval).
            let (timeout, orig_tv) = if !self.timer_queue.is_empty() {
                let ts = self.timer_queue[0].ts.diff(saved_now);
                assert!(ts.tv_sec > 0 || ts.tv_nsec > 0);
                let (s, u) = ts.to_timeval();
                (Some(s as f64 + u as f64 * 1e-6), Some((s, u)))
            } else {
                (None, None)
            };

            let (rd, wr, ex) = self.fill_fd_sets();
            if timeout.is_none() && rd.is_empty() && wr.is_empty() {
                panic!("nothing to do");
            }

            let res = (self.select_fn)(timeout, &rd, &wr, &ex);

            let now = self.read_raw_time();
            let (mut cooked, mut err) = (self.cook_time)(now);
            self.update_monotonic_time(now, self.last_select_ts_raw);

            // `select` consumed the timeout; model the remaining as zero.
            let rem_tv = orig_tv.map(|_| (0i64, 0i64));
            if !self.check_current_time(saved_now, now, res.status == 0, orig_tv, rem_tv) {
                let c = (self.cook_time)(now);
                cooked = c.0;
                err = c.1;
            }

            self.last_select_ts_raw = now;
            self.last_select_ts = cooked;
            self.last_select_ts_err = err;

            if res.status > 0 {
                self.dispatch_filehandlers(&res);
            }
        }
    }

    /// chrony `SCH_QuitProgram`.
    pub fn quit_program(&mut self) {
        self.need_to_exit = true;
    }

    /// Current raw time as `f64` seconds (used by handlers/tests).
    pub fn now_seconds(&mut self) -> f64 {
        self.read_raw_time().as_seconds()
    }
}

#[cfg(test)]
mod tests;

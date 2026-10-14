// Everything the app shows that comes from the router, and the few primitives every action uses. Nothing here is
// optimistic: a row changes only when the router reports the new state; an action in flight shows as a pending label
// on its row or button (`pending`), and a second tap meanwhile is refused (`exclusive`).
import Observation
import SwiftUI

struct Loaded<T: Equatable>: Equatable {
  var items: [T] = []
  var loaded = false
  var error: String?
}

enum AppTab: Hashable { case sessions, inbox, tasks, settings, search }

/// a short note at the bottom of the screen ("Session id copied"); errors from user actions are alerts
struct Notice: Identifiable, Equatable { let id = UUID(); let text: String }

/// a question before an action (Destroy? Resume with a prompt?), answered on an alert; `input` adds a text field,
/// `match` makes the action wait until exactly that text is typed (Delete permanently)
struct Ask: Identifiable {
  let id = UUID()
  let title: String
  var message: String = ""
  let action: String
  var destructive = false
  var input: (placeholder: String, match: String?)?
  let answer: (String?) -> Void
}

@Observable @MainActor
final class AppModel {
  // ---- api/state ----
  var sessions: [Session] = []
  var approvals: [Approval] = []
  var inbox: [InboxItem] = []
  /// batches (router/batches.go): several Inbox items filed together, reviewed on one page under one Face ID
  var inboxBatches: [InboxBatch] = []
  /// secrets answers the router (GET api/state `secrets.up`)
  var secretsUp = false
  /// the router holds root's ⊤ on the sink (made once at setup with the root key); nil before the first state
  var rootGrant: Bool?
  var budget: JSON = .null
  var fly: JSON = .null
  var flyApp: String?
  var repos: [RepoEntry] = []
  var loaded = false
  var loadError: String?

  // ---- lists loaded on demand ----
  var sizes: [Choice] = []
  var models: [Choice] = []
  /// the stores each harness brings (GET api/policy): the router adds them, the pickers don't offer them
  var policy: [String: [String]] = [:]
  var records = Loaded<Rec>()
  /// secrets' signed store list (verified against the pinned key)
  var stores = Loaded<StoreView>()
  var openUnlocks: [UnlockRow] = []
  var machines = Loaded<Machine>()
  /// the whole answer of api/machines: every Fly org and app (router/flyorgs.go)
  var machinesDoc: JSON = .null
  var tasks = TasksOverview()
  var tasksLoaded = false
  var tasksError: String?

  // ---- the app around them ----
  var tab: AppTab = .sessions
  var pending: [String: String] = [:]
  var notice: Notice?
  /// an action failed: one alert
  var failure: String?
  var question: Ask?
  /// the review sheet up now, and what runs when it closes (true = it went through)
  var secure: SecureRequest?
  @ObservationIgnored private var secureDone: ((Bool) -> Void)?
  @ObservationIgnored private var secureFinished = false
  /// Reset or recover (at first launch, after a core change, or from Settings)
  var showSetup = false
  var signedOut = false
  var harnessHidden: Set<String> { Set(policy.values.flatMap { $0 }) }
  /// the Inbox's entries: each batch counts once
  var inboxCount: Int { inboxLoose.count + inboxBatches.count }
  /// the items in no listed batch
  var inboxLoose: [InboxItem] {
    let ids = Set(inboxBatches.map(\.id))
    return inbox.filter { $0.batch.map { !ids.contains($0) } ?? true }
  }
  func batchItems(_ b: InboxBatch) -> [InboxItem] { b.items.compactMap { id in inbox.first { $0.id == id } } }

  @ObservationIgnored private var pollTask: Task<Void, Never>?
  @ObservationIgnored private var fastUntil = Date.distantPast
  @ObservationIgnored private var lastPoll = Date.distantPast
  @ObservationIgnored private var machinesAt = Date.distantPast
  @ObservationIgnored private var tasksAt = Date.distantPast
  @ObservationIgnored private var running: Set<String> = []
  @ObservationIgnored private var stateRun: Coalescer?
  @ObservationIgnored private var storesRun: Coalescer?
  @ObservationIgnored private var recordsRun: Coalescer?
  @ObservationIgnored private var machinesRun: Coalescer?
  @ObservationIgnored private var tasksRun: Coalescer?

  init() {
    stateRun = Coalescer { [weak self] in await self?.fetchState() }
    storesRun = Coalescer { [weak self] in await self?.fetchStores() }
    recordsRun = Coalescer { [weak self] in await self?.fetchRecords() }
    machinesRun = Coalescer { [weak self] in await self?.fetchMachines() }
    tasksRun = Coalescer { [weak self] in await self?.fetchTasks() }
  }

  // ---- launch ----
  func launch() async {
    RouterClient.shared.onSignedOut = { [weak self] out in self?.signedOut = out }
    // the master private key an earlier build held in the Keychain: no core trusts it any more
    Keychain.set("held-master", nil); Keychain.set("held-master-public", nil)
    if CoreTrust.pinned == nil {
      showSetup = true
    } else if let x = try? await RouterClient.shared.identity(), x.id.signingKey != CoreTrust.pinned?.signingKey {
      // a restarted secrets is a new, empty one: until it is set up again nothing can be signed
      showSetup = true
    }
    start()
  }

  private func start() {
    guard pollTask == nil else { return }
    Task { await loadLists() }
    pollTask = Task { [weak self] in
      while !Task.isCancelled {
        guard let self else { return }
        if Date.now < self.fastUntil || Date.now.timeIntervalSince(self.lastPoll) >= 15 {
          self.lastPoll = .now
          await self.refresh()
        }
        if self.tab == .tasks, Date.now.timeIntervalSince(self.tasksAt) >= 15 || self.tasks.instances.contains(where: { $0.activeRun != nil || $0.lastRun?.active == true }) {
          await self.loadTasks()
        }
        try? await Task.sleep(for: .seconds(2))
      }
    }
  }

  /// the router's lists that change rarely (sizes, models, the harnesses' stores) and secrets' stores
  func loadLists() async {
    let r = RouterClient.shared
    if let j = try? await r.get("api/sizes") { sizes = j["sizes"].array.map(Choice.init) }
    if let j = try? await r.get("api/models") { models = j["models"].array.map(Choice.init) }
    if let j = try? await r.get("api/policy") { policy = (j["harnesses"].object ?? [:]).mapValues { $0["stores"].strings } }
    await loadStores()
  }

  /// back in the foreground: refresh at once (also where an expired login gets noticed)
  func foreground() { Task { await refresh() } }

  // ---- api/state, coalesced: a call while one runs gets ONE follow-up that starts after it ----
  func refresh() async { await stateRun?.run() }
  /// follow the sessions closely for a while (2 s polls)
  func settle(_ seconds: Double = 90) { fastUntil = max(fastUntil, .now.addingTimeInterval(seconds)) }

  private func fetchState() async {
    do {
      let j = try await RouterClient.shared.get("api/state")
      sessions = j["sessions"].array.map(Session.init)
      approvals = j["approvals"].array.map(Approval.init)
      inbox = j["inbox"].array.map(InboxItem.init)
      inboxBatches = j["inboxBatches"].array.map(InboxBatch.init)
      secretsUp = j["secrets"]["up"].bool == true
      rootGrant = j["rootGrant"].bool
      budget = j["budget"]
      fly = j["fly"]
      flyApp = j["flyApp"].text
      repos = j["repos"].array.map(RepoEntry.init)
      loaded = true
      loadError = nil
      signedOut = false
      if sessions.contains(where: { ["starting", "approval", "initialising", "pausing", "resuming", "destroying"].contains($0.state) }) { settle(4) }
    } catch is SignedOut {
      signedOut = true
    } catch {
      loadError = errText(error)
    }
  }

  /// refresh until `pred` holds (or `seconds` pass); true when it held
  @discardableResult
  func refreshUntil(_ seconds: Double, _ pred: (AppModel) -> Bool) async -> Bool {
    let until = Date.now.addingTimeInterval(seconds)
    while Date.now < until {
      await refresh()
      if pred(self) { return true }
      try? await Task.sleep(for: .seconds(1))
    }
    return false
  }
  func session(_ id: String) -> Session? { sessions.first { $0.id == id } }

  // ---- the on-demand lists ----
  func loadStores() async { await storesRun?.run() }
  private func fetchStores() async {
    guard CoreTrust.pinned != nil else { stores.error = "Jarvis 2 isn't set up on this iPhone yet."; return }
    do {
      let d = try await RouterClient.shared.storesDoc()
      stores = Loaded(items: d.stores.filter { !$0.isCore }, loaded: true, error: nil)
      openUnlocks = (try? await RouterClient.shared.unlocked()) ?? openUnlocks
    } catch { stores.error = errText(error) }
  }
  func loadRecords() async { await recordsRun?.run() }
  private func fetchRecords() async {
    do { records = Loaded(items: try await RouterClient.shared.get("api/records")["records"].array.map(Rec.init), loaded: true, error: nil) }
    catch { records.error = errText(error) }
  }
  func loadMachines() async { await machinesRun?.run() }
  private func fetchMachines() async {
    machinesAt = .now
    do {
      let j = try await RouterClient.shared.get("api/machines")
      machinesDoc = j
      machines = Loaded(items: j["machines"].array.map(Machine.init), loaded: true, error: nil)
    }
    catch { machines.error = errText(error) }
  }
  func loadTasks() async { await tasksRun?.run() }
  private func fetchTasks() async {
    tasksAt = .now
    do { tasks = TasksOverview(j: try await RouterClient.shared.get("api/tasks")); tasksLoaded = true; tasksError = nil }
    catch { tasksError = errText(error) }
  }

  // ---- actions ----
  func say(_ text: String) { notice = Notice(text: text) }
  func fail(_ e: Error, _ prefix: String = "") { failure = prefix + errText(e) }
  func pend(_ key: String, _ label: String?) { pending[key] = label }

  /// one run per key at a time, whichever button or menu started it
  func exclusive(_ key: String, _ fn: () async -> Void) async {
    guard !running.contains(key) else { say("Still busy with the last action."); return }
    running.insert(key)
    defer { running.remove(key) }
    await fn()
  }
  /// run an action and keep its pending label until the router CONFIRMS the outcome
  func pendUntil(_ key: String, _ label: String, _ seconds: Double = 60, action: () async throws -> Void, until pred: @escaping (AppModel) -> Bool) async {
    await exclusive(key) {
      pend(key, label)
      defer { pend(key, nil) }
      do { try await action(); await refreshUntil(seconds, pred) }
      catch { fail(error); await refresh() }
    }
  }

  /// a question on an alert; nil = cancelled, otherwise the typed text ("" without a field)
  func ask(_ title: String, _ message: String = "", action: String, destructive: Bool = false, input: (placeholder: String, match: String?)? = nil) async -> String? {
    await withCheckedContinuation { k in
      question = Ask(title: title, message: message, action: action, destructive: destructive, input: input) { k.resume(returning: $0) }
    }
  }
  func confirm(_ title: String, _ message: String = "", action: String, destructive: Bool = false) async -> Bool {
    await ask(title, message, action: action, destructive: destructive) != nil
  }

  // ---- the review sheets ----
  func present(_ r: SecureRequest, done: ((Bool) -> Void)? = nil) {
    secureDone = done
    secureFinished = false
    secureInbox = r.inboxId
    secure = r
  }
  /// the sheet's page went through (or the request was denied there): close it and tell the caller
  func secureCompleted(_ ok: Bool) {
    guard !secureFinished else { return }
    secureFinished = true
    let done = secureDone
    secureDone = nil
    secure = nil
    if let id = secureInbox, ok { Task { await RouterClient.shared.inboxDone(id) } }
    done?(ok)
    Task { await refresh(); await loadStores() }
    settle(30)
  }
  @ObservationIgnored var secureInbox: String?
  /// the sheet was dismissed (Cancel, a swipe down): nothing was signed
  func secureDismissed() { secureCompleted(false) }
}

/// One request at a time; a call while one runs gets ONE follow-up that starts after it (never the running one,
/// which was sent before the caller's change and would hand back the old state).
@MainActor
final class Coalescer {
  private let fn: () async -> Void
  private var running: Task<Void, Never>?
  private var next: Task<Void, Never>?
  init(_ fn: @escaping () async -> Void) { self.fn = fn }
  func run() async {
    if let running {
      if let next { await next.value; return }
      let n = Task { await running.value; await self.begin() }
      next = n
      await n.value
      return
    }
    await begin()
  }
  private func begin() async {
    next = nil
    let t = Task { await fn() }
    running = t
    await t.value
    running = nil
  }
}

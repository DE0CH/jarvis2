// The router's shapes (docs/API.md), read through JSON (Model/JSON.swift). Each is a thin view over the object the
// router sent: identity comes from the object's own id, so lists keep their rows across polls.
import Foundation

/// a session line (GET api/state `sessions`)
struct Session: Identifiable, Equatable, Hashable {
  let j: JSON
  var id: String { j["id"].string ?? "" }
  var state: String { j["state"].string ?? "" }
  /// Resume brings it back: paused, or failed with no machine (a failed or cut-off start; router Resume)
  var resumable: Bool { state == "paused" || (state == "failed" && j["machineId"].text == nil) }
  var status: String? { j["status"].text }
  var harness: String { j["harness"].text ?? "claude" }
  var model: String? { j["model"].text }
  var region: String? { j["region"].text }
  var guest: String? { j["guest"].text }
  var size: String? { j["size"].text }
  var image: String? { j["image"].text }
  var created: Date? { j["created"].string?.isoDate }
  var pausedAt: Date? { j["pausedAt"].string?.isoDate }
  var error: String? { j["error"].text }
  var permissionMode: String { j["permissionMode"].string == "bypass" ? "bypass" : "auto" }
  var oneShot: Bool { j["oneShot"].bool == true }
  var oneShotDone: Bool { j["oneShotDone"].bool == true }
  var authFailed: Bool { j["authFailed"].bool == true }
  var autoPause: Bool { j["autoPause"].string != "off" }
  var notifyIdle: Bool { j["notifyIdle"].string != "off" }
  var bgTasks: Int { j["bgTasks"].int ?? 0 }
  var pauseInMs: Double? { j["pauseInMs"].double }
  var needsGrant: String? { j["needsGrant"].text }
  var lockedStore: String? { j["lockedStore"].text }
  var waiting: String? { j["waiting"].text }
  var resumePrompt: String? { j["resumePrompt"].text }
  var discordChannel: String? { j["discordChannel"].text }
  var createRequestId: String? { j["createRequestId"].text }
  var wakeups: [Wakeup] { j["wakeups"].array.map(Wakeup.init) }
  var crons: [Cron] { j["crons"].array.map(Cron.init) }
  var hasSchedule: Bool { !wakeups.isEmpty || !crons.isEmpty }
  var isTaskLine: Bool { harness.hasPrefix("task:") }
  /// OpenCode and OpenClaw sessions aren't in the Claude app: their primary action is the Remote page
  var hasRemote: Bool { harness == "opencode" || harness == "openclaw" }
  /// what the Claude app calls it (router/discord.go sessionTitle): the app's title, a CLI name, the label, the AI title
  var title: String {
    for k in ["serverTitle", "userTitle", "label", "aiTitle", "title", "name"] { if let t = j[k].text { return t } }
    return id
  }
  /// the stores it was given, without the harness's own and the core's
  func stores(policy: [String: [String]]) -> [String] {
    var all = j["stores"].strings
    if all.isEmpty { all = (j["environment"].string ?? "").split(separator: ",").map(String.init) }
    let h = Set(policy[harness] ?? [])
    return all.filter { !h.contains($0) && $0 != StoreView.coreStore }
  }
  /// a memory-starvation episode the router is watching (absent once it is over)
  var memAlert: MemAlert? { j["memAlert"].object == nil ? nil : MemAlert(j: j["memAlert"]) }
  /// the latest memory sample of a running machine
  var memory: (availMb: Int, totalMb: Int)? {
    guard let a = j["memory"]["availMb"].int, let t = j["memory"]["totalMb"].int, t > 0 else { return nil }
    return (a, t)
  }
  /// the router's last restart / upgrade job (kind, phase, error)
  var wakeKind: String? { j["wake"]["kind"].text }
  var wakePhase: String? { j["wake"]["phase"].text }
  var wakeError: String? { j["wake"]["error"].text }
  /// what the router is doing to it right now (its lifecycle lock, or a mode / restart job), seen on every device
  var serverBusy: String? {
    if let k = j["busy"]["kind"].string { return Fmt.busyLabel[k] ?? "Working…" }
    if let k = j["wake"]["kind"].string, let p = j["wake"]["phase"].string, p != "done", p != "failed" { return Fmt.busyLabel[k] ?? "Working…" }
    return nil
  }
}

/// a memory-starvation episode (router memory watch): why, the memory now, and the size Upgrade moves it to
struct MemAlert: Equatable, Hashable {
  let j: JSON
  var since: Date? { j["since"].string?.isoDate }
  var reason: String { j["reason"].text ?? "memory is short" }
  var detail: String? { j["detail"].text }
  /// the size Upgrade moves to: always one (the memory doubles each step)
  var nextSize: String? { j["nextSize"].text }
  var nextGB: Int? { j["nextGb"].int }
  /// its Fly guest, "8×performance · 32 GB"
  var nextGuest: String? { j["nextGuest"].text }
}

struct Wakeup: Identifiable, Equatable, Hashable {
  let j: JSON
  var id: String { name }
  var name: String { j["name"].string ?? "default" }
  var prompt: String { j["prompt"].string ?? "" }
  var at: Date? { j["at"].double.map { Date(timeIntervalSince1970: $0 / 1000) } ?? j["atIso"].string?.isoDate }
}

struct Cron: Identifiable, Equatable, Hashable {
  let j: JSON
  var id: String { name }
  var name: String { j["name"].string ?? "" }
  var prompt: String { j["prompt"].string ?? "" }
  var everySeconds: Int { j["everySeconds"].int ?? 86400 }
  var tz: String? { j["tz"].text }
  var nextAt: Date? { j["nextAt"].double.map { Date(timeIntervalSince1970: $0 / 1000) } ?? j["nextAtIso"].string?.isoDate }
  var runs: Int { j["runs"].int ?? 0 }
  var until: Date? { j["untilIso"].string?.isoDate }
}

/// an approval the router holds (GET api/state `approvals`); the challenge is checked by Checks.review before anything
struct Approval: Identifiable, Equatable, Hashable {
  let j: JSON
  var id: String { j["id"].string ?? "" }
  var kind: String { j["kind"].string ?? "" }
  var session: String? { j["session"].text }
}

/// an Inbox entry (router/inbox.go): a request waiting for the phone, or one of the router's approvals
struct InboxItem: Identifiable, Equatable, Hashable {
  let j: JSON
  var id: String { j["id"].string ?? "" }
  var kind: String { j["kind"].string ?? "" }
  var isApproval: Bool { j["approval"].bool == true }
  var params: JSON { j["params"] }
  var session: String? { j["session"].text }
  var sessionName: String? { j["sessionName"].text }
  var callerText: String { j["callerText"].string ?? "someone" }
  var explanation: String { j["explanation"].string ?? "" }
  var created: Date? { j["created"].string?.isoDate }
  var expires: Date? { j["expires"].string?.isoDate }
  var openKind: String { j["open"]["kind"].string ?? "" }
  var openOptions: JSON { j["open"]["options"] }
  /// the batch it was filed in (router/batches.go)
  var batch: String? { j["batch"].text }
  /// the call as one line: POST /api/requests/repo/add {"repo":"DE0CH/claude-env"}
  var callLine: String {
    let c = j["call"]
    guard let path = c["path"].text else { return "(no API call recorded)" }
    return SignedAction.call(method: c["method"].string ?? "", path: path, args: c["args"].object.map { $0.mapValues(\.any) })
  }
}

/// several Inbox items a caller filed together (router/batches.go): one Inbox entry, one review page, one Face ID
struct InboxBatch: Identifiable, Equatable, Hashable {
  let j: JSON
  var id: String { j["id"].string ?? "" }
  /// the caller's words about the whole batch, unverified
  var summary: String { j["summary"].string ?? "" }
  var callerText: String { j["callerText"].string ?? "someone" }
  var items: [String] { j["items"].array.compactMap(\.text) }
  /// approvals still being made (a new session's challenge): Allow waits for them
  var preparing: Int { j["preparing"].int ?? 0 }
  var created: Date? { j["created"].string?.isoDate }
  var expires: Date? { j["expires"].string?.isoDate }
  var callLine: String {
    let c = j["call"]
    guard let path = c["path"].text else { return "(no API call recorded)" }
    return SignedAction.call(method: c["method"].string ?? "", path: path, args: c["args"].object.map { $0.mapValues(\.any) })
  }
}

/// a destroyed session on the Previous list (GET api/records)
struct Rec: Identifiable, Equatable, Hashable {
  let j: JSON
  var id: String { j["id"].string ?? "" }
  var session: Session { Session(j: j) }
  var archive: JSON { j["archive"] }
  var hasArchive: Bool { !archive.isNull }
  /// an archive indexed by hand has no machine-signed snapshot: nothing Jarvis 2 can restore
  var restorable: Bool { archive["signer"].text != nil }
  var title: String { archive["title"].text ?? session.title }
  var destroyedAt: Date? { j["destroyedAt"].string?.isoDate }
  var restoredCount: Int { j["restored"].array.count }
  var lastRestored: Date? { j["restored"].array.last?["at"].string?.isoDate }
  var transcripts: Int { archive["transcripts"].array.count }
  var artifacts: Int { archive["artifacts"].int ?? 0 }
  var archiveError: String? { j["archiveError"].text }
  var last: TailMessage? { archive["last"].isNull ? nil : TailMessage(j: archive["last"]) }
}

struct TailMessage: Equatable, Hashable, Identifiable {
  let j: JSON
  var id: String { (j["at"].string ?? "") + role + text.prefix(32) }
  var role: String { j["role"].string ?? "assistant" }
  var text: String { j["text"].string ?? "" }
  var at: Date? { j["at"].string?.isoDate }
}

struct Grant: Identifiable, Equatable, Hashable {
  let j: JSON
  var id: String { j["id"].string ?? "" }
  var holder: String { j["holder"].string ?? "" }
  var isRule: Bool { j["kind"].string == "rule" }
  var ends: Date? { j["ends"].string?.isoDate }
}

struct RepoEntry: Identifiable, Equatable, Hashable {
  let j: JSON
  var id: String { name }
  var name: String { j["name"].string ?? "" }
  var url: String { j["url"].string ?? "" }
  var repo: String { j["repo"].string ?? "" }
  var store: String { j["store"].string ?? "" }
  var sensitive: Bool { j["sensitive"].bool == true }
  var fingerprint: String? { j["fingerprint"].text }
}

struct GitHubRepo: Identifiable, Equatable, Hashable {
  let j: JSON
  var id: String { fullName }
  var fullName: String { j["fullName"].string ?? "" }
  var htmlUrl: String { j["htmlUrl"].string ?? "" }
  var description: String? { j["description"].text }
  var language: String? { j["language"].text }
  var isPrivate: Bool { j["private"].bool == true }
  var isFork: Bool { j["fork"].bool == true }
  var archived: Bool { j["archived"].bool == true }
  var pushedAt: Date? { j["pushedAt"].string?.isoDate }
}

struct Machine: Identifiable, Equatable, Hashable {
  let j: JSON
  var id: String { j["id"].string ?? "" }
  var name: String { j["name"].string ?? "" }
  var state: String { j["state"].string ?? "" }
  var region: String { j["region"].string ?? "" }
  var size: String { j["size"].string ?? "" }
  var guest: String { j["guest"].string ?? "" }
  var image: String { j["image"].string ?? "" }
  var created: Date? { j["created"].string?.isoDate }
  var sessionId: String? { j["sessionId"].text }
  var current: Bool { j["current"].bool == true }
  var routerUrl: String { j["routerUrl"].string ?? "" }
  var test: Bool { j["test"].bool == true }
  var noDestroy: String? { j["noDestroy"].text }
  /// what stands out about it ("" = nothing)
  var attention: String? { j["attention"].text }
  /// a Jarvis 1 session it belongs to (shown, never linked)
  var otherSession: String? { j["otherSession"].text }
}

/// a router list (sizes, models): id + label, a model also its harness
struct Choice: Identifiable, Equatable, Hashable {
  let id: String
  let label: String?
  let harness: String?
  init(j: JSON) { id = j["id"].string ?? ""; label = j["label"].text; harness = j["harness"].text }
}

// ---- tasks (docs/API.md "Tasks") ----
struct TaskField: Identifiable, Equatable, Hashable {
  let j: JSON
  var id: String { name }
  var name: String { j["name"].string ?? "" }
  var label: String { j["label"].text ?? name }
  var type: String { j["type"].string ?? "text" }
  var required: Bool { j["required"].bool == true }
  var optionsFrom: String? { j["optionsFrom"].text }
  var help: String? { j["help"].text }
  var placeholder: String? { j["placeholder"].text }
  var defaultValue: JSON { j["default"] }
  /// the template's own options (a string or {value, label, sub})
  var options: [TaskOption] {
    j["options"].array.map { o in
      if let s = o.string { return TaskOption(value: s, label: s, sub: nil) }
      return TaskOption(value: o["value"].string ?? "", label: o["label"].text ?? o["value"].string ?? "", sub: o["sub"].text)
    }
  }
}
struct TaskOption: Identifiable, Equatable, Hashable { let value: String; let label: String; let sub: String?; var id: String { value } }

struct TaskTemplate: Identifiable, Equatable, Hashable {
  let j: JSON
  var id: String { name }
  var name: String { j["name"].string ?? "" }
  var title: String { j["title"].text ?? name }
  var description: String? { j["description"].text }
  var stores: [String] { j["stores"].strings }
  var hasPrompt: Bool { j["prompt"].text != nil }
  var fields: [TaskField] { j["fields"].array.map(TaskField.init) }
  var error: String? { j["error"].text }
}

struct TaskRun: Identifiable, Equatable, Hashable {
  let j: JSON
  var id: String { name }
  var name: String { j["name"].string ?? "" }
  var runId: String { j["id"].string ?? "" }
  var phase: String { j["phase"].string ?? "" }
  var active: Bool { ["queued", "starting", "running"].contains(phase) }
  var scheduled: Bool { j["trigger"].string == "schedule" }
  var upgrade: Bool { j["upgrade"].bool == true }
  var createdAt: Date? { j["createdAt"].string?.isoDate }
  var ranAt: Date? { j["ranAt"].string?.isoDate }
  var finishedAt: Date? { j["finishedAt"].string?.isoDate }
  var exitCode: Int? { j["exitCode"].int }
  var reason: String? { j["reason"].text }
  var waiting: String? { j["waiting"].text }
  /// the latest step and when: ("Finished", "5 min ago")
  var when: (label: String, value: String)? {
    if let d = finishedAt { return ("Finished", Fmt.ago(d)) }
    if let d = ranAt { return ("Started", Fmt.ago(d)) }
    if let d = createdAt { return ("Queued", Fmt.ago(d)) }
    return nil
  }
}

struct TaskInstance: Identifiable, Equatable, Hashable {
  let j: JSON
  var id: String { j["id"].string ?? "" }
  var template: String { j["template"].string ?? "" }
  var name: String { j["name"].string ?? "" }
  var params: JSON { j["params"] }
  var size: String? { j["size"].text }
  var stores: [String] { j["stores"].strings }
  var session: String? { j["session"].text }
  var createdAt: Date? { j["createdAt"].string?.isoDate }
  var state: String { j["state"].string ?? "" }
  var detail: String? { j["detail"].text }
  var lastRun: TaskRun? { j["lastRun"].isNull ? nil : TaskRun(j: j["lastRun"]) }
  var activeRun: TaskRun? { j["activeRun"].isNull ? nil : TaskRun(j: j["activeRun"]) }
  var queued: Int { j["queued"].int ?? 0 }
  var schedules: Int { j["schedules"].int ?? 0 }
  /// the values as one line ("Message: hi · Count: 2")
  /// the task's parameters as (label, value) rows, in the template's field order
  func summary(_ t: TaskTemplate?) -> [(label: String, value: String)] {
    let fields: [(String, String, String)] = t.map { $0.fields.map { ($0.name, $0.label, $0.type) } }
      ?? (params.object ?? [:]).keys.sorted().map { ($0, $0, "text") }
    return fields.compactMap { name, label, type in
      let v = params[name]
      if v.isNull || v.string == "" || (v.object == nil && v.string == nil && v.array.isEmpty) { return nil }
      let s = type == "checkbox" ? (v.bool == true ? "yes" : "no") : (v.string ?? v.strings.joined(separator: ", "))
      return (label, s)
    }
  }
}

struct TaskSchedule: Identifiable, Equatable, Hashable {
  let j: JSON
  var id: String { j["id"].string ?? "" }
  var instance: String { j["instance"].string ?? "" }
  var time: String { j["time"].string ?? "09:00" }
  var tz: String { j["tz"].string ?? "UTC" }
  var enabled: Bool { j["enabled"].bool == true }
  var nextAt: Date? { j["nextAt"].double.map { Date(timeIntervalSince1970: $0 / 1000) } }
  var text: String { "Daily at \(time) · \(tz.replacing("_", with: " "))" }
}

struct TasksOverview: Equatable {
  var templates: [TaskTemplate] = []
  var instances: [TaskInstance] = []
  var schedules: [TaskSchedule] = []
  init() {}
  init(j: JSON) {
    templates = j["templates"].array.map(TaskTemplate.init)
    instances = j["instances"].array.map(TaskInstance.init)
    schedules = j["schedules"].array.map(TaskSchedule.init)
  }
}

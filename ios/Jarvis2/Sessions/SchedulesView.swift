// A session's wakeups and crons (router/schedule.go): at the due time the router delivers the prompt into the session
// as a message, resuming it first when it is paused. Delivery runs as the `scheduler` feature, so the session must
// allow it (arming from inside the session does that by itself) or the phone must (a standing rule).
import SwiftUI

struct SchedulesView: View {
  @Environment(AppModel.self) private var model
  let sessionId: String
  @State private var wakeups: [Wakeup]?
  @State private var crons: [Cron]?
  @State private var error: String?
  @State private var kind = "wakeup"
  @State private var prompt = ""
  @State private var name = ""
  @State private var minutes = 60
  @State private var every = "daily"
  @State private var time = Calendar.current.date(from: DateComponents(hour: 9, minute: 0)) ?? .now
  @State private var hours = 6.0
  @State private var busy = false
  @State private var formError: String?

  private var title: String { model.session(sessionId)?.title ?? sessionId }

  var body: some View {
    Form {
      Section {
        Text("At the time, the prompt arrives in the session as a message; a paused session is resumed first. The session has to allow the scheduler (it does when it arms one itself), or the phone does with a standing rule.")
          .font(.subheadline).foregroundStyle(.secondary)
        Button("Standing rule for the scheduler…", systemImage: "calendar.badge.clock") { model.requestGrant(sessionId, title, holder: "scheduler", rule: true) }
          .accessibilityIdentifier("sch-rule")
      }
      Section("Armed") {
        if let error { ErrorRow(text: error) }
        else if let wakeups, let crons {
          if wakeups.isEmpty && crons.isEmpty { Text("Nothing armed.").foregroundStyle(.secondary).accessibilityIdentifier("sch-none") }
          ForEach(wakeups) { w in
            HStack {
              VStack(alignment: .leading) {
                Text("Wakes\(w.name == "default" ? "" : " “\(w.name)”") \(w.at.map(Fmt.when) ?? "")").font(.headline)
                Text("“\(w.prompt)”").font(.subheadline).foregroundStyle(.secondary)
              }
              Spacer()
              PendingButton(key: "sch:wakeup:" + w.name, title: "Cancel", role: .destructive) { await cancel("wakeup", w.name) }
                .buttonStyle(.borderless).accessibilityIdentifier("sch-cancel-w-\(w.name)")
            }
          }
          ForEach(crons) { c in
            HStack {
              VStack(alignment: .leading) {
                Text("“\(c.name)” \(Fmt.every(c.everySeconds))").font(.headline)
                Text("next \(c.nextAt.map(Fmt.when) ?? "")\(c.tz.map { $0 == "UTC" ? "" : " · \($0)" } ?? "")\(c.runs > 0 ? " · \(Fmt.plural(c.runs, "run"))" : "")")
                  .font(.footnote).foregroundStyle(.secondary)
                Text("“\(c.prompt)”").font(.subheadline).foregroundStyle(.secondary)
              }
              Spacer()
              PendingButton(key: "sch:cron:" + c.name, title: "Cancel", role: .destructive) { await cancel("cron", c.name) }
                .buttonStyle(.borderless).accessibilityIdentifier("sch-cancel-c-\(c.name)")
            }
          }
        } else { ProgressView() }
      }
      Section {
        Picker("Kind", selection: $kind) { Text("Once").tag("wakeup"); Text("Repeating").tag("cron") }
          .pickerStyle(.segmented).accessibilityIdentifier("sch-kind")
        TextField("What the session gets at that time, as a message", text: $prompt, axis: .vertical)
          .lineLimit(3...8).accessibilityIdentifier("sch-prompt")
        if kind == "wakeup" {
          Picker("In", selection: $minutes) {
            Text("15 min").tag(15); Text("1 hour").tag(60); Text("4 hours").tag(240); Text("1 day").tag(1440)
          }
          .accessibilityIdentifier("sch-in")
        } else {
          Picker("Repeat", selection: $every) { Text("Daily").tag("daily"); Text("Every N hours").tag("hours") }
            .accessibilityIdentifier("sch-every")
          if every == "daily" {
            DatePicker("At (\(TimeZone.current.identifier))", selection: $time, displayedComponents: .hourAndMinute).accessibilityIdentifier("sch-time")
          } else {
            Stepper("Every \(hours.formatted()) h", value: $hours, in: 0.25...168, step: hours < 1 ? 0.25 : 1).accessibilityIdentifier("sch-hours")
          }
        }
        TextField(kind == "wakeup" ? "Name (default)" : "Name (daily)", text: $name)
          .textInputAutocapitalization(.never).autocorrectionDisabled().accessibilityIdentifier("sch-name")
        if let formError { ErrorRow(text: formError, id: "sch-err") }
      } header: { Text("New") } footer: { Text("Arming the same name again replaces it.") }
    }
    .navigationTitle("Schedules")
    .navigationBarTitleDisplayMode(.inline)
    .toolbar {
      ToolbarItem(placement: .confirmationAction) {
        Button(busy ? "Saving…" : "Arm", action: { Task { await add() } }).disabled(busy).accessibilityIdentifier("sch-save")
      }
    }
    .task { await load() }
  }

  private func load() async {
    do {
      async let w = RouterClient.shared.get("api/sessions/\(sessionId)/wakeups")
      async let c = RouterClient.shared.get("api/sessions/\(sessionId)/crons")
      wakeups = try await w["wakeups"].array.map(Wakeup.init)
      crons = try await c["crons"].array.map(Cron.init)
      error = nil
    } catch { self.error = errText(error) }
  }

  private func add() async {
    formError = nil
    let p = prompt.trimmingCharacters(in: .whitespacesAndNewlines)
    guard !p.isEmpty else { formError = "Write the prompt the session gets."; return }
    let nm = name.trimmingCharacters(in: .whitespaces)
    var body: [String: Any] = ["prompt": p]
    if kind == "wakeup" {
      body["delaySeconds"] = minutes * 60
      if !nm.isEmpty { body["name"] = nm }
    } else if every == "daily" {
      let c = Calendar.current.dateComponents([.hour, .minute], from: time)
      body["time"] = String(format: "%02d:%02d", c.hour ?? 9, c.minute ?? 0)
      body["tz"] = TimeZone.current.identifier
      body["name"] = nm.isEmpty ? "daily" : nm
    } else {
      body["everySeconds"] = Int(hours * 3600)
      body["name"] = nm.isEmpty ? "every" : nm
    }
    busy = true
    defer { busy = false }
    do {
      try await RouterClient.shared.call("POST", "api/sessions/\(sessionId)/\(kind == "wakeup" ? "wakeups" : "crons")", body)
      prompt = ""; name = ""
      await load()
      await model.refresh()
      model.say(kind == "wakeup" ? "Wakeup armed." : "Cron armed.")
    } catch { formError = errText(error) }
  }

  private func cancel(_ what: String, _ n: String) async {
    await model.exclusive("sch:\(what):\(n)") {
      guard await model.confirm("Cancel the \(what)\(n == "default" ? "" : " “\(n)”")?", action: "Cancel \(what)", destructive: true) else { return }
      model.pend("sch:\(what):\(n)", "Cancelling…")
      defer { model.pend("sch:\(what):\(n)", nil) }
      let enc = n.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? n
      do {
        try await RouterClient.shared.call("DELETE", "api/sessions/\(sessionId)/\(what == "wakeup" ? "wakeups" : "crons")/\(enc)")
        await load(); await model.refresh()
      } catch { model.fail(error) }
    }
  }
}

// vdm menu bar icon: shows whether vdm runs, and each account's limits.
// Built on the user's Mac by `vdm menubar on` (swiftc from the Command Line Tools):
//   swiftc -O -swift-version 5 -o VdmMenu VdmMenu.swift
// It only reads http://localhost:<port>/api/profiles. `VdmMenu --dump` prints the menu and exits.

import AppKit

let port = ProcessInfo.processInfo.environment["CSW_PORT"] ?? "3333"
let launchLabel = ProcessInfo.processInfo.environment["VDM_LAUNCH_LABEL"] ?? "io.github.loekj.vdm"
let dashboardURL = URL(string: "http://localhost:\(port)")!

// MARK: - Data from /api/profiles (only the fields used here)

struct Window: Decodable { let utilization: Double?; let reset: Double? }
struct RateLimits: Decodable { let fiveH: Window?; let sevenD: Window?; let sevenDOI: Window?; let fableBlockedUntil: Double? }
struct Blocked: Decodable { let until: Double; let what: String }
struct RefreshFailed: Decodable { let retriable: Bool? }
struct Profile: Decodable {
  let name: String
  let label: String?
  let isActive: Bool?
  let expired: Bool?
  let expiresAt: Double?
  let refreshFailed: RefreshFailed?
  let rateLimits: RateLimits?
  let blocked: Blocked?
  let dormant: Bool?
}
struct UsedUp: Decodable { let fable: Bool?; let until: String? }
struct Status: Decodable { let profiles: [Profile]; let usedUp: UsedUp? }

enum State { case unknown, down, up(Status) }

// MARK: - Text

func timeLeft(_ until: Double) -> String {
  let s = Int(until - Date().timeIntervalSince1970)
  if s <= 0 { return "a moment" }
  let d = s / 86400, h = (s % 86400) / 3600, m = (s % 3600) / 60
  if d > 0 { return "\(d)d \(h)h" }
  if h > 0 { return "\(h)h \(m)m" }
  return "\(max(m, 1))m"
}

/// One window as "week 42%", or "week fresh" once its reset time has passed.
func windowText(_ name: String, _ w: Window?) -> String? {
  guard let w = w, let u = w.utilization else { return nil }
  if let r = w.reset, r > 0, r <= Date().timeIntervalSince1970 { return "\(name) fresh" }
  if (w.reset ?? 0) == 0 && u == 0 { return nil }  // not started: nothing to show
  return "\(name) \(Int((u * 100).rounded()))%"
}

func accountLine(_ p: Profile) -> String {
  let name = p.label ?? p.name
  let now = Date().timeIntervalSince1970 * 1000
  let loginDead = (p.isActive != true) && (p.expired == true || (p.refreshFailed != nil && p.refreshFailed?.retriable == false) || ((p.expiresAt ?? .infinity) < now))
  var detail: String
  if let b = p.blocked {
    detail = "used up · back in \(timeLeft(b.until))"
  } else if loginDead {
    detail = "login expired"
  } else if let rl = p.rateLimits {
    var parts = [windowText("5h", rl.fiveH), windowText("week", rl.sevenD)].compactMap { $0 }
    if let until = rl.fableBlockedUntil, until > Date().timeIntervalSince1970 { parts.append("Fable used up") }
    else if let f = windowText("Fable", rl.sevenDOI) { parts.append(f) }
    detail = parts.isEmpty ? "not started" : parts.joined(separator: " · ")
  } else {
    detail = p.dormant == true ? "not started" : "limits not known yet"
  }
  return "\(name)  —  \(detail)"
}

func menuLines(_ state: State) -> [String] {
  switch state {
  case .unknown: return ["Checking vdm…"]
  case .down: return ["vdm is not running"]
  case .up(let st):
    var lines = ["vdm is running"]
    if let u = st.usedUp { lines.append((u.fable == true ? "Fable is used up on every account until " : "Every account is used up until ") + (u.until ?? "?")) }
    lines += st.profiles.map { ($0.isActive == true ? "✓ " : "   ") + accountLine($0) }
    return lines
  }
}

// MARK: - Fetch

func fetchStatus(_ done: @escaping (State) -> Void) {
  var req = URLRequest(url: dashboardURL.appendingPathComponent("api/profiles"))
  req.timeoutInterval = 8
  URLSession.shared.dataTask(with: req) { data, resp, _ in
    let ok = (resp as? HTTPURLResponse)?.statusCode == 200
    let st = ok ? data.flatMap { try? JSONDecoder().decode(Status.self, from: $0) } : nil
    DispatchQueue.main.async { done(st.map { .up($0) } ?? .down) }
  }.resume()
}

// MARK: - App

final class AppDelegate: NSObject, NSApplicationDelegate, NSMenuDelegate {
  let item = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
  let menu = NSMenu()
  var state: State = .unknown
  var timer: Timer?

  func applicationDidFinishLaunching(_ n: Notification) {
    menu.delegate = self
    menu.autoenablesItems = false
    item.menu = menu
    updateIcon()
    refresh()
    timer = Timer.scheduledTimer(withTimeInterval: 20, repeats: true) { [weak self] _ in self?.refresh() }
  }

  func refresh() {
    fetchStatus { [weak self] st in
      self?.state = st
      self?.updateIcon()
    }
  }

  func updateIcon() {
    guard let button = item.button else { return }
    let name: String
    var tip = "vdm"
    switch state {
    case .down: name = "exclamationmark.triangle"; tip = "vdm is not running"
    case .up(let st) where st.usedUp != nil: name = "hourglass"; tip = "vdm: accounts used up"
    default: name = "figure.martial.arts"
    }
    let img = NSImage(systemSymbolName: name, accessibilityDescription: tip)
      ?? NSImage(systemSymbolName: "bolt.fill", accessibilityDescription: tip)
    img?.isTemplate = true
    button.image = img
    button.toolTip = tip
    button.appearsDisabled = { if case .down = state { return true }; return false }()
  }

  // Rebuild the menu each time it opens, and ask for fresh numbers.
  func menuNeedsUpdate(_ menu: NSMenu) {
    menu.removeAllItems()
    for (i, line) in menuLines(state).enumerated() {
      let mi = NSMenuItem(title: line, action: i == 0 ? nil : #selector(openDashboard), keyEquivalent: "")
      mi.target = self
      mi.isEnabled = i != 0
      if i == 0 { mi.attributedTitle = NSAttributedString(string: line, attributes: [.font: NSFont.boldSystemFont(ofSize: 13)]) }
      menu.addItem(mi)
    }
    menu.addItem(.separator())
    add("Open dashboard", #selector(openDashboard), "d")
    if case .down = state { add("Start vdm", #selector(restartDaemon), "") } else { add("Restart vdm", #selector(restartDaemon), "") }
    menu.addItem(.separator())
    add("Hide this icon", #selector(quit), "q")
    refresh()
  }

  func add(_ title: String, _ action: Selector, _ key: String) {
    let mi = NSMenuItem(title: title, action: action, keyEquivalent: key)
    mi.target = self
    menu.addItem(mi)
  }

  @objc func openDashboard() { NSWorkspace.shared.open(dashboardURL) }

  @objc func restartDaemon() {
    let p = Process()
    p.executableURL = URL(fileURLWithPath: "/bin/launchctl")
    p.arguments = ["kickstart", "-k", "gui/\(getuid())/\(launchLabel)"]
    do { try p.run(); p.waitUntilExit() } catch {}
    if p.terminationStatus != 0 {
      let a = NSAlert()
      a.messageText = "Could not start vdm"
      a.informativeText = "The vdm daemon is not installed. In a terminal, run: vdm daemon on"
      a.runModal()
    }
    DispatchQueue.main.asyncAfter(deadline: .now() + 2) { [weak self] in self?.refresh() }
  }

  @objc func quit() { NSApp.terminate(nil) }
}

if CommandLine.arguments.contains("--dump") {
  // Test mode: print the menu text and exit
  let sem = DispatchSemaphore(value: 0)
  var result: State = .unknown
  var req = URLRequest(url: dashboardURL.appendingPathComponent("api/profiles"))
  req.timeoutInterval = 8
  URLSession.shared.dataTask(with: req) { data, resp, _ in
    let ok = (resp as? HTTPURLResponse)?.statusCode == 200
    result = (ok ? data.flatMap { try? JSONDecoder().decode(Status.self, from: $0) } : nil).map { .up($0) } ?? .down
    sem.signal()
  }.resume()
  sem.wait()
  menuLines(result).forEach { print($0) }
  exit(0)
}

let app = NSApplication.shared
let delegate = AppDelegate()
app.delegate = delegate
app.setActivationPolicy(.accessory)
app.run()

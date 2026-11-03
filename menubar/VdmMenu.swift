// vdm menu bar icon: shows whether vdm runs, and each account's limits.
// Built on the user's Mac by `vdm menubar on` (swiftc from the Command Line Tools):
//   swiftc -O -swift-version 5 -o VdmMenu VdmMenu.swift
// It only reads http://localhost:<port>/api/profiles?light=1 (what vdm knows already: no
// rate-limit checks, no email lookups). `VdmMenu --dump` prints the menu and exits.

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

// upUnreadable: vdm answers, but this app could not read the answer (newer vdm?)
enum State { case unknown, down, upUnreadable, up(Status) }

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
  case .upUnreadable: return ["vdm is running", "Accounts: see the dashboard"]
  case .up(let st):
    var lines = ["vdm is running"]
    if let u = st.usedUp { lines.append((u.fable == true ? "Fable is used up on every account until " : "Every account is used up until ") + (u.until ?? "?")) }
    lines += st.profiles.map { ($0.isActive == true ? "✓ " : "   ") + accountLine($0) }
    return lines
  }
}

// MARK: - Fetch

let profilesURL = URL(string: "http://localhost:\(port)/api/profiles?light=1")!

/// nil = no answer in time (vdm busy): keep showing what we had
func readStatus(_ data: Data?, _ resp: URLResponse?, _ err: Error?) -> State? {
  if let e = err as? URLError, e.code == .timedOut { return nil }
  guard let http = resp as? HTTPURLResponse else { return .down }
  guard http.statusCode == 200 else { return .upUnreadable }
  guard let d = data, let st = try? JSONDecoder().decode(Status.self, from: d) else { return .upUnreadable }
  return .up(st)
}

func fetchStatus(_ done: @escaping (State?) -> Void) {
  var req = URLRequest(url: profilesURL)
  req.timeoutInterval = 10
  URLSession.shared.dataTask(with: req) { data, resp, err in
    let st = readStatus(data, resp, err)
    DispatchQueue.main.async { done(st) }
  }.resume()
}

// MARK: - Icon: a figure doing a near-vertical high kick (Van Damme-o-Matic), drawn in code

enum IconBadge { case none, dot, off }

/// 18×18 pt template image (macOS colors it for light/dark menu bars).
/// .dot = every account used up; .off = vdm is not running (struck through).
func vdmIcon(_ badge: IconBadge) -> NSImage {
  let img = NSImage(size: NSSize(width: 18, height: 18), flipped: false) { _ in
    NSColor.black.set()
    let stroke = { (pts: [(CGFloat, CGFloat)], w: CGFloat) in
      let p = NSBezierPath()
      p.lineWidth = w; p.lineCapStyle = .round; p.lineJoinStyle = .round
      p.move(to: NSPoint(x: pts[0].0, y: pts[0].1))
      for q in pts.dropFirst() { p.line(to: NSPoint(x: q.0, y: q.1)) }
      p.stroke()
    }
    // Standing leg, then the kicking leg almost straight up, foot flexed.
    // Both legs about the same length, like a real body.
    stroke([(9.6, 0.9), (11.0, 7.6)], 1.7)
    stroke([(11.0, 7.6), (12.6, 14.8), (14.3, 15.6)], 1.7)
    // Body leaning back, away from the kick
    stroke([(11.0, 7.6), (6.6, 10.6)], 1.9)
    // Arms: a guard up front, the other arm back for balance
    stroke([(7.0, 10.3), (9.0, 11.0), (9.1, 13.2)], 1.4)
    stroke([(7.0, 10.3), (3.8, 7.8)], 1.4)
    // Head, a small gap above the shoulders
    NSBezierPath(ovalIn: NSRect(x: 2.65, y: 10.45, width: 3.5, height: 3.5)).fill()
    switch badge {
    case .dot:
      // Bottom right: the only corner the kick leaves free
      NSGraphicsContext.current?.compositingOperation = .clear
      NSBezierPath(ovalIn: NSRect(x: 11.8, y: -0.2, width: 6.4, height: 6.4)).fill()
      NSGraphicsContext.current?.compositingOperation = .sourceOver
      NSBezierPath(ovalIn: NSRect(x: 12.9, y: 0.9, width: 4.2, height: 4.2)).fill()
    case .off:
      NSGraphicsContext.current?.compositingOperation = .clear
      stroke([(2, 16.5), (16.5, 1.5)], 3.6)
      NSGraphicsContext.current?.compositingOperation = .sourceOver
      stroke([(2, 16.5), (16.5, 1.5)], 1.4)
    case .none: break
    }
    return true
  }
  img.isTemplate = true
  return img
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
      guard let self = self else { return }
      if let st = st { self.state = st } else if case .unknown = self.state { self.state = .upUnreadable }
      self.updateIcon()
    }
  }

  func updateIcon() {
    guard let button = item.button else { return }
    var badge = IconBadge.none
    var tip = "vdm is running"
    switch state {
    case .down: badge = .off; tip = "vdm is not running"
    case .up(let st) where st.usedUp != nil: badge = .dot; tip = "vdm: every account is used up for now"
    default: break
    }
    button.image = vdmIcon(badge)
    button.toolTip = tip
    button.setAccessibilityLabel(tip)
    button.appearsDisabled = badge == .off
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
    if case .down = state {} else { add("Quit vdm…", #selector(quitVdm), "q") }
    add("Hide icon", #selector(quit), "")
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

  // Stops vdm itself (a clean exit: launchd starts it again at the next login, or with
  // `vdm dashboard start`), then this icon.
  @objc func quitVdm() {
    let a = NSAlert()
    a.messageText = "Quit vdm?"
    a.informativeText = "This stops vdm and this icon. Claude Code sessions that use vdm cannot reach Anthropic until vdm runs again.\n\nBoth start again at your next login. To start vdm now, run: vdm dashboard start"
    a.addButton(withTitle: "Quit vdm")
    a.addButton(withTitle: "Cancel")
    NSApp.activate(ignoringOtherApps: true)
    guard a.runModal() == .alertFirstButtonReturn else { return }
    var req = URLRequest(url: dashboardURL.appendingPathComponent("api/shutdown"))
    req.httpMethod = "POST"
    req.setValue("application/json", forHTTPHeaderField: "Content-Type")
    req.httpBody = "{}".data(using: .utf8)
    req.timeoutInterval = 5
    URLSession.shared.dataTask(with: req) { _, resp, _ in
      let ok = (resp as? HTTPURLResponse)?.statusCode == 200
      DispatchQueue.main.async {
        if ok { NSApp.terminate(nil); return }
        let e = NSAlert()
        e.messageText = "Could not quit vdm"
        e.informativeText = "In a terminal, run: vdm dashboard stop"
        e.runModal()
      }
    }.resume()
  }
}

if let i = CommandLine.arguments.firstIndex(of: "--render-icons"), i + 1 < CommandLine.arguments.count {
  // Test mode: draw the three icons, 8x, black on white and white on dark, into one PNG
  let out = CommandLine.arguments[i + 1]
  let scale: CGFloat = 8, cell: CGFloat = 18 * scale + 24
  let rep = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: Int(cell * 3), pixelsHigh: Int(cell * 2), bitsPerSample: 8,
                             samplesPerPixel: 4, hasAlpha: true, isPlanar: false, colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0)!
  NSGraphicsContext.saveGraphicsState()
  NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: rep)
  for (row, (bg, fg)) in [(NSColor.white, NSColor.black), (NSColor(white: 0.15, alpha: 1), NSColor.white)].enumerated() {
    for (col, b) in [IconBadge.none, .dot, .off].enumerated() {
      let r = NSRect(x: CGFloat(col) * cell, y: CGFloat(1 - row) * cell, width: cell, height: cell)
      bg.setFill(); r.fill()
      let tinted = NSImage(size: NSSize(width: 18 * scale, height: 18 * scale), flipped: false) { rr in
        vdmIcon(b).draw(in: rr); fg.set(); rr.fill(using: .sourceIn); return true
      }
      tinted.draw(in: r.insetBy(dx: 12, dy: 12))
    }
  }
  NSGraphicsContext.restoreGraphicsState()
  try? rep.representation(using: .png, properties: [:])?.write(to: URL(fileURLWithPath: out))
  exit(0)
}

if CommandLine.arguments.contains("--dump") {
  // Test mode: print the menu text and exit
  let sem = DispatchSemaphore(value: 0)
  var result: State = .unknown
  fetchStatus { st in result = st ?? .upUnreadable; sem.signal() }
  while sem.wait(timeout: .now()) == .timedOut { RunLoop.main.run(until: Date().addingTimeInterval(0.05)) }
  menuLines(result).forEach { print($0) }
  exit(0)
}

let app = NSApplication.shared
let delegate = AppDelegate()
app.delegate = delegate
app.setActivationPolicy(.accessory)
app.run()

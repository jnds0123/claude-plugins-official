// Nourison Home Mac Defender — menu bar status app.
//
// A lightweight AppKit menu-bar (status bar) app that shows a colored health
// light and opens a native window with the latest report and scan history.
//
// It does NOT do the scanning itself — the shell engine at
//   /Library/Application Support/MacSecurityCheck/mac-security-check
// is the scanner. That engine writes a small status.json and a latest report
// into the user's Application Support folder; this app just reads them,
// colors the menu-bar icon, and displays reports in a WKWebView window.
//
// Build: see build-app.sh (compiles with swiftc, bundles a .app, signs it).

import Cocoa
import WebKit

// ---- Paths -----------------------------------------------------------------
let kSupport = ("~/Library/Application Support/MacSecurityCheck" as NSString).expandingTildeInPath
let kStatusFile = kSupport + "/status.json"
let kLatestReport = kSupport + "/latest-report.html"
let kArchive = kSupport + "/reports"
let kEngine = "/Library/Application Support/MacSecurityCheck/mac-security-check"

// ---- Status model ----------------------------------------------------------
struct Status {
    var overall = "unknown"
    var attention = 0
    var review = 0
    var ok = 0
    var timestamp = "never"
    var report = ""
}

func loadStatus() -> Status {
    var s = Status()
    guard let data = FileManager.default.contents(atPath: kStatusFile),
          let obj = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
    else { return s }
    s.overall = obj["overall"] as? String ?? "unknown"
    s.attention = (obj["attention"] as? NSNumber)?.intValue ?? 0
    s.review = (obj["review"] as? NSNumber)?.intValue ?? 0
    s.ok = (obj["ok"] as? NSNumber)?.intValue ?? 0
    s.timestamp = obj["timestamp"] as? String ?? "never"
    s.report = obj["report"] as? String ?? kLatestReport
    return s
}

func tint(for overall: String) -> NSColor {
    switch overall {
    case "clean":     return .systemGreen
    case "review":    return .systemOrange
    case "attention": return .systemRed
    default:          return .systemGray
    }
}

func headline(for s: Status) -> String {
    switch s.overall {
    case "clean":     return "All clear"
    case "review":    return "\(s.review) item(s) to review"
    case "attention": return "\(s.attention) item(s) need attention"
    default:          return "Not scanned yet"
    }
}

// ---- Report window (native WKWebView) --------------------------------------
final class ReportWindowController: NSWindowController {
    private let web = WKWebView(frame: .zero)

    convenience init() {
        let win = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 900, height: 680),
            styleMask: [.titled, .closable, .resizable, .miniaturizable],
            backing: .buffered, defer: false)
        win.title = "Nourison Home Mac Defender"
        win.center()
        self.init(window: win)
        win.contentView = web
    }

    func show(path: String) {
        if let w = window {
            w.makeKeyAndOrderFront(nil)
            NSApp.activate(ignoringOtherApps: true)
        }
        let url = URL(fileURLWithPath: path)
        if FileManager.default.fileExists(atPath: path) {
            web.loadFileURL(url, allowingReadAccessTo: url.deletingLastPathComponent())
        } else {
            web.loadHTMLString("<h2 style='font-family:sans-serif;padding:40px'>No report yet.</h2><p style='font-family:sans-serif;padding:0 40px'>Choose “Run Scan Now” to generate one.</p>", baseURL: nil)
        }
    }
}

// ---- App delegate ----------------------------------------------------------
final class AppDelegate: NSObject, NSApplicationDelegate {
    let statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
    let reportWindow = ReportWindowController()
    var timer: Timer?

    func applicationDidFinishLaunching(_ note: Notification) {
        refresh()
        // Poll the status file so the light updates after scheduled scans.
        timer = Timer.scheduledTimer(withTimeInterval: 30, repeats: true) { [weak self] _ in
            self?.refresh()
        }
    }

    func refresh() {
        let s = loadStatus()
        if let button = statusItem.button {
            let img = NSImage(systemSymbolName: "shield.lefthalf.filled",
                              accessibilityDescription: "Mac Defender status")
            img?.isTemplate = true
            button.image = img
            button.contentTintColor = tint(for: s.overall)
            button.toolTip = "Mac Defender — \(headline(for: s))"
        }
        statusItem.menu = buildMenu(s)
    }

    func buildMenu(_ s: Status) -> NSMenu {
        let menu = NSMenu()

        let dot: String
        switch s.overall {
        case "clean": dot = "🟢"; case "review": dot = "🟠"
        case "attention": dot = "🔴"; default: dot = "⚪️"
        }
        let header = NSMenuItem(title: "\(dot)  \(headline(for: s))", action: nil, keyEquivalent: "")
        header.isEnabled = false
        menu.addItem(header)

        let when = NSMenuItem(title: "Last checked: \(s.timestamp)", action: nil, keyEquivalent: "")
        when.isEnabled = false
        menu.addItem(when)

        menu.addItem(.separator())
        menu.addItem(NSMenuItem(title: "Run Scan Now", action: #selector(runScan), keyEquivalent: "r"))
        menu.addItem(NSMenuItem(title: "Open Latest Report", action: #selector(openLatest), keyEquivalent: "o"))

        // History submenu — recent archived reports.
        let hist = NSMenuItem(title: "History", action: nil, keyEquivalent: "")
        let sub = NSMenu()
        for (title, path) in recentReports() {
            let it = NSMenuItem(title: title, action: #selector(openHistory(_:)), keyEquivalent: "")
            it.representedObject = path
            it.target = self
            sub.addItem(it)
        }
        if sub.items.isEmpty {
            let none = NSMenuItem(title: "(no past scans)", action: nil, keyEquivalent: "")
            none.isEnabled = false
            sub.addItem(none)
        }
        hist.submenu = sub
        menu.addItem(hist)

        menu.addItem(.separator())
        menu.addItem(NSMenuItem(title: "Quit", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q"))

        for item in menu.items where item.target == nil && item.action != nil { item.target = self }
        return menu
    }

    func recentReports() -> [(String, String)] {
        let fm = FileManager.default
        guard let files = try? fm.contentsOfDirectory(atPath: kArchive) else { return [] }
        let reports = files.filter { $0.hasPrefix("Mac-Security-Report-") && $0.hasSuffix(".html") }
            .sorted(by: >)
            .prefix(10)
        return reports.map { name in
            let stamp = name
                .replacingOccurrences(of: "Mac-Security-Report-", with: "")
                .replacingOccurrences(of: ".html", with: "")
            return (stamp, kArchive + "/" + name)
        }
    }

    @objc func runScan() {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/bin/bash")
        p.arguments = [kEngine, "--quiet"]
        p.terminationHandler = { [weak self] _ in
            DispatchQueue.main.async {
                self?.refresh()
                self?.openLatest()
            }
        }
        try? p.run()
    }

    @objc func openLatest() {
        reportWindow.show(path: loadStatus().report)
    }

    @objc func openHistory(_ sender: NSMenuItem) {
        if let path = sender.representedObject as? String { reportWindow.show(path: path) }
    }
}

// ---- Entry point -----------------------------------------------------------
let app = NSApplication.shared
let delegate = AppDelegate()
app.delegate = delegate
app.setActivationPolicy(.accessory)   // menu-bar only, no Dock icon
app.run()

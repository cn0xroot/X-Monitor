// XmonES — EXPERIMENTAL Endpoint Security AUTH client for X-Monitor.
//
// Status: type-checked only. It cannot run until Apple grants the
// `com.apple.developer.endpoint-security.client` entitlement, the binary is
// signed and notarized, and the user grants Full Disk Access (see README.md in
// this directory). It has never been executed.
//
// What it does: subscribes to AUTH events and denies, *only for processes that
// descend from a root pid listed in ~/.xmon/tracked-roots.json* (written by
// xmond), the actions forbidden by ~/.xmon/enforce-policy.json:
//   - AUTH_EXEC   of a denied executable
//   - AUTH_OPEN   for writing a deny_write path / reading a deny_read path
//   - AUTH_UNLINK of a deny_write path
//   - AUTH_RENAME whose source is a deny_write path (destination not checked yet)
// ES events are system-wide; the ancestry check is what keeps this from
// affecting the user's own processes.
import Darwin
import EndpointSecurity
import Foundation

struct Policy: Decodable {
    var deny_write: [String] = []
    var deny_read: [String] = []
    var deny_exec: [String] = []

    enum CodingKeys: String, CodingKey { case deny_write, deny_read, deny_exec }
    init(from d: Decoder) throws {
        let c = try d.container(keyedBy: CodingKeys.self)
        deny_write = (try? c.decode([String].self, forKey: .deny_write)) ?? []
        deny_read = (try? c.decode([String].self, forKey: .deny_read)) ?? []
        deny_exec = (try? c.decode([String].self, forKey: .deny_exec)) ?? []
    }
    init() {}
}

let home = FileManager.default.homeDirectoryForCurrentUser.path
let dataDir = ProcessInfo.processInfo.environment["XMON_HOME"] ?? home + "/.xmon"
let lock = NSLock()
var policy = Policy()
var roots = Set<Int32>()

func reload() {
    let dec = JSONDecoder()
    if let d = FileManager.default.contents(atPath: dataDir + "/enforce-policy.json"),
       let p = try? dec.decode(Policy.self, from: d) {
        lock.lock(); policy = p; lock.unlock()
    }
    if let d = FileManager.default.contents(atPath: dataDir + "/tracked-roots.json"),
       let r = try? dec.decode([Int32].self, from: d) {
        lock.lock(); roots = Set(r); lock.unlock()
    }
}

func under(_ path: String, _ prefix: String) -> Bool {
    let p = prefix.hasSuffix("/") ? String(prefix.dropLast()) : prefix
    return path == p || path.hasPrefix(p + "/")
}

func parentPid(_ pid: Int32) -> Int32 {
    var info = proc_bsdinfo()
    let n = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, Int32(MemoryLayout<proc_bsdinfo>.size))
    return n > 0 ? Int32(info.pbi_ppid) : 0
}

/// True when pid is one of the tracked roots or descends from one.
func inTree(_ pid: Int32) -> Bool {
    lock.lock(); let r = roots; lock.unlock()
    var p = pid
    for _ in 0..<64 where p > 1 {
        if r.contains(p) { return true }
        p = parentPid(p)
    }
    return false
}

func str(_ t: es_string_token_t) -> String { String(cString: t.data) }

func deniedExec(_ path: String) -> Bool {
    lock.lock(); defer { lock.unlock() }
    let base = (path as NSString).lastPathComponent
    for e in policy.deny_exec {
        if e.contains("/") ? under(path, e) : base == e { return true }
    }
    return false
}
func deniedWrite(_ path: String) -> Bool {
    lock.lock(); defer { lock.unlock() }
    return policy.deny_write.contains { under(path, $0) }
}
func deniedRead(_ path: String) -> Bool {
    lock.lock(); defer { lock.unlock() }
    return policy.deny_read.contains { under(path, $0) }
}

func handle(_ client: OpaquePointer, _ msg: UnsafePointer<es_message_t>) {
    let m = msg.pointee
    let pid = audit_token_to_pid(m.process.pointee.audit_token)

    // Fast exit: anything outside a monitored agent tree is always allowed.
    func allow() {
        switch m.event_type {
        case ES_EVENT_TYPE_AUTH_OPEN:
            es_respond_flags_result(client, msg, UInt32(bitPattern: m.event.open.fflag), false)
        default:
            es_respond_auth_result(client, msg, ES_AUTH_RESULT_ALLOW, false)
        }
    }
    guard inTree(pid) else { return allow() }

    switch m.event_type {
    case ES_EVENT_TYPE_AUTH_EXEC:
        let path = str(m.event.exec.target.pointee.executable.pointee.path)
        es_respond_auth_result(client, msg, deniedExec(path) ? ES_AUTH_RESULT_DENY : ES_AUTH_RESULT_ALLOW, false)

    case ES_EVENT_TYPE_AUTH_OPEN:
        let path = str(m.event.open.file.pointee.path)
        let fflag = m.event.open.fflag
        let writes = (fflag & FWRITE) != 0
        let blocked = (writes && deniedWrite(path)) || deniedRead(path)
        // allowed_flags == 0 denies the open; otherwise the flags are permitted.
        es_respond_flags_result(client, msg, blocked ? 0 : UInt32(bitPattern: fflag), false)

    case ES_EVENT_TYPE_AUTH_UNLINK:
        let path = str(m.event.unlink.target.pointee.path)
        es_respond_auth_result(client, msg, deniedWrite(path) ? ES_AUTH_RESULT_DENY : ES_AUTH_RESULT_ALLOW, false)

    case ES_EVENT_TYPE_AUTH_RENAME:
        let src = str(m.event.rename.source.pointee.path)
        es_respond_auth_result(client, msg, deniedWrite(src) ? ES_AUTH_RESULT_DENY : ES_AUTH_RESULT_ALLOW, false)

    default:
        allow()
    }
}

reload()
Timer.scheduledTimer(withTimeInterval: 1, repeats: true) { _ in reload() }

var client: OpaquePointer?
let res = es_new_client(&client) { c, msg in handle(c, msg) }
guard res == ES_NEW_CLIENT_RESULT_SUCCESS, let cl = client else {
    FileHandle.standardError.write(Data("es_new_client failed (\(res.rawValue)); needs the ES entitlement, root and Full Disk Access\n".utf8))
    exit(1)
}
let events: [es_event_type_t] = [ES_EVENT_TYPE_AUTH_EXEC, ES_EVENT_TYPE_AUTH_OPEN,
                                 ES_EVENT_TYPE_AUTH_UNLINK, ES_EVENT_TYPE_AUTH_RENAME]
guard es_subscribe(cl, events, UInt32(events.count)) == ES_RETURN_SUCCESS else {
    FileHandle.standardError.write(Data("es_subscribe failed\n".utf8))
    exit(1)
}
RunLoop.main.run()

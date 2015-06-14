
public class SSH2Session {
  public let cSession: COpaquePointer
  
  public init(cSession: COpaquePointer) {
    self.cSession = cSession
  }
  
  public init() { self.cSession = nil }
  
  deinit {
    if self.cSession != nil { libssh2_free(cSession, UnsafeMutablePointer<Void>()) }
  }
}
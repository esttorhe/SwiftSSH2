
public class SSH2Session {
  public let cSession: COpaquePointer
  
  public init(cSession: COpaquePointer) {
    self.cSession = cSession
  }
  
  deinit {
    libssh2_free(cSession, UnsafeMutablePointer<Void>())
  }
}
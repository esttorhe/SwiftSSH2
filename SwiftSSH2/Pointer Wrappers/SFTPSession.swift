
public class SFTPSession {
  public let cSFTPSession: COpaquePointer
  
  public init(cSFTPSession: COpaquePointer) {
    self.cSFTPSession = cSFTPSession
  }
  
  deinit {
    libssh2_sftp_shutdown(cSFTPSession)
  }
}

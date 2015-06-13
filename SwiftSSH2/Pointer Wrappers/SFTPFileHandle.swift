
public class SFTPFileHandle {
  public let cFileHandle: COpaquePointer
  public var isDirectory: Bool
  
  public init(fileHandle: COpaquePointer) {
    self.cFileHandle = fileHandle
    self.isDirectory = false
  }
  
  deinit {
    libssh2_sftp_close_handle(cFileHandle)
  }
}
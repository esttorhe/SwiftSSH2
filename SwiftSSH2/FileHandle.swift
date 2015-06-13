
public typealias SFTP_Handle = COpaquePointer

public struct FileHandle {
  private var handle: SFTP_Handle?
  private let path: String?
  private let session: SSH2Client?
  
  public init(fileHandle _handle: SFTP_Handle, session _session: SSH2Client, path _path: String) {
    handle = _handle
    session = _session
    path = _path
  }
  
  public func write(buffer: UnsafePointer<Int8>, maxLength: Int) -> Int {
    if let handle = handle {
      return libssh2_sftp_write(handle, buffer, maxLength)
    } else {
      return 0
    }
  }
  
  public func writeData(data: NSData) -> Result<Int, NSError> {
    var offset = 0
    var remainder = data.length
    
//    while remainder != 0 {
//      let bytes: UnsafePointer<()> = data.bytes
//      let bytesWritten = self.write(UnsafePointer<Int8>(bytes+offset), maxLength: remainder)
//      if bytesWritten < 0 {
//        if let session = session {
//          if let path = path {
//            if let error = session.sessionError(path: path) {
//              return Result<Int, NSError>.failure(error)
//            }
//          }
//        }
//        
//        return Result<Int, NSError>.failure(NSError(domain: "es.estebantorr.SwiftSSH2", code: -666, userInfo: [NSLocalizedDescriptionKey: "Unable to write data"]))
//      } else {
//        offset+=bytesWritten
//        remainder-=bytesWritten
//      }
//    }
    
    return Result.success(0)
  }
}
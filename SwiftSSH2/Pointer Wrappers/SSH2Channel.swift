
public class SSH2Channel {
  public let cChannel: COpaquePointer
  
  public init(channel: COpaquePointer) {
    cChannel = channel
  }
  
   deinit {
    let rc = libssh2_channel_close(cChannel)
    
    if (rc == 0) {
      libssh2_channel_wait_closed(cChannel)
    }
    
    libssh2_channel_free(cChannel)
  }
}
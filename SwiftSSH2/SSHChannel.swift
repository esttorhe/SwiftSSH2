
/**
*/
public enum PTYTerminal: String {
  case Vanilla = "vanilla"
  case VT100 = "vt100"
  case VT102 = "vt102"
  case VT220 = "vt220"
  case Ansi = "ansi"
  case Xterm = "xterm"
  case None = ""
}

/**
*/
public enum ChannelType {
  case Closed
  case Exec
  case Shell
  case SCP
  case Subsystem
}

public enum ChannelError: ErrorType {
  case UnableToOpenChannelSession
}

/**
*/
public class SSHChannel {
  private let session: SSH2Session
  private var channel: SSH2Channel?=nil
  private let LIBSSH2_CHANNEL_WINDOW_DEFAULT: UInt32 = 256*1024
  private (set) public var ptyTerminal = PTYTerminal.None
  
  // MARK: - Initializers
  
  /**
  */
  public init(session: SSH2Session) {
    self.session = session
  }
  
  /**
  */
  public func openChannel(channel: SSH2Channel?=nil) throws -> SSH2Channel {
    libssh2_session_set_blocking(session.cSession, 10)
    
    let windowSize: UInt32 = 256*1024
    let cChannel = libssh2_channel_open_ex(session.cSession, "session", UInt32("session".characters.count - 1), windowSize, UInt32(LIBSSH2_CHANNEL_PACKET_DEFAULT), nil, UInt32(0))
    self.channel = SSH2Channel(channel: cChannel)
    
    guard cChannel.hashValue == 0 else {
      throw ChannelError.UnableToOpenChannelSession
    }
    
    return self.channel!
  }
}
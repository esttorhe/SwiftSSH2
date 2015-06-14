
public enum ClientError: ErrorType {
  case HandshakeFailed(String)
  case UnableToCreateUnderlyingLibSSH2Session
  case HostAddressOrNameNotProvided
  case GetAddressInfoFailed(String)
  case UnableToDiscoverServerInformationForHost
  case UnableToOpenConnectionToServer
  case ResolvingSymlinkFailed(String)
  case UnableToListItemsWithoutValidSSH2Session
  case SFTP2OpenDirectoryFailed(String)
  case UnableToListItemsAtPath(String)
  case RemoveDirectoryFailed(String)
  case CreateDirectoryFailed(String)
  case CannotAuthorizeWithoutUsernameAndPassword
  case AuthenticationFailed(String)
  case SFTP2SessionFailed(String)
  case UnableToCheckAuthenticationMethodWithoutSession(String)
  case UnableToCheckAuthenticationMethodsWithoutValidSession
  case UnableToCheckAuthenticationMethodsWithoutValidUsername
  case FailedToGetAuthenticationMethodsForHost(String)
  case UnableToRetrieveBannerWithoutValidSession
  case UnableToRetrieveBannerFromHost(String)
}

/**
  Basic `*nix` `chmod` permissions set.
  - `7`	read, write and execute	`111`
  - `6`	read and write	 `110`
  - `5`	read and execute	 `101`
  - `4`	read only	`100`
  - `3`	write and execute	`011`
  - `2`	write only	 `010`
  - `1`	execute only	 `001`
  - `0`	none	`000`
*/
public struct FilePermission: OptionSetType {
  public let rawValue: UInt32
  public init(rawValue: UInt32) { self.rawValue = rawValue }
  
  static public let None = FilePermission(rawValue: 0)
  static public let Execute = FilePermission(rawValue: 1)
  static public let Write = FilePermission(rawValue: 2)
  static public let Read =  FilePermission(rawValue: 4)
}

/**
Manages *all* communication with the host/server. 
*/
public class SSH2Client {
  
  // MARK: Properties
  /// Current `SSH2Session` instance. (`nil` if not yet connected or failed to connect)
  public var session: SSH2Session? = nil
  private var hostaddr: String? = nil
  private var port: Int32
  private let username: String?
  private let password: String?
  
  /**
  Property that determines if the session was provided with `password`.
  If it was we assume the authorization to be password; if not then certificate.
  */
  private var authorizeWithPassword: Bool {
    get {
      switch password {
        case .None: return false
        case .Some(_): return true
      }
    }
  }
  
  // MARK: Initializers
  /**
  Initializes an `SSHClient` instance with the parameters provided.
  
  - parameter host: The host/server address or name to which we'll be connecting.
  
  - parameter port: The `host` port to which we'll try to connect.
  
  - parameter username: The username we'll use to authenticate with the `host`.
  
  - parameter password: The password we'll use to authenticate with against the `host` (if any).
  
  - returns: Returns a fully initialized client ready to start connecting or `nil`
  if no valid host address/name was provided.
  */
  public init?(host hostaddr: String, port: Int32 = 22, username: String? = nil, password: String? = nil) {
    // Assigning all properties to silence compiler warning
    self.hostaddr = hostaddr
    self.port = port
    self.username = username
    self.password = password
    
    // Cannot initialize without a host address or name
    if hostaddr.characters.count <= 0 {
      println("• Cannot initialize without a host address or name")
      
      return nil
    }
  }

  // MARK: - Connection
  
  /**
  Start interacting with the provided `host`.
  
  - parameter hash: A `Fingerprint` hash specifying what type of hash will be used when
  getting the fingerprint back from the server.
  If none provided will default to `.MD5`
  
  - returns: A `Result` with a tuple of (SSH2Session, Fingerprint) for the current 
  host if succeeds or `String` describing the current error.
  */
  public func startConnection(hash: Fingerprint.Hash=Fingerprint.Hash.MD5) throws -> (SSH2Session, Fingerprint) {
    let addrInfo = try self.discoverAddressInfoForHost()
    let sock = try self.connectToSocketUsing(addrInfo: addrInfo)
    
    // Initialize the libssh2 flow
    var rc = libssh2_init(0)
    
    // Create a session that will be used to interact with the server
    let cSession = libssh2_session_init_ex(nil, nil, nil, nil)
    session = SSH2Session(cSession: cSession)
    
    guard let oSession = self.session else {
      throw ClientError.UnableToCreateUnderlyingLibSSH2Session
    }
    
    // Set the session as blocking
    libssh2_session_set_blocking(oSession.cSession, 10)
    
    // Start the handshake with the server (exchanging banners, MAC layers, etc)
    repeat {
      rc = libssh2_session_handshake(oSession.cSession, sock)
    } while (rc == LIBSSH2_ERROR_EAGAIN)
    
    // Check if the handshake failed
    guard rc == 0 else {
      let errMsg = "handshake failed: " + String(UTF8String: strerror(errno))!
      println(errMsg)
      
      throw ClientError.HandshakeFailed(errMsg)
    }
    
    // Grab the server fingerprint if possible
    let cFingerprint = libssh2_hostkey_hash(oSession.cSession, hash.rawValue)
    let fingerprint = Fingerprint.fingerprint(cFingerprint, hash: hash)
    println("• Fingerprint: \(fingerprint.fingerprint)\n")
    
    let tupleResult:(SSH2Session, Fingerprint) = (oSession, fingerprint)

    return tupleResult
  }
  
  
  // MARK: - Connection Settings
  /**
  Retrieves the remove banner from the server (if any).
  
  - parameter session: A valid `SSH2Session` that will be used to retrieve the banner.
  If `nil` a previously open internal session will be used or an error will be returned.
  
  - returns: The host's remote banner (if any) or an error if there's no valid/open `SSH2Session`.
  */
  public func remoteBanner(session sess: SSH2Session?=nil) throws -> String? {
    /**
    * Parameters validation and local variables declarations
    */
    var session = SSH2Session() // Adding this to silence compiler warning. Real value results from switch
    switch (sess, self.session) {
      case (.Some(let parameterSession), _): session = parameterSession
      case (_, .Some(let selfSession)): session = selfSession
      default: ClientError.UnableToRetrieveBannerWithoutValidSession
    }
    
    let banner = libssh2_session_banner_get(session.cSession)
    guard let bannrStr = String(UTF8String: banner) else {
      throw ClientError.UnableToRetrieveBannerFromHost(self.hostaddr!)
    }

    println("• Remote host banner: \(bannrStr)")
    
    return bannrStr
  }
  
  
  // MARK: - Authentication
  
  /**
  */
  public func supportedAuthenticationMethods(session sess: SSH2Session?=nil, username usr:String?=nil) throws -> [String] {
    /**
    * Parameters validation and local variables declarations
    */
    let session: SSH2Session
    switch (sess, self.session) {
      case (.Some(let parameterSession), _): session = parameterSession
      case (_, .Some(let selfSession)): session = selfSession
      default: throw ClientError.UnableToCheckAuthenticationMethodsWithoutValidSession
    }
    
    let username: String
    switch (usr, self.username) {
      case (.Some(let parameterUsername), _): username = parameterUsername
      case (_, .Some(let selfUsername)): username = selfUsername
      default: throw ClientError.UnableToCheckAuthenticationMethodsWithoutValidUsername
    }
    
    // Reading the authentication methods from the session
    guard let methodsList:String = String(UTF8String: libssh2_userauth_list(session.cSession, username, UInt32(username.characters.count))) else {
      throw ClientError.FailedToGetAuthenticationMethodsForHost(self.hostaddr!)
    }
    
    let methods = methodsList.componentsSeparatedByString(",")
    println("• Supported methods for host: \(methodsList)")
    
    return methods
  }
  
  /**
  */
  public func supportsAuthenticationMethod(method: String, session sess: SSH2Session?=nil) throws -> Bool {
    /**
    * Parameters validation and local variables declarations
    */
    let session: SSH2Session
    switch (sess, self.session) {
      case (.Some(let parameterSession), _): session = parameterSession
      case (_, .Some(let selfSession)): session = selfSession
      default: throw ClientError.UnableToCheckAuthenticationMethodWithoutSession(method)
    }
   
    // We convert to lowercase to compare methods in same casing
    let lwrMethod = method.lowercaseString
    return try self.supportedAuthenticationMethods(session: session).filter{$0.lowercaseString == lwrMethod}.count > 0
  }
  
  /**
  */
  public func authorizeWithCredentials(session: SSH2Session) throws -> SFTPSession {
    // Check if we have username and passowrd
    guard let username = self.username, password = self.password else {
      throw ClientError.CannotAuthorizeWithoutUsernameAndPassword
    }
    
    var rc: Int32 = 0
    repeat {
      rc = libssh2_userauth_password_ex(session.cSession, username, UInt32(username.characters.count), password, UInt32(password.characters.count), nil)
    } while (rc == LIBSSH2_ERROR_EAGAIN)
    
    guard rc == 0 else {
      let errMsg = "authentication failed: " + String(UTF8String: strerror(errno))!
      println(errMsg)
      
      throw ClientError.AuthenticationFailed(errMsg)
    }
    
    var sftp_session: SFTPSession
    repeat {
      sftp_session = SFTPSession(cSFTPSession:libssh2_sftp_init(session.cSession))
      
      let sftpStatus = libssh2_session_last_errno(session.cSession)
      guard sftp_session.cSFTPSession.hashValue != 0 || sftpStatus == LIBSSH2_ERROR_EAGAIN else {
        let errMsg = "sftp2 session failed: " + String(UTF8String: strerror(errno))!
        println(errMsg)
        
        throw ClientError.SFTP2SessionFailed(errMsg)
      }
    } while (sftp_session.cSFTPSession.hashValue == 0)
    
    return sftp_session
  }
  
  
  // MARK: - Directories
  
  /**
  */
  public func createDirectoryAtPath(path: String, createIntermediateDirectories: Bool=false, sftp_session: SFTPSession, mode: (owner: UInt32, group: UInt32, everyone: UInt32)) throws -> String {
    let str = "\(mode.owner)\(mode.group)\(mode.everyone)"
    println("• File permission: \(str)")
    
    guard let flags = Int(str) else {
      let errMsg = "remove dir failed: " + String(UTF8String: strerror(errno))!
      println(errMsg)
      
      throw ClientError.RemoveDirectoryFailed(errMsg)
    }
    
    var result: Int32 = -1
    repeat {
      result = libssh2_sftp_mkdir_ex(sftp_session.cSFTPSession, path, UInt32(path.characters.count), flags)
      guard result >= 0 else {
        let errMsg = "create dir failed: " + String(UTF8String: strerror(errno))!
        println(errMsg)
        
        throw ClientError.CreateDirectoryFailed(errMsg)
      }
    
      if result > 0 && createIntermediateDirectories { // && result == LIBSSH2_FX_NO_SUCH_FILE {
          //            for pathComponent in path.pathComponents {
          //              self.createDirectoryAtPath(pathComponent, createIntermediateDirectories: createIntermediateDirectories, sftp_session: sftp_session, mode: mode) >>- {
          //                result -> Result<String, String> in
          //                println(result)
          //
          //                return Result.success(result)
          //              }
          //            }
          //            let parent = path.stringByDeletingLastPathComponent
          //
          //            return self.createDirectoryAtPath(parent, createIntermediateDirectories: createIntermediateDirectories, sftp_session: sftp_session, mode: mode)
      }
    } while (result > 0)
    
    return "Successfully created directory at path \(path)"
  }
  
  /**
  */
  public func removeDirectoryAtPath(path: String, sftp_session: SFTPSession) throws -> String {
    guard libssh2_sftp_rmdir_ex(sftp_session.cSFTPSession, path, UInt32(path.characters.count)) == 0 else {
      let errMsg = "remove dir failed: " + String(UTF8String: strerror(errno))!
      println(errMsg)
      
      throw ClientError.RemoveDirectoryFailed(errMsg)
    }
    
    return "Successfully deleted directory \(path)"
  }

  /**
  */
  public func listItemsOnPath(path sftppath: String, sftp_session: SFTPSession, sess: SSH2Session? = nil) throws -> [File] {
    // Support injecting an `SSH2Session` for testing purposes
    let session: SSH2Session
    switch (sess, self.session) {
      case (.Some(let parameterSession), _): session = parameterSession
      case (_, .Some(let selfSession)): session = selfSession
      default: throw ClientError.UnableToListItemsWithoutValidSSH2Session
    }
    
    /* Request a dir listing via SFTP */
    var rc: Int32 = 0
    var sftp_handle: SFTPFileHandle
    repeat {
      sftp_handle = SFTPFileHandle(fileHandle: libssh2_sftp_open_ex(sftp_session.cSFTPSession, sftppath, UInt32(sftppath.characters.count), 0, 0, LIBSSH2_SFTP_OPENDIR))
      sftp_handle.isDirectory = true
      
      let sftpHandleStatus = libssh2_session_last_errno(session.cSession) != LIBSSH2_ERROR_EAGAIN
      guard (sftp_handle.cFileHandle.hashValue != 0 || !sftpHandleStatus) else {
        let errMsg = "sftp2 open dir failed: " + String(UTF8String: strerror(errno))!
        println(errMsg)
        
        throw ClientError.SFTP2OpenDirectoryFailed(errMsg)
      }
    } while (sftp_handle.cFileHandle.hashValue == 0)
    
    /* loop until we can't read any more data to the buffer */
    var result = [File]()
    repeat {
      // Local variables declaration
      let buffSize = 512
      let attrs = UnsafeMutablePointer<LIBSSH2_SFTP_ATTRIBUTES>.alloc(1)
      let buffer = UnsafeMutablePointer<Int8>.alloc(buffSize)
      let longe = UnsafeMutablePointer<Int8>.alloc(buffSize)
      
      defer {
        longe.dealloc(buffSize)
        buffer.dealloc(buffSize)
        attrs.dealloc(1)
      }
    
      repeat {
        rc = libssh2_sftp_readdir_ex(sftp_handle.cFileHandle, buffer, buffSize, longe, buffSize, attrs)
      } while (rc == LIBSSH2_ERROR_EAGAIN)
      
      // rc is the length of the file name in the mem buffer
      switch rc {
        case (_) where rc == LIBSSH2_ERROR_EAGAIN: /* Blocking */
          println("• \(stderr)Blocking")
        case (_) where rc > 0: /* Successfully read to the buffer */
          if let file = File(buffer: buffer, fileAttributes: attrs.memory, longentry: longe) {
            result.append(file)
            println("\t\t\t• \(file.type) •")
          }
        case (_) where rc < 0: /* There was an error */
          let errMsg = "sftp2 read dir failed: " + String(UTF8String: strerror(errno))!
          println(errMsg)
          
          throw ClientError.UnableToListItemsAtPath(sftppath)
        default: return result /* We finished reading the directory */
      }
    } while (rc > 0)

    // Added to silence compiler warning 
    throw ClientError.UnableToListItemsAtPath(sftppath)
  }
  
  public func currentDirectoryPath(sftp_session sftp_session: SFTPSession) throws -> String {
    return try self.resolveSymlink(sftp_session, path: ".", complex: true)
  }
  
  // MARK: - Internal Helpers
  // MARK: Sockets
  
  /**
  */
  internal func discoverAddressInfoForHost() throws -> addrinfo {
    // Local variables initialization
    guard let hostaddr = self.hostaddr else {
      throw ClientError.HostAddressOrNameNotProvided
    }
    
    /** ========================================================================
    * This is commented out until a bug in `Swift` gets fixed that prevents this
    * method signature to be called with the correct parameters.
    * Radar link here: http://openradar.me/21275861
    * ========================================================================*/
    // Get address info
/*******************************************************************************
    let host:CFHost! = CFHostCreateWithName(kCFAllocatorDefault, hostaddr).takeRetainedValue()
    let error = UnsafeMutablePointer<CFStreamError>.alloc(1)
    if CFHostStartInfoResolution(host, CFHostInfoType.Addresses, error) {
      let hbr = UnsafeMutablePointer<Boolean>()
      addresses = CFHostGetAddressing(host, hbr)
      
      host.release()
    }
*******************************************************************************/
    
    // Hints Structure to «discover» the server info
    var hints = addrinfo()
    hints.ai_family = AF_INET
    hints.ai_socktype = SOCK_STREAM
    let unsafePointer = UnsafeMutablePointer<addrinfo>.alloc(1)
    unsafePointer.initialize(hints)
    let hintsPointer = UnsafePointer<addrinfo>(unsafePointer)
    let servInfo = UnsafeMutablePointer<UnsafeMutablePointer<addrinfo>>.alloc(sizeofValue(UnsafeMutablePointer<UnsafeMutablePointer<addrinfo>>))
    let addrInfo = getaddrinfo(hostaddr, String(port), hintsPointer, servInfo)
    
    defer {
      unsafePointer.dealloc(1)
      servInfo.dealloc(sizeofValue(UnsafeMutablePointer<UnsafeMutablePointer<addrinfo>>))
    }
    
    guard addrInfo == 0 else {
      let errMsg = ("getaddrinfo failed: " + String(UTF8String: strerror(errno))!)
      println(errMsg)
      
      throw ClientError.GetAddressInfoFailed(errMsg)
    }
    
    guard servInfo.hashValue != 0 && servInfo.memory.hashValue != 0 else {
      throw ClientError.UnableToDiscoverServerInformationForHost
    }
    
    return servInfo.memory.memory
  }
  
  /**
  */
  internal func connectToSocketUsing(addrInfo addrInfo: addrinfo) throws -> libssh2_socket_t {
    // loop through all the results and connect to the first we can
    var p:addrinfo = addrInfo
    var sock: libssh2_socket_t = -1
    
    // Iterate through the list of addrinfo
    while true {
      // Let's try to create a socket with the discovered info
      let sockfd = socket(p.ai_family, p.ai_socktype, p.ai_protocol)
      if (sockfd == -1) {
        println("• socket failed: " + String(UTF8String: strerror(errno))!)
       
        // Move to the next possible addrinfo
        if p.ai_next.hashValue != 0 { p = p.ai_next.memory; continue }
        break
      }
      
      // Let's try to connect to the new socket
      let connectStatus = connect(sockfd, address: p.ai_addr.memory)
      if (connectStatus == -1) {
        close(sockfd)
        println("• connect failed: " + String(UTF8String: strerror(errno))!)
        
        // Move to the next possible addrinfo
        if p.ai_next.hashValue != 0 { p = p.ai_next.memory; continue }
        break
      }
      
      sock = sockfd
      break
    }
    
    // No valid socket was found
    guard sock != -1 else {
      throw ClientError.UnableToOpenConnectionToServer
    }
    
    return sock
  }
  
  // MARK: Paths
  
  /**
  */
  public func destinationOfSimbolicLinkAtPath(path: String, sftp_session: SFTPSession) throws -> String {
    return try self.resolveSymlink(sftp_session, path: path, complex: false)
  }
  
  /**
  */
  internal func resolveSymlink(sftp_session: SFTPSession, path: String, complex: Bool=true) throws -> String {
    let buffer: UnsafeMutablePointer<Int8> = UnsafeMutablePointer<Int8>.alloc(1)
    var pathLength: Int32 = 0
    var bufferLength: UInt32 = 256
    
    defer {
      buffer.dealloc(1)
    }
    
    repeat {
      pathLength = libssh2_sftp_symlink_ex(sftp_session.cSFTPSession, path, UInt32(path.characters.count), buffer, bufferLength, complex ? LIBSSH2_SFTP_REALPATH : LIBSSH2_SFTP_READLINK)
      bufferLength *= 2 // grow exponentially so don't get bogged down too long
    } while(pathLength == LIBSSH2_ERROR_BUFFER_TOO_SMALL)
    
    guard pathLength >= 0 else {
      let errMsg = "resolving symlink failed: " + String(UTF8String: strerror(errno))!
      println(errMsg)

      throw ClientError.ResolvingSymlinkFailed(errMsg)
    }

    guard let pathName = String.fromCString(buffer) else {
      throw ClientError.ResolvingSymlinkFailed("Cannot retrieve path name for path: \(path)")
    }
    
    println("• Current Path: \(pathName)")
    
    return pathName
  }
}
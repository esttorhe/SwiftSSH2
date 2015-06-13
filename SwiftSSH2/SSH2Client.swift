
// 3rd Party Dynamic Frameworks
import Result

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
public enum FilePermission: UInt32 {
  case None = 0
  case Execute = 1
  case Write = 2
  case Read = 4
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
  public func startConnection(hash: Fingerprint.Hash=Fingerprint.Hash.MD5) -> Result<(SSH2Session, Fingerprint), String> {
    return self.discoverAddressInfoForHost() >>- { addrInfo -> Result<(SSH2Session, Fingerprint), String> in
      self.connectToSocketUsing(addrInfo: addrInfo) >>- { sock -> Result<(SSH2Session, Fingerprint), String> in
        // Initialize the libssh2 flow
        var rc = libssh2_init(0)

        // Create a session that will be used to interact with the server
        let cSession = libssh2_session_init_ex(CFunctionPointer<((Int, UnsafeMutablePointer<UnsafeMutablePointer<Void>>) -> UnsafeMutablePointer<Void>)>(nilLiteral: ()), CFunctionPointer<((UnsafeMutablePointer<Void>, UnsafeMutablePointer<UnsafeMutablePointer<Void>>) -> Void)>(nilLiteral: ()), CFunctionPointer<((UnsafeMutablePointer<Void>, Int, UnsafeMutablePointer<UnsafeMutablePointer<Void>>) -> UnsafeMutablePointer<Void>)>(nilLiteral: ()), UnsafeMutablePointer<Void>(nilLiteral: ()))
        session = SSH2Session(cSession: cSession)

        if let oSession = self.session {
          // Set the session as blocking
          libssh2_session_set_blocking(oSession.cSession, 10)
          
          // Start the handshake with the server (exchanging banners, MAC layers, etc)
          repeat {
            rc = libssh2_session_handshake(oSession.cSession, sock)
          } while (rc == LIBSSH2_ERROR_EAGAIN)

          // Check if the handshake failed
          if rc != 0 {
            let errMsg = "handshake failed: " + String(UTF8String: strerror(errno))!
            println(errMsg)

            return Result.failure(errMsg)
          }

          // Grab the server fingerprint if possible
          let cFingerprint = libssh2_hostkey_hash(oSession.cSession, hash.rawValue)
          let fingerprint = Fingerprint.fingerprint(cFingerprint, hash: hash)
          println("• Fingerprint: \(fingerprint.fingerprint)\n")
          
          let tupleResult:(SSH2Session, Fingerprint) = (oSession, fingerprint)
          return Result.success(tupleResult)
        }
        
        return Result.failure("Unable to create an underlying libssh2 session.")
      }
    }
  }
  
  
  // MARK: - Connection Settings
  /**
  Retrieves the remove banner from the server (if any).
  
  - parameter session: A valid `SSH2Session` that will be used to retrieve the banner.
  If `nil` a previously open internal session will be used or an error will be returned.
  
  - returns: The host's remote banner (if any) or an error if there's no valid/open `SSH2Session`.
  */
  public func remoteBanner(session: SSH2Session?=nil) -> Result<String?, String> {
    /**
    * Parameters validation and local variables declarations
    */
    let rSession: SSH2Session
    if let session = session {
      rSession = session
    } else if let session = self.session {
      rSession = session
    } else {
      return Result.failure("Unable to retrieve the banner without a valid SSH2 session.")
    }
    
    let banner = libssh2_session_banner_get(rSession.cSession)
    let bannrStr = String(UTF8String: banner)
    if let bannrStr = bannrStr {
      println("• Remote host banner: \(bannrStr)")
    }
    
    return Result.success(bannrStr)
  }
  
  
  // MARK: - Authentication
  
  /**
  */
  public func supportedAuthenticationMethods(session: SSH2Session?=nil, username:String?=nil) -> Result<[String], String> {
    /**
    * Parameters validation and local variables declarations
    */
    let rSession: SSH2Session
    if let session = session {
      rSession = session
    } else if let session = self.session {
      rSession = session
    } else {
      return Result.failure("Unable to check authentication methods without a valid SSH2 session.")
    }
    
    let rUsername: String
    if let username = username {
      rUsername = username
    } else if let username = self.username {
      rUsername = username
    } else {
      return Result.failure("Unable to check authentication methods without a valid username.")
    }
    
    // Reading the authentication methods from the session
    if let methodsList:String = String(UTF8String: libssh2_userauth_list(rSession.cSession, rUsername, UInt32(rUsername.count))) {
      let methods = methodsList.componentsSeparatedByString(",")
      println("• Supported methods for host: \(methodsList)")
      
      return Result.success(methods)
    }
    
    return Result.failure("Failed to get authentication methods for host \(self.hostaddr!)")
  }
  
  /**
  */
  public func supportsAuthenticationMethod(method: String, session: SSH2Session?=nil) -> Result<Bool, String> {
    /**
    * Parameters validation and local variables declarations
    */
    let rSession: SSH2Session
    if let session = session {
      rSession = session
    } else if let session = self.session {
      rSession = session
    } else {
      return Result.failure("Unable to check if authentication method `\(method)` is supported without a valid SSH2 session.")
    }
   
    // We convert to lowercase to compare methods in same casing
    let lwrMethod = method.lowercaseString
    return self.supportedAuthenticationMethods(session: session) >>- { methods -> Result<Bool, String> in
      Result.success(count(methods.filter{$0.lowercaseString == lwrMethod}) > 0)
    }
  }
  
  /**
  */
  public func authorizeWithCredentials(session: SSH2Session) -> Result<SFTPSession, String> {
    // Check if we have username and passowrd
    let username: String, password: String
    switch (self.username, self.password) {
    case (Optional.Some(let usr), Optional.Some(let pwd)):
      // Unwrap the optionals because we _DO_ know they have values
      username = usr
      password = pwd
    default:
      return Result.failure("Cannot authorize without username and password.")
    }
    
    var rc: Int32 = 0
    repeat {
      rc = libssh2_userauth_password_ex(session.cSession, username, UInt32(username.count), password, UInt32(password.count), CFunctionPointer<((COpaquePointer, UnsafeMutablePointer<UnsafeMutablePointer<Int8>>, UnsafeMutablePointer<Int32>, UnsafeMutablePointer<UnsafeMutablePointer<Void>>) -> Void)>())
    } while (rc == LIBSSH2_ERROR_EAGAIN)
    
    if rc != 0 {
      let errMsg = "authentication failed: " + String(UTF8String: strerror(errno))!
      println(errMsg)
      
      return Result.failure(errMsg)
    }
    
    var sftp_session: SFTPSession
    repeat {
      sftp_session = SFTPSession(cSFTPSession:libssh2_sftp_init(session.cSession))
      
      let sftpStatus = libssh2_session_last_errno(session.cSession)
      if sftp_session.cSFTPSession.hashValue == 0 && sftpStatus != LIBSSH2_ERROR_EAGAIN {
        let errMsg = "sftp2 session failed: " + String(UTF8String: strerror(errno))!
        println(errMsg)
        
        return Result.failure(errMsg)
      }
    } while (sftp_session.cSFTPSession.hashValue == 0)
    
    return Result.success(sftp_session)
  }
  
  
  // MARK: - Directories
  
  /**
  */
  public func createDirectoryAtPath(path: String, createIntermediateDirectories: Bool=false, sftp_session: SFTPSession, mode: (owner: UInt32, group: UInt32, everyone: UInt32)) -> Result<String, String> {
    let str = "\(mode.owner)\(mode.group)\(mode.everyone)"
    println("• File permission: \(str)")
    
    if let flags = str.toInt() {
      var result: Int32 = -1
      repeat {
        result = libssh2_sftp_mkdir_ex(sftp_session.cSFTPSession, path, UInt32(count(path)), flags)
        
        if result == 0 {
          return Result.success("Successfully created directory at path \(path)")
        } else {
          if createIntermediateDirectories { // && result == LIBSSH2_FX_NO_SUCH_FILE {
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
        }
      } while (result > 0)
    }
    
    let errMsg = "create dir failed: " + String(UTF8String: strerror(errno))!
    println(errMsg)
    
    return Result.failure(errMsg)
  }
  
  /**
  */
  public func removeDirectoryAtPath(path: String, sftp_session: SFTPSession) -> Result<String, String> {
    if libssh2_sftp_rmdir_ex(sftp_session.cSFTPSession, path, UInt32(path.count)) == 0 {
      return Result.success("Successfully deleted directory \(path)")
    }
    
    let errMsg = "remove dir failed: " + String(UTF8String: strerror(errno))!
    println(errMsg)
    
    return Result.failure(errMsg)
  }

  /**
  */
  public func listItemsOnPath(path sftppath: String, sftp_session: SFTPSession, sess: SSH2Session? = nil) -> Result<[File], String> {
    // Support injecting an `SSH2Session` for testing purposes
    let session: SSH2Session
    if let paramSession = sess {
      session = paramSession
    } else if let selfSession = self.session {
      session = selfSession
    } else {
      return Result.failure("Unable to list items without a valid SSH2 Session.")
    }
    
    /* Request a dir listing via SFTP */
    var rc: Int32 = 0
    var sftp_handle: SFTPFileHandle
    repeat {
      sftp_handle = SFTPFileHandle(fileHandle: libssh2_sftp_open_ex(sftp_session.cSFTPSession, sftppath, UInt32(sftppath.count), 0, 0, LIBSSH2_SFTP_OPENDIR))
      sftp_handle.isDirectory = true
      
      let sftpHandleStatus = libssh2_session_last_errno(session.cSession) != LIBSSH2_ERROR_EAGAIN
      if (sftp_handle.cFileHandle.hashValue == 0 && sftpHandleStatus) {
        let errMsg = "sftp2 open dir failed: " + String(UTF8String: strerror(errno))!
        println(errMsg)
        
        return Result.failure(errMsg)
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
      
      repeat {
        rc = libssh2_sftp_readdir_ex(sftp_handle.cFileHandle, buffer, buffSize, longe, buffSize, attrs)
      } while (rc == LIBSSH2_ERROR_EAGAIN)
      
      // rc is the length of the file name in the mem buffer
      switch rc {
        case let (_) where rc == LIBSSH2_ERROR_EAGAIN: /* Blocking */
          println("• \(stderr)Blocking")
        case let (_) where rc > 0: /* Successfully read to the buffer */
          if let file = File(buffer: buffer, fileAttributes: attrs.memory, longentry: longe) {
            result.append(file)
            println("\t\t\t• \(file.type) •")
          }
        
          attrs.dealloc(1)
          buffer.dealloc(buffSize)
          longe.dealloc(buffSize)
        case let (_) where rc < 0: /* There was an error */
          let errMsg = "sftp2 read dir failed: " + String(UTF8String: strerror(errno))!
          println(errMsg)
          attrs.dealloc(1)
          buffer.dealloc(buffSize)
          longe.dealloc(buffSize)
          
          return Result.failure("Unable to list items at '\(sftppath)'")
        default: return Result.success(result) /* We finished reading the directory */
      }
    } while (rc > 0)

    // Added to silence compiler warning 
    return Result.failure("Unable to list items at '\(sftppath)'")
  }
  
  public func currentDirectoryPath(sftp_session sftp_session: SFTPSession) -> Result<String, String> {
    return self.resolveSymlink(sftp_session, path: ".", complex: true)
  }
  
  // MARK: - Internal Helpers
  // MARK: Sockets
  
  /**
  */
  internal func discoverAddressInfoForHost() -> Result<addrinfo, String> {
    // Local variables initialization
    var hostaddr: String = ""
    
    if let tempHostAddr = self.hostaddr {
      hostaddr = tempHostAddr
    } else {
      return Result.failure("Host address/name not provided.")
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
    var servInfo = UnsafeMutablePointer<UnsafeMutablePointer<addrinfo>>.alloc(sizeofValue(UnsafeMutablePointer<UnsafeMutablePointer<addrinfo>>))
    let addrInfo = getaddrinfo(hostaddr, String(port), hintsPointer, servInfo)
    
    if addrInfo != 0 {
      let errMsg = ("getaddrinfo failed: " + String(UTF8String: strerror(errno))!)
      println(errMsg)
      unsafePointer.dealloc(1)
      servInfo.dealloc(sizeofValue(UnsafeMutablePointer<UnsafeMutablePointer<addrinfo>>))
      
      return Result.failure(errMsg)
    }
    
    if servInfo.hashValue != 0 && servInfo.memory.hashValue != 0 {
      return Result.success(servInfo.memory.memory)
    }
    
    return Result.failure("Unable to discover server information for the provided host.")
  }
  
  /**
  */
  internal func connectToSocketUsing(addrInfo addrInfo: addrinfo) -> Result<libssh2_socket_t, String> {
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
      let connectStatus = connect(sockfd, p.ai_addr.memory)
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
    if sock == -1 {
      return Result.failure("Unable to open a connection to the provided server.")
    }
    
    return Result.success(sock)
  }
  
  // MARK: Paths
  
  /**
  */
  public func destinationOfSimbolicLinkAtPath(path: String, sftp_session: SFTPSession) -> Result<String, String> {
    return self.resolveSymlink(sftp_session, path: path, complex: false)
  }
  
  /**
  */
  internal func resolveSymlink(sftp_session: SFTPSession, path: String, complex: Bool=true) -> Result<String, String> {
    let buffer: UnsafeMutablePointer<Int8> = UnsafeMutablePointer<Int8>.alloc(1)
    var pathLength: Int32 = 0
    var bufferLength: UInt32 = 256
    repeat {
      pathLength = libssh2_sftp_symlink_ex(sftp_session.cSFTPSession, path, UInt32(path.count), buffer, bufferLength, complex ? LIBSSH2_SFTP_REALPATH : LIBSSH2_SFTP_READLINK)
      bufferLength *= 2 // grow exponentially so don't get bogged down too long
    } while(pathLength == LIBSSH2_ERROR_BUFFER_TOO_SMALL)
    
    if pathLength >= 0 {
      if let pathName = String(buffer) {
        println("• Current Path: \(pathName)")
        buffer.dealloc(1)
        
        return Result.success(pathName)
      }
      buffer.dealloc(1)
      
      return Result.failure("Unable to extract the current path.")
    }
    else {
      let errMsg = "resolving symlink failed: " + String(UTF8String: strerror(errno))!
      println(errMsg)
      buffer.dealloc(1)
      
      return Result.failure(errMsg)
    }
  }
}
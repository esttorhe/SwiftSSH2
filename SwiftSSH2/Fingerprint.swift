
/// Fingerprint enumerator that will generate appropiate fingerprint representations
/// depending on the Hash provided.
public enum Fingerprint: Equatable {
  
  /// Available hashes for fingerprinting
  /// Matches exactly to the `libssh2` hash types.
  public enum Hash: Int32 {
    case MD5 = 1
    case SHA1 = 2
  }
  
  case None
  case HashMD5(UnsafePointer<Int8>)
  case HashSHA1(UnsafePointer<Int8>)
  
  
  // MARK: Constructors
  
  /// Initializes a `Fingerprint` «instance» with the provided
  /// `MD5Fingerprint`.
  public init(MD5Fingerprint: UnsafePointer<Int8>) {
    self = .HashMD5(MD5Fingerprint)
  }
  
  /// Initializes a `Fingerprint` «instance» with the provided
  /// `SHA1Fingerprint`.
  public init(SHA1Fingerprint: UnsafePointer<Int8>) {
    self = .HashSHA1(SHA1Fingerprint)
  }
  
  /// Returns a fully initialized `Fingerprint` with `.MD5` hash.
  public static func hashMD5(fingerprint: UnsafePointer<Int8>) -> Fingerprint {
    return Fingerprint(MD5Fingerprint: fingerprint)
  }
  
  /// Returns a fully initialized `Fingerprint` with `.SHA1` hash.
  public static func hashSHA1(fingerprint: UnsafePointer<Int8>) -> Fingerprint {
    return Fingerprint(SHA1Fingerprint: fingerprint)
  }
  
  /// Returns a fully initialized `Fingerprint` depending on the provided `hash` value.
  public static func fingerprint(fingerprint: UnsafePointer<Int8>, hash: Fingerprint.Hash) -> Fingerprint {
    switch hash {
      case .MD5: return Fingerprint.hashMD5(fingerprint)
      case .SHA1: return Fingerprint.hashSHA1(fingerprint)
    }
  }
  
  // MARK: Deconstruction
  
  /// Returns the hashed `String` representation depending on the hash used
  /// when initializing.
  public var fingerprint: String {
    get {
      switch self {
        case .HashMD5(let fingerprint):
          return fingerprintString(fingerprint, length: 16)
        case .HashSHA1(let fingerprint):
          return fingerprintString(fingerprint, length: 20)
        default:
          println("• Invalid Fingerprint hash provided.")
          
          return ""
      }
    }
  }
  
  // MARK: Internal Helpers
  
  /// Converts the provided `fingerprint` to a valid `String` based on the `length`.
  /// Inserts `:` every 2 «characters» to match a fingerprint mask.
  ///
  /// - returns: A `String` representation of `fingerprint` according to the provided `hash`
  internal func fingerprintString(fingerprint: UnsafePointer<Int8>, length: Int) -> String {
    let buf = UnsafePointer<UInt8>(fingerprint)
    func itoh(i: UInt8) -> UInt8 {
      let charA = UInt8(UnicodeScalar("a").value)
      let char0 = UInt8(UnicodeScalar("0").value)
      
      return (i > 9) ? (charA + i - 10) : (char0 + i)
    }
    
    var pf = UnsafeMutablePointer<UInt8>.alloc(1)
    for i in 0..<length {
      pf[i*3] = itoh((buf[i] >> 4) & 0xF)
      pf[i*3+1] = itoh(buf[i] & 0xF)
      if i != (length - 1) { pf[i*3+2] = UInt8(UnicodeScalar(":").value) }
    }
    
    if let sfp = NSString(bytesNoCopy: pf, length: length*3, encoding: NSUTF8StringEncoding, freeWhenDone: true) {
      return sfp as String
    }
    
    return ""
  }
}


// MARK: - Equatable implementation
// MARK: Fingerprint
public func == (lftFingerprint: Fingerprint, rgtFingerprint: Fingerprint) -> Bool {
  switch (lftFingerprint, rgtFingerprint) {
    case (.HashMD5(let lft), .HashMD5(let rgt)): return lft == rgt
    case (.HashSHA1(let lft), .HashSHA1(let rgt)): return lft == rgt
    default: false
  }
  
  return false
}

// MARK: Hash
public func == (lftHash: Fingerprint.Hash, rgtHash: Fingerprint.Hash) -> Bool {
  switch (lftHash, rgtHash) {
  case (.MD5, .MD5): return true
  case (.SHA1, .SHA1): return true
  default: false
  }
  
  return false
}
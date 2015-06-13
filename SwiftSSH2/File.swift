
// Dynamic Frameworks
import Result

/**
A «model» structure that will hold instances of files, directories, symlinks, etc.
*/
public struct File {
  /// The file's name.
  private (set) public var name: String
  
  /**
  The file's type. As following:
  - NSFileTypeRegular
  - NSFileTypeDirectory
  - NSFileTypeSymbolicLink
  - NSFileTypeSocket
  - NSFileTypeCharacterSpecial
  - NSFileTypeBlockSpecial
  */
  private (set) public var type: String
  
  /**
  Initializes a `File` instance with the provided parameters.
  Returns `nil` if fails to read the file name or any of its attributes.
  
  - parameter buffer: The «C buffer» containing the file name returned from `libssh2`.
  
  - parameter fileAttributes: `LIBSSH2_SFTP_ATTRIBUTES` with the file attributes (flags).
  
  - parameter longentry: «C string» returned from `libssh2` «describing» the file.
  
  - returns: A fully initialized `File` or `nil` if some value couldn't be retrieved.
  */
  public init?(buffer: UnsafeMutablePointer<Int8>, fileAttributes attrs: LIBSSH2_SFTP_ATTRIBUTES, longentry: UnsafeMutablePointer<Int8>?=nil) {
    // Initialize variables
    type = NSFileTypeUnknown
    name = ""
    
    // Extract the flags
//    let flags = UInt8(bitPattern: Int8(attrs.flags))
//    if (flags & UInt8(bitPattern: Int8(LIBSSH2_SFTP_ATTR_PERMISSIONS))) == 0 {
//      /* this should check what permissions it
//      is and print the output accordingly */
//      println("--fix----- ");
//    } else {
//      println("---------- ");
//    }
//    
//    if (flags & UInt8(bitPattern: Int8(LIBSSH2_SFTP_ATTR_UIDGID))) == 0 {
//      println("\(attrs.uid) - \(attrs.gid)");
//    } else {
//      println("   -    - ");
//    }
//    
//    if (flags & UInt8(bitPattern: Int8(LIBSSH2_SFTP_ATTR_SIZE))) == 0 {
//      println("\(attrs.filesize)")
//    }
    
    // Extract the filename from the buffer
    if let filename = String(UTF8String: buffer) {
      // Exclude . and .. as they're not Cocoa-like
      if filename == "." || filename == ".." {
        return nil
      }
      
      self.name = filename
      print("• \(filename)")
      
      if let longe = longentry {
        if let longename = String(UTF8String: longe) {
          println("\t\t \(longename)")
        }
      }
    }
    
    // Extract the permissions flags from the attributes
    // and then pattern match to determine file type.
    let permissions = UInt32(bitPattern: Int32(attrs.permissions))
    let permissionResult = (permissions & UInt32(bitPattern: LIBSSH2_SFTP_S_IFMT))
    switch permissionResult {
      case UInt32(LIBSSH2_SFTP_S_IFREG): type = NSFileTypeRegular
      case UInt32(LIBSSH2_SFTP_S_IFDIR): type = NSFileTypeDirectory
      case UInt32(LIBSSH2_SFTP_S_IFLNK): type = NSFileTypeSymbolicLink
      case UInt32(LIBSSH2_SFTP_S_IFSOCK): type = NSFileTypeSocket
      case UInt32(LIBSSH2_SFTP_S_IFCHR): type = NSFileTypeCharacterSpecial
      case UInt32(LIBSSH2_SFTP_S_IFBLK): type = NSFileTypeBlockSpecial
      default: println("Unable to determine type.")
    }
  }
}
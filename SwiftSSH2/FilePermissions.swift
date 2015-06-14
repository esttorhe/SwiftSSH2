
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
public struct FilePermissionFlag: OptionSetType {
  public let rawValue: UInt32
  public init(rawValue: UInt32) { self.rawValue = rawValue }
  
  /**
  `000` None
  */
  static public let None = FilePermissionFlag(rawValue: 0)
  
  /**
  `001` Execute only
  */
  static public let Execute = FilePermissionFlag(rawValue: 1)
  
  /**
  `010` Write only
  */
  static public let Write = FilePermissionFlag(rawValue: 2)
  
  /**
  `100` Read only
  */
  static public let Read =  FilePermissionFlag(rawValue: 4)
}

/**
`Struct` holding the full set of flags.
`owner` | `group` | `everyone`
*/
public struct FilePermission {
  public let ownerFlag: FilePermissionFlag
  public let groupFlag: FilePermissionFlag
  public let everyoneFlag: FilePermissionFlag
  
  // Full set of flags as a `String` variable.
  public var flags: String {
    get {
      return String(ownerFlag.rawValue) + String(groupFlag.rawValue) + String(everyoneFlag.rawValue)
    }
  }
  
  public init (ownerFlag owner: FilePermissionFlag, groupFlag group: FilePermissionFlag, everyoneFlag everyone: FilePermissionFlag) {
    ownerFlag = owner
    groupFlag = group
    everyoneFlag = everyone
  }
}
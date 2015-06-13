
public protocol SocketAddressType {}

extension sockaddr: SocketAddressType {}
extension sockaddr_in: SocketAddressType {}
extension sockaddr_in6: SocketAddressType {}

func withSockaddrPointer<sockaddr_T: SocketAddressType, Ret>(
  value: UnsafePointer<sockaddr_T>,
  body: (UnsafePointer<sockaddr>, socklen_t) -> Ret
  ) -> Ret {
    return body(UnsafePointer(value), socklen_t(sizeof(sockaddr_T.self)))
}

public func bind<sockaddr_T: SocketAddressType>(socket: CInt, var address: sockaddr_T) -> CInt {
  return withSockaddrPointer(&address) { addrPtr, addrSize in
    bind(socket, addrPtr, addrSize)
  }
}

public func connect<sockaddr_T: SocketAddressType>(socket: CInt, var address: sockaddr_T) -> CInt {
  return withSockaddrPointer(&address) { addrPtr, addrSize in
    connect(socket, addrPtr, addrSize)
  }
}
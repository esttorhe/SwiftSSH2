
/**
  `println` «wrapper» that will only print to console
  when `-D DEBUG` is set on `Other Swift Flags`.
*/
func println(object: Any) {
  #if DEBUG
    Swift.println(object)
  #endif
}

/**
`print` «wrapper» that will only print to console
when `-D DEBUG` is set on `Other Swift Flags`.
*/
func print(object: Any) {
  #if DEBUG
    Swift.print(object)
  #endif
}
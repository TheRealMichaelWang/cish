proc includedll(array<char> lib) {
  auto liboffset = foreign[17]('lib');
  return liboffset;
}

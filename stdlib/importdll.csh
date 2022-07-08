proc includedll(array<char> lib) {
  int liboffset = foreign[17]('lib');
  return liboffset;
}

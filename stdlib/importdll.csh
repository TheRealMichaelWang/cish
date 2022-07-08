proc includedll(array<char> lib) {
  auto liboffset = foreign[19](lib);
  return liboffset;
}

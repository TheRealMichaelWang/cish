proc isAlphaInt(int c) => 
	(c >= foreign[15]('a') and c <= foreign[15]('z')) or
	(c >= foreign[15]('A') and c <= foreign[15]('Z'))

proc isNumericalInt(int c) =>
	c >= foreign[15]('0') and c <= foreign[15]('9')

proc isAlpha(char c) => isAlphaInt(foreign[15](c))
proc isNumerical(char c) => isNumericalInt(foreign[15](c))

proc isAlnum(char c) => isAlpha(c) or isNumerical(c)